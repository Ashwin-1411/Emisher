"""Static analysis of attachments. Nothing is ever executed, opened by an application or written
to disk: all libraries here read from in-memory bytes."""

from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile

from app.attachments.filetypes import (
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_TYPES,
    EXT_TO_TYPES,
    OFFICE_TYPES,
    RISKY_EXTENSIONS,
    detect_type,
)
from app.models import AttachmentData, AttachmentFinding, MacroInfo, Signal

log = logging.getLogger(__name__)
logging.getLogger("olevba").setLevel(logging.ERROR)  # oletools is chatty about odd-but-valid files

MAX_MACRO_SCAN_BYTES = 15 * 1024 * 1024
_RTL_CHARS = {"‮", "‭", "‫", "‪"}  # bidi overrides that can reverse display


def file_extensions(filename: str) -> list[str]:
    """Extensions after normalising tricks: ``"invoice.pdf   .exe"`` -> ``["pdf", "exe"]``."""
    cleaned = re.sub(r"\s+\.", ".", filename.strip()).lower()
    parts = cleaned.split(".")
    return [p for p in parts[1:] if p]


def hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data, usedforsecurity=False).hexdigest(),
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def _is_password_protected(label: str, data: bytes) -> bool:
    """Cheap, header-level checks only; we never try to open or crack the content."""
    if label == "zip" or label in ("docx", "xlsx", "pptx", "jar", "apk"):
        try:
            return any(i.flag_bits & 0x1 for i in zipfile.ZipFile(io.BytesIO(data)).infolist())
        except (zipfile.BadZipFile, NotImplementedError, ValueError):
            return False
    if label == "ole_encrypted":  # OOXML encrypted with a password is wrapped in an OLE file
        return True
    if label == "pdf":
        return b"/Encrypt" in data[-4096:] or b"/Encrypt" in data[:4096]
    return False


def scan_macros(data: bytes, filename: str) -> MacroInfo:
    """Look for VBA macros with ``olevba`` (oletools). Reads bytes directly, no temp files."""
    info = MacroInfo()
    if len(data) > MAX_MACRO_SCAN_BYTES:
        return info
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser(filename or "attachment", data=data)
        try:
            if parser.detect_vba_macros():
                info.has_macros = True
                for kind, keyword, _desc in parser.analyze_macros():
                    if kind == "AutoExec":
                        info.autoexec.append(keyword)
                    elif kind == "Suspicious":
                        info.suspicious.append(keyword)
        finally:
            parser.close()
    except Exception as exc:  # unreadable / not an Office file / oletools quirk
        log.info("macro scan skipped: %s", type(exc).__name__)
    info.autoexec = sorted(set(info.autoexec))
    info.suspicious = sorted(set(info.suspicious))
    return info


def analyze_attachment(att: AttachmentData) -> AttachmentFinding:
    """Hash, type-check and macro-scan one attachment."""
    data = att.data
    md5, sha1, sha256 = hashes(data)
    label, mime = detect_type(data)
    exts = file_extensions(att.filename)
    claimed = exts[-1] if exts else ""

    flags: list[str] = []
    if any(ch in att.filename for ch in _RTL_CHARS):
        flags.append("rtl_override")
    if len(exts) >= 2 and exts[-1] in RISKY_EXTENSIONS and exts[-2] in DOCUMENT_EXTENSIONS:
        flags.append("double_extension")

    is_exec = label in EXECUTABLE_TYPES or claimed in RISKY_EXTENSIONS
    if is_exec:
        flags.append("executable")
    elif label == "html":
        flags.append("html_attachment")  # HTML smuggling / credential-harvest page

    # Extension vs content. Only judge when we positively identified the content.
    allowed = EXT_TO_TYPES.get(claimed)
    if label not in ("unknown", "text") or claimed in EXT_TO_TYPES:
        if allowed is not None and label != "unknown" and label not in allowed:
            flags.append("type_mismatch")
        elif allowed is None and label in ("pe", "elf", "macho") and claimed:
            flags.append("type_mismatch")  # e.g. "photo.jpg2" that is really a Windows program

    if _is_password_protected(label, data):
        flags.append("password_protected")

    macro = MacroInfo()
    if label in OFFICE_TYPES:
        macro = scan_macros(data, att.filename)
        if macro.has_macros:
            flags.append("macros")
            if macro.autoexec:
                flags.append("macro_autoexec")

    return AttachmentFinding(
        filename=att.filename or "(unnamed)",
        content_type=att.content_type,
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        detected_type=label,
        detected_mime=mime,
        claimed_extension=claimed,
        nested_in=att.nested_in,
        flags=flags,
        macro=macro,
    )


def analyze_attachments(
    attachments: list[AttachmentData],
) -> tuple[list[AttachmentFinding], list[Signal]]:
    """Analyse all attachments; skip empty ones (e.g. a body part that only had a name)."""
    findings = [analyze_attachment(a) for a in attachments if a.data]
    return findings, _signals(findings)


def _signals(findings: list[AttachmentFinding]) -> list[Signal]:
    mapping = {
        "double_extension": "attachment_double_extension",
        "executable": "attachment_executable",
        "type_mismatch": "attachment_type_mismatch",
        "macros": "attachment_macro",
        "macro_autoexec": "attachment_macro_autoexec",
        "password_protected": "attachment_password_protected",
        "html_attachment": "attachment_html",
        "rtl_override": "attachment_rtlo",
    }
    out: list[Signal] = []
    for flag, rule in mapping.items():
        hit = [f for f in findings if flag in f.flags]
        if hit:
            first = hit[0]
            out.append(
                Signal(
                    rule_id=rule,
                    detail="; ".join(
                        f"{f.filename} (detected {f.detected_type}, sha256 {f.sha256[:12]}...)"
                        for f in hit
                    ),
                    context={
                        "filename": first.filename,
                        "detected": first.detected_type,
                        "count": len(hit),
                        "autoexec": ", ".join(first.macro.autoexec),
                    },
                )
            )
    return out
