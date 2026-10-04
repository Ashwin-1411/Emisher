"""True file-type detection from content ("magic bytes"), not from the filename.

We carry our own small signature table so the analyzer behaves identically on every OS and
works where ``libmagic`` is missing (``python-magic`` needs a native library that Windows
does not ship). ``python-magic`` is consulted only as a fallback for types we don't know.
"""

from __future__ import annotations

import io
import logging
import zipfile

import olefile

log = logging.getLogger(__name__)

# (type label, offset, signature). First match wins, so list specific signatures before general.
_SIGNATURES: list[tuple[str, int, bytes]] = [
    ("pe", 0, b"MZ"),  # Windows .exe/.dll/.scr (DOS header)
    ("elf", 0, b"\x7fELF"),
    ("macho", 0, b"\xcf\xfa\xed\xfe"),
    ("macho", 0, b"\xce\xfa\xed\xfe"),
    ("pdf", 0, b"%PDF-"),
    ("ole", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # legacy Office / MSI / encrypted OOXML
    ("zip", 0, b"PK\x03\x04"),
    ("zip", 0, b"PK\x05\x06"),  # empty archive
    ("rtf", 0, b"{\\rtf"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("gif", 0, b"GIF87a"),
    ("gif", 0, b"GIF89a"),
    ("rar", 0, b"Rar!\x1a\x07"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("gz", 0, b"\x1f\x8b"),
    ("bz2", 0, b"BZh"),
    ("cab", 0, b"MSCF"),
    ("lnk", 0, b"L\x00\x00\x00\x01\x14\x02\x00"),  # Windows shortcut
    ("iso", 0x8001, b"CD001"),
    ("tar", 257, b"ustar"),
]

EXECUTABLE_TYPES = {"pe", "elf", "macho", "lnk", "script"}
OFFICE_TYPES = {"doc", "xls", "ppt", "docx", "xlsx", "pptx", "ole", "rtf"}


def detect_type(data: bytes) -> tuple[str, str]:
    """Return ``(label, mime)`` for the content. ``label`` is ``"unknown"`` if nothing matched."""
    label = _match_signature(data)
    if label == "zip":
        label = _refine_zip(data)
    elif label == "ole":
        label = _refine_ole(data)
    elif label == "unknown":
        label = _sniff_text(data)
    if label == "unknown":
        return label, _libmagic_mime(data)
    return label, _MIME.get(label, "")


def _match_signature(data: bytes) -> str:
    for label, offset, sig in _SIGNATURES:
        if data[offset : offset + len(sig)] == sig:
            return label
    return "unknown"


def _refine_zip(data: bytes) -> str:
    """ZIP is the container for OOXML, JAR and APK; the member names tell them apart."""
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except (zipfile.BadZipFile, ValueError, NotImplementedError):
        return "zip"
    lowered = [n.lower() for n in names]
    if any(n.startswith("word/") for n in lowered):
        return "docx"
    if any(n.startswith("xl/") for n in lowered):
        return "xlsx"
    if any(n.startswith("ppt/") for n in lowered):
        return "pptx"
    if "androidmanifest.xml" in lowered:
        return "apk"
    if "meta-inf/manifest.mf" in lowered:
        return "jar"
    return "zip"


def _refine_ole(data: bytes) -> str:
    """Legacy Office files are all OLE containers; the stream names say which application."""
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = {"/".join(p).lower() for p in ole.listdir()}
        ole.close()
    except Exception:
        return "ole"
    if "encryptedpackage" in streams:
        return "ole_encrypted"
    if "worddocument" in streams:
        return "doc"
    if "workbook" in streams or "book" in streams:
        return "xls"
    if "powerpoint document" in streams:
        return "ppt"
    return "ole"


def _sniff_text(data: bytes) -> str:
    head = data[:2048]
    if not head or b"\x00" in head:
        return "unknown"
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return "unknown"
    lowered = text.lstrip().lower()
    if lowered.startswith(("<!doctype html", "<html", "<head", "<body", "<script")):
        return "html"
    if lowered.startswith("#!"):
        return "script"
    if lowered.startswith("<?xml"):
        return "xml"
    return "text"


def _libmagic_mime(data: bytes) -> str:
    try:
        import magic  # optional: needs native libmagic

        return str(magic.from_buffer(data[:4096], mime=True))
    except Exception:
        return ""


_MIME = {
    "pe": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-executable",
    "macho": "application/x-mach-binary",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "jar": "application/java-archive",
    "apk": "application/vnd.android.package-archive",
    "doc": "application/msword",
    "xls": "application/vnd.ms-excel",
    "ppt": "application/vnd.ms-powerpoint",
    "ole": "application/x-ole-storage",
    "rtf": "application/rtf",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "rar": "application/vnd.rar",
    "7z": "application/x-7z-compressed",
    "gz": "application/gzip",
    "html": "text/html",
    "text": "text/plain",
    "xml": "text/xml",
    "script": "text/x-script",
    "lnk": "application/x-ms-shortcut",
}

# claimed extension -> detected labels that are consistent with it
EXT_TO_TYPES: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "doc": {"doc", "ole", "rtf"},
    "dot": {"doc", "ole"},
    "docx": {"docx"},
    "docm": {"docx"},
    "xls": {"xls", "ole"},
    "xlsx": {"xlsx"},
    "xlsm": {"xlsx"},
    "ppt": {"ppt", "ole"},
    "pptx": {"pptx"},
    "pptm": {"pptx"},
    "rtf": {"rtf"},
    "zip": {"zip"},
    "rar": {"rar"},
    "7z": {"7z"},
    "gz": {"gz"},
    "exe": {"pe"},
    "dll": {"pe"},
    "scr": {"pe"},
    "msi": {"ole"},
    "jar": {"jar", "zip"},
    "apk": {"apk", "zip"},
    "lnk": {"lnk"},
    "txt": {"text", "unknown"},
    "csv": {"text", "unknown"},
    "log": {"text", "unknown"},
    "html": {"html", "text"},
    "htm": {"html", "text"},
    "xml": {"xml", "text"},
}

# Extensions that execute code (or launch something that does) when opened on Windows/macOS/Linux.
RISKY_EXTENSIONS = {
    "exe", "scr", "com", "pif", "dll", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "jar", "lnk", "cpl", "reg", "sh", "apk", "msc", "gadget", "application",
}  # fmt: skip
# Extensions people expect to be harmless documents; used to spot "invoice.pdf.exe".
DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "zip", "htm", "html",
}  # fmt: skip
