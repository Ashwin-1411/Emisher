"""Raw ``.eml`` bytes -> :class:`~app.models.ParsedEmail`.

Design goal: never raise. Real-world phishing is often malformed on purpose (or by sloppy
tooling), so every oddity becomes a string in ``parse_warnings`` and parsing carries on.
"""

from __future__ import annotations

import logging
from datetime import UTC
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

from app.models import Address, AttachmentData, Header, MimeNode, ParsedEmail
from app.netutil import to_ascii_host

log = logging.getLogger(__name__)

_MAX_DEPTH = 20  # guards against maliciously deep message/rfc822 nesting


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw RFC 5322 bytes into a structured model. Never raises on bad input."""
    result = ParsedEmail(raw_size=len(raw), raw=raw)
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # the stdlib parser is lenient, but be defensive
        log.warning("email parser failed: %s", type(exc).__name__)
        result.parse_warnings.append(f"Message could not be parsed: {type(exc).__name__}")
        return result

    _collect_headers(msg, result)
    _collect_identity_fields(result)
    state = _WalkState(result)
    result.mime_tree = state.walk(msg, nested_in=None, depth=0)
    for defect in dict.fromkeys(state.defects):  # de-duplicate, keep order
        result.parse_warnings.append(f"MIME defect: {defect}")
    if not result.headers:
        result.parse_warnings.append("No headers found; input may not be an email")
    return result


# --------------------------------------------------------------------------- headers
def _collect_headers(msg: Message, result: ParsedEmail) -> None:
    """Store every header in wire order. ``raw_items`` keeps repeats (Received!) un-merged."""
    for name, raw_value in msg.raw_items():
        raw_text = str(raw_value)
        try:
            # header_fetch_parse performs RFC 2047 decoding ("=?utf-8?b?...?=") and unfolding.
            value = str(msg.policy.header_fetch_parse(name, raw_value))
        except Exception:
            value = " ".join(raw_text.split())
            result.parse_warnings.append(f"Header {name!r} could not be decoded")
        result.headers.append(Header(name=name, value=value, raw=raw_text))


def _parse_address(value: str) -> Address | None:
    display, addr = parseaddr(value)
    if not addr:
        return None
    domain = addr.rsplit("@", 1)[1] if "@" in addr else ""
    return Address(display_name=display.strip(), address=addr, domain=to_ascii_host(domain))


def _collect_identity_fields(result: ParsedEmail) -> None:
    def first(name: str) -> str:
        values = result.get_headers(name)
        return values[0] if values else ""

    result.from_ = _parse_address(first("From"))
    if len(result.get_headers("From")) > 1:
        result.parse_warnings.append("Multiple From headers present (only the first is used)")
    if result.from_ is None:
        result.parse_warnings.append("No usable From address")
    result.reply_to = _parse_address(first("Reply-To"))
    result.return_path = _parse_address(first("Return-Path"))
    result.sender = _parse_address(first("Sender"))
    result.to = [
        a
        for _, addr in getaddresses(result.get_headers("To"))
        if addr and (a := _parse_address(addr))
    ]
    result.subject = first("Subject")
    result.message_id = first("Message-ID").strip()
    result.date_raw = first("Date")
    if result.date_raw:
        try:
            parsed = parsedate_to_datetime(result.date_raw)
            result.date = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError):
            result.parse_warnings.append("Date header could not be parsed")
    else:
        result.parse_warnings.append("No Date header")


# --------------------------------------------------------------------------- MIME walk
class _WalkState:
    """Accumulates bodies/attachments while recursing through the MIME tree."""

    def __init__(self, result: ParsedEmail) -> None:
        self.result = result
        self.defects: list[str] = []
        self._text: list[str] = []
        self._html: list[str] = []

    def walk(self, part: Any, nested_in: str | None, depth: int) -> MimeNode:
        ctype = part.get_content_type()
        node = MimeNode(content_type=ctype)
        self.defects.extend(type(d).__name__ for d in part.defects)
        node.filename = _safe_filename(part)
        node.disposition = _safe_disposition(part)

        if depth > _MAX_DEPTH:
            self.result.parse_warnings.append("MIME nesting too deep; remaining parts skipped")
            return node

        if ctype == "message/rfc822":
            self._walk_embedded_message(part, node, nested_in, depth)
        elif part.is_multipart():
            for child in part.iter_parts():
                node.children.append(self.walk(child, nested_in, depth + 1))
        else:
            self._handle_leaf(part, node, nested_in)

        if depth == 0:  # finalise bodies once the whole tree has been visited
            self.result.text_body = "\n".join(self._text)
            self.result.html_body = "\n".join(self._html)
        return node

    def _walk_embedded_message(
        self, part: Any, node: MimeNode, nested_in: str | None, depth: int
    ) -> None:
        """A forwarded-as-attachment email. Kept as an attachment, and its own attachments are
        surfaced too (flagged ``nested_in``) because malware is often hidden one level down."""
        inner = part.get_payload(0) if part.is_multipart() else None
        label = (
            node.filename or (str(inner["subject"]) if inner is not None else "") or "forwarded.eml"
        )
        data = b""
        if inner is not None:
            try:
                data = inner.as_bytes()
            except Exception:
                self.result.parse_warnings.append("Embedded message could not be re-serialised")
        node.size = len(data)
        self.result.attachments.append(
            AttachmentData(
                filename=node.filename or "forwarded.eml",
                content_type="message/rfc822",
                disposition=node.disposition or "attachment",
                size=len(data),
                nested_in=nested_in,
                data=data,
            )
        )
        if inner is not None:
            node.children.append(self.walk(inner, nested_in=label, depth=depth + 1))

    def _handle_leaf(self, part: Message, node: MimeNode, nested_in: str | None) -> None:
        ctype = node.content_type
        payload = _payload_bytes(part)
        node.size = len(payload)
        is_text_body = (
            ctype in ("text/plain", "text/html")
            and node.disposition != "attachment"
            and not node.filename
        )
        if is_text_body:
            if nested_in is None:  # bodies of forwarded messages are not the message's own body
                text = self._decode_text(part, payload)
                (self._html if ctype == "text/html" else self._text).append(text)
            return
        self.result.attachments.append(
            AttachmentData(
                filename=node.filename or "",
                content_type=ctype,
                disposition=node.disposition or "attachment",
                size=len(payload),
                nested_in=nested_in,
                data=payload,
            )
        )

    def _decode_text(self, part: Message, payload: bytes) -> str:
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            self.result.parse_warnings.append(f"Unknown charset {charset!r}; decoded as UTF-8")
            return payload.decode("utf-8", errors="replace")


def _payload_bytes(part: Message) -> bytes:
    """Transfer-decoded payload (base64 / quoted-printable undone). Empty on failure."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return b""
    return payload if isinstance(payload, bytes) else b""


def _safe_filename(part: Message) -> str | None:
    try:
        name = part.get_filename()
    except Exception:
        return None
    return str(name) if name else None


def _safe_disposition(part: Message) -> str | None:
    try:
        return part.get_content_disposition()
    except Exception:
        return None
