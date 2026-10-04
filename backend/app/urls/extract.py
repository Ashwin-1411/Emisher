"""Find URLs in HTML bodies, plain-text bodies and text attachments."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

from app.models import ParsedEmail

# Stops at whitespace and characters that almost never belong to a URL inside prose or markup.
_URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`]+""")
_TRAILING_PUNCT = ".,;:!?)]}>'\""
_MAX_TEXT_ATTACHMENT = 1_000_000  # bytes; larger text attachments are not worth scanning


@dataclass
class RawLink:
    """A URL as found, before any normalisation, plus what the reader sees for it."""

    url: str
    text: str = ""  # visible anchor text (HTML links only)
    source: str = "text"  # html | text | attachment


class _LinkParser(HTMLParser):
    """Collects ``<a href>`` (with its visible text), ``<area href>`` and ``<form action>``."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[RawLink] = []
        self._open: RawLink | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attr.get("href"):
            self._open = RawLink(url=attr["href"].strip(), source="html")
            self.links.append(self._open)
        elif tag == "area" and attr.get("href"):
            self.links.append(RawLink(url=attr["href"].strip(), source="html"))
        elif tag == "form" and attr.get("action"):
            self.links.append(RawLink(url=attr["action"].strip(), source="html"))

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._open.text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            if self._open is not None:
                self._open.text = " ".join(self._open.text.split())
            self._open = None


def extract_from_html(html: str, source: str = "html") -> list[RawLink]:
    parser = _LinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTMLParser is tolerant; this is belt and braces for hostile input
        pass
    for link in parser.links:
        link.source = source
    return parser.links


def extract_from_text(text: str, source: str = "text") -> list[RawLink]:
    links = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_TRAILING_PUNCT)
        if url:
            links.append(RawLink(url=url, source=source))
    return links


def extract_raw_links(email: ParsedEmail) -> list[RawLink]:
    """All candidate links in the message, HTML anchors first (they carry display text)."""
    links = extract_from_html(email.html_body) if email.html_body else []
    links += extract_from_text(email.text_body)
    for att in email.attachments:
        if att.filename:
            links += extract_from_text(att.filename, source="attachment")
        if att.content_type.startswith("text/") and 0 < att.size <= _MAX_TEXT_ATTACHMENT:
            body = att.data.decode("utf-8", errors="replace")
            if att.content_type == "text/html":
                links += extract_from_html(body, source="attachment")
            else:
                links += extract_from_text(body, source="attachment")
    return links
