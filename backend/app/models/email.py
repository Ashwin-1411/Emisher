"""Models describing a parsed email (the output of ``parsing/``)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Header(BaseModel):
    """One header line. ``value`` is decoded and unfolded; ``raw`` is what was on the wire."""

    name: str
    value: str
    raw: str = ""


class Address(BaseModel):
    """A single mailbox such as ``"PayPal Support" <x@random.xyz>``."""

    display_name: str = ""
    address: str = ""
    domain: str = ""  # lower-cased, IDNA (punycode) form as found in the header


class MimeNode(BaseModel):
    """A node of the MIME tree. Leaves carry sizes; multiparts carry children."""

    content_type: str
    filename: str | None = None
    disposition: str | None = None
    size: int = 0
    children: list[MimeNode] = Field(default_factory=list)


class AttachmentData(BaseModel):
    """An attachment part. Bytes are held in memory only and never serialised."""

    filename: str = ""
    content_type: str = "application/octet-stream"
    disposition: str = "attachment"  # "attachment" or "inline"
    size: int = 0
    nested_in: str | None = None  # filename/subject of the message/rfc822 part that contained it
    data: bytes = Field(default=b"", exclude=True, repr=False)


class ParsedEmail(BaseModel):
    """Everything later stages need, extracted once from the raw message."""

    headers: list[Header] = Field(default_factory=list)  # wire order, repeats preserved
    from_: Address | None = None
    reply_to: Address | None = None
    return_path: Address | None = None
    sender: Address | None = None
    to: list[Address] = Field(default_factory=list)
    subject: str = ""
    date: datetime | None = None
    date_raw: str = ""
    message_id: str = ""
    text_body: str = ""
    html_body: str = ""
    mime_tree: MimeNode | None = None
    attachments: list[AttachmentData] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    raw_size: int = 0
    raw: bytes = Field(default=b"", exclude=True, repr=False)  # kept only for DKIM verification

    def get_headers(self, name: str) -> list[str]:
        """All values of a header, in wire order (top of the message first)."""
        lowered = name.lower()
        return [h.value for h in self.headers if h.name.lower() == lowered]
