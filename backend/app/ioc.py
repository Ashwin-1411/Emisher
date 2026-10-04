"""Build the indicator-of-compromise list and export it as JSON or CSV."""

from __future__ import annotations

import csv
import io

from app.models import IOC, AttachmentFinding, HopReport, ParsedEmail, UrlFinding
from app.netutil import registered_domain
from app.urls.normalize import defang


def build_iocs(
    email: ParsedEmail,
    hops: HopReport,
    urls: list[UrlFinding],
    attachments: list[AttachmentFinding],
) -> list[IOC]:
    """Collect de-duplicated IOCs with a note about where each came from."""
    seen: set[tuple[str, str]] = set()
    out: list[IOC] = []

    def add(kind: str, value: str, context: str, defanged: str | None = None) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        out.append(IOC(type=kind, value=value, defanged=defanged or defang(value), context=context))

    if email.from_ and email.from_.address:
        add(
            "email",
            email.from_.address,
            "From address",
            email.from_.address.replace("@", "[@]").replace(".", "[.]"),
        )
        add("domain", email.from_.domain, "From domain")
    for label, addr in (("Reply-To", email.reply_to), ("Return-Path", email.return_path)):
        if (
            addr
            and addr.domain
            and registered_domain(addr.domain)
            != registered_domain(email.from_.domain if email.from_ else "")
        ):
            add("domain", addr.domain, f"{label} domain")
    if hops.connecting_ip:
        add("ip", hops.connecting_ip, "Connecting IP (seen by receiving server)")
    if hops.originating_ip and hops.originating_ip != hops.connecting_ip:
        trust = "" if hops.originating_ip_trusted else " (unverified claim)"
        add("ip", hops.originating_ip, f"Originating IP{trust}")
    for url in urls:
        add("url", url.url, f"Link ({url.source})", url.defanged)
        if url.domain and "ip_host" not in url.flags:
            add("domain", url.domain, "Link domain")
        elif "ip_host" in url.flags:
            add("ip", url.host, "Link IP host")
    for att in attachments:
        ctx = f"Attachment {att.filename}"
        add("sha256", att.sha256, ctx, att.sha256)
        add("sha1", att.sha1, ctx, att.sha1)
        add("md5", att.md5, ctx, att.md5)
    return out


def iocs_to_csv(iocs: list[IOC]) -> str:
    """CSV with a header row; the defanged column is the one to paste into tickets."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "defanged", "context"])
    for ioc in iocs:
        writer.writerow([_safe_cell(c) for c in (ioc.type, ioc.value, ioc.defanged, ioc.context)])
    return buf.getvalue()


def _safe_cell(value: str) -> str:
    """Neutralise spreadsheet formula injection: a cell starting with = + - @ is executed by Excel.
    Values come from attacker-controlled email, so prefix those with an apostrophe."""
    first = value[:1]
    return "'" + value if first and (first in "=+-@" or ord(first) in (9, 13)) else value
