"""Small network/domain helpers shared by several analysis modules."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import idna
import tldextract

# suffix_list_urls=() forces tldextract to use the Public Suffix List snapshot bundled with the
# package. Its default behaviour is to download the list at first use, which would break the
# "works fully offline" requirement and make tests depend on the network.
_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) of ``host``, e.g. ``mail.google.co.uk`` -> ``google.co.uk``.

    This "organisational domain" is what DMARC relaxed alignment compares. For IPs or
    hosts with no known suffix we return the host unchanged.
    """
    host = host.strip().strip(".").lower()
    if not host:
        return ""
    parts = _extractor(host)
    if not parts.suffix:
        return host
    return f"{parts.domain}.{parts.suffix}" if parts.domain else parts.suffix


def second_level_label(host: str) -> str:
    """The label just left of the public suffix (``paypa1`` for ``www.paypa1.com``)."""
    parts = _extractor(host.strip().strip(".").lower())
    return parts.domain


def to_ascii_host(host: str) -> str:
    """IDNA/punycode form of a host; falls back to the lower-cased input if it is not valid IDNA."""
    host = host.strip().strip(".").lower()
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return host


def to_unicode_host(host: str) -> str:
    """Human-readable (Unicode) form of a possibly-punycode host."""
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return host


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal (tolerating ``[..]`` brackets and ``IPv6:`` prefixes) or return None."""
    value = value.strip().strip("[]")
    if value.lower().startswith("ipv6:"):
        value = value[5:]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    """True for globally routable addresses. Private, loopback, link-local, documentation ranges
    and other reserved space are all "not public"."""
    ip = parse_ip(value)
    return bool(ip and ip.is_global)


def has_known_suffix(host: str) -> bool:
    """True if the host ends in a public suffix from the bundled PSL (``.com``, ``.co.uk``...).

    Used to tell ``paypal.com`` from prose like ``Terms.Conditions`` when scanning link text.
    """
    return bool(_extractor(host.strip().strip(".").lower()).suffix)
