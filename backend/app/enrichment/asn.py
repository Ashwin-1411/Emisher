"""Optional ASN / country lookup for hop IPs via Team Cymru's DNS service (no key, no HTTP).

Query ``<reversed-ip>.origin.asn.cymru.com`` for a TXT record shaped like
``"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"``. Using DNS keeps this on the same resolver
abstraction as the auth checks and avoids a free HTTP geo-IP API that would send IPs in the
clear. Behind ``HOP_ASN_LOOKUP_ENABLED`` because it reveals the hop IPs to the DNS resolver.
"""

from __future__ import annotations

import logging

from app.auth_checks.resolver import DnsResolver, DnsTemporaryError
from app.models import HopReport
from app.netutil import parse_ip

log = logging.getLogger(__name__)


def lookup_asn(resolver: DnsResolver, ip: str) -> tuple[str, str]:
    """Return ``(asn, country)`` for an IPv4 address, or ``("", "")`` if unknown."""
    parsed = parse_ip(ip)
    if parsed is None or parsed.version != 4 or not parsed.is_global:
        return "", ""
    name = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    try:
        records = resolver.txt(name)
    except DnsTemporaryError:
        return "", ""
    if not records:
        return "", ""
    fields = [f.strip() for f in records[0].split("|")]
    if len(fields) < 3:
        return "", ""
    return f"AS{fields[0].split()[0]}", fields[2]


def annotate_hops(report: HopReport, resolver: DnsResolver) -> None:
    """Fill ``asn`` and ``country`` on every hop with a public IP (blocking; run in a thread)."""
    cache: dict[str, tuple[str, str]] = {}
    for hop in report.hops:
        if hop.from_ip:
            if hop.from_ip not in cache:
                cache[hop.from_ip] = lookup_asn(resolver, hop.from_ip)
            hop.asn, hop.country = cache[hop.from_ip]
