"""Received-chain tracer.

Each mail server that handles a message *prepends* a ``Received:`` header, so the header at
the top of the message is the newest hop and the one at the bottom is the oldest. We reverse
the list so index 0 is the oldest hop and time flows forward.

Only the topmost hop(s), written by *our own* receiving provider, can be believed. Everything
below was written by systems the sender may control, so a forger can invent any of it. We
therefore label hops as trusted or not and apply the "forged" heuristics only to the latter.
"""

from __future__ import annotations

import re
from datetime import UTC
from email.utils import parsedate_to_datetime

from app.models import Hop, HopReport, ParsedEmail, Signal
from app.netutil import is_public_ip, parse_ip, registered_domain

LARGE_DELAY_SECONDS = 3600  # an hour between two hops is unusual for modern mail flow
CLOCK_SKEW_TOLERANCE = 300  # servers' clocks disagree by a few minutes in practice

_FROM_RE = re.compile(r"\bfrom\s+(?P<host>\S+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(?P<host>\S+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9][A-Za-z0-9\-]*)", re.IGNORECASE)
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?(?P<ip>[0-9a-fA-F:.]+)\]")
_BARE_IPV4_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_received(raw: str) -> Hop:
    """Parse one ``Received`` header value into a :class:`Hop` (index is set by the caller).

    Received syntax is only loosely standardised (RFC 5321 s4.4), so this is best-effort:
    anything we cannot extract is left empty and the hop is marked ``malformed``.
    """
    text = " ".join(raw.split())
    hop = Hop(index=0, raw=text)

    body, _, date_part = text.rpartition(";")
    if not body:  # no semicolon: there is no timestamp
        body, date_part = text, ""
    if date_part.strip():
        try:
            ts = parsedate_to_datetime(date_part.strip())
            hop.timestamp = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError):
            hop.flags.append("bad_timestamp")

    by_match = _BY_RE.search(body)
    if by_match:
        hop.by_host = by_match.group("host").strip("();,").lower()
    with_match = _WITH_RE.search(body)
    if with_match:
        hop.protocol = with_match.group("proto").upper()

    from_match = _FROM_RE.search(body)
    if from_match:
        # The "from" clause runs up to "by"; searching only inside it avoids picking up IPs
        # that belong to the receiving side or the "for <rcpt>" part.
        end = by_match.start() if by_match and by_match.start() > from_match.start() else len(body)
        clause = body[from_match.start() : end]
        host = from_match.group("host").strip("();,").lower()
        ip_match = _BRACKET_IP_RE.search(clause) or _BARE_IPV4_RE.search(clause)
        if ip_match:
            hop.from_ip = ip_match.group("ip")
        if parse_ip(host):  # "from [1.2.3.4]" - the host slot holds a bare address
            hop.from_ip = hop.from_ip or host.strip("[]")
            host = ""
        hop.from_host = host.strip("[]")

    if not (hop.from_host or hop.from_ip) and not hop.by_host or hop.timestamp is None:
        hop.flags.append("malformed")
    return hop


def trace_hops(email: ParsedEmail, trusted_hops: int = 1) -> tuple[HopReport, list[Signal]]:
    """Build the chronological hop list, flag anomalies and pick the connecting/originating IPs.

    ``trusted_hops`` is how many of the newest hops we treat as written by our own provider.
    One is the safe default: the topmost header is the only one we can be sure was added by
    the system that handed us the message.
    """
    received = email.get_headers("Received")  # newest first
    hops = [parse_received(raw) for raw in reversed(received)]  # now oldest first
    report = HopReport()
    signals: list[Signal] = []
    if not hops:
        return report, signals

    total = len(hops)
    for i, hop in enumerate(hops):
        hop.index = i
        hop.trusted = i >= total - trusted_hops
    report.receiving_host = hops[-1].by_host

    _flag_timing(hops)
    _flag_ips_and_chain(hops)
    for hop in hops:
        untrusted_problem = not hop.trusted and (
            "malformed" in hop.flags
            or "timestamp_out_of_order" in hop.flags
            or "private_ip_after_public" in hop.flags
        )
        if untrusted_problem or (not hop.trusted and "predates_newer_hop" in hop.flags):
            hop.flags.append("likely_forged")

    # Connecting IP: newest hop whose address is public. This is the peer our provider saw.
    for hop in reversed(hops):
        if hop.from_ip and is_public_ip(hop.from_ip):
            report.connecting_ip = hop.from_ip
            break
    # Originating IP: oldest public address in the chain; only as trustworthy as its hop.
    for hop in hops:
        if hop.from_ip and is_public_ip(hop.from_ip):
            report.originating_ip = hop.from_ip
            report.originating_ip_trusted = hop.trusted
            break

    report.hops = hops
    signals.extend(_signals(hops))
    return report, signals


def _flag_timing(hops: list[Hop]) -> None:
    """Compute per-hop delays and flag large delays and out-of-order timestamps."""
    for prev, cur in zip(hops, hops[1:], strict=False):
        if prev.timestamp is None or cur.timestamp is None:
            continue
        delay = (cur.timestamp - prev.timestamp).total_seconds()
        cur.delay_seconds = delay
        if delay < -CLOCK_SKEW_TOLERANCE:
            # `cur` is newer in the chain but claims an earlier time than `prev`: impossible
            # unless clocks are badly wrong or one of the two headers was fabricated.
            cur.flags.append("timestamp_out_of_order")
            prev.flags.append("predates_newer_hop")  # the older hop is the suspect
        elif delay > LARGE_DELAY_SECONDS:
            cur.flags.append("large_delay")


def _flag_ips_and_chain(hops: list[Hop]) -> None:
    seen_public = False
    for hop in hops:
        ip = parse_ip(hop.from_ip) if hop.from_ip else None
        if ip is not None:
            if ip.is_global:
                seen_public = True
            elif seen_public:
                # A message that already crossed the public Internet cannot be handed over
                # by a private address: that hop is either NAT-confused or invented.
                hop.flags.append("private_ip_after_public")
    for prev, cur in zip(hops, hops[1:], strict=False):
        a, b = registered_domain(prev.by_host), registered_domain(cur.from_host)
        if a and b and "." in a and "." in b and a != b:
            # Informational only: legitimate relays often introduce themselves under another name.
            cur.flags.append("chain_break")


def _signals(hops: list[Hop]) -> list[Signal]:
    out: list[Signal] = []

    def flagged(flag: str) -> list[Hop]:
        return [h for h in hops if flag in h.flags]

    if forged := flagged("likely_forged"):
        out.append(
            Signal(
                rule_id="hop_forged_suspected",
                detail=f"{len(forged)} hop(s) below the trusted boundary look fabricated: "
                + ", ".join(f"#{h.index}" for h in forged),
                context={"count": len(forged)},
            )
        )
    if ooo := flagged("timestamp_out_of_order"):
        out.append(
            Signal(
                rule_id="hop_timestamp_out_of_order",
                detail="Timestamps go backwards at hop(s) " + ", ".join(f"#{h.index}" for h in ooo),
                context={"count": len(ooo)},
            )
        )
    if priv := flagged("private_ip_after_public"):
        out.append(
            Signal(
                rule_id="hop_private_ip_unexpected",
                detail="Private address appears after the message crossed the Internet at hop(s) "
                + ", ".join(f"#{h.index}" for h in priv),
                context={"count": len(priv)},
            )
        )
    if big := flagged("large_delay"):
        worst = max(big, key=lambda h: h.delay_seconds or 0)
        out.append(
            Signal(
                rule_id="hop_large_delay",
                detail=f"Delay of {int((worst.delay_seconds or 0) // 60)} min before hop #{worst.index}",
                context={"minutes": int((worst.delay_seconds or 0) // 60)},
            )
        )
    return out
