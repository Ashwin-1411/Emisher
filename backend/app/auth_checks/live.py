"""Independent re-checks of SPF, DKIM and DMARC against *current* DNS.

These are the secondary signal. They can legitimately disagree with the delivery-time result
because DNS records and DKIM keys change after a message is delivered (selector rotation,
SPF edits, expired domains). The caller labels disagreements rather than treating them as
proof of forgery.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from typing import Any

import dkim
import spf

from app.auth_checks.alignment import compute_alignment, domain_of
from app.auth_checks.resolver import DnsResolver, DnsTemporaryError
from app.models import LiveAuth, ParsedEmail
from app.netutil import registered_domain

log = logging.getLogger(__name__)

# pyspf calls a module-level ``spf.DNSLookup`` function. We replace it once with a dispatcher
# that reads the resolver from a ContextVar, so concurrent requests (each in its own worker
# thread, with a copied context) never see each other's resolver.
_current_resolver: contextvars.ContextVar[DnsResolver] = contextvars.ContextVar("dns_resolver")


def _spf_dns_lookup(name: str, qtype: str, strict: Any = True, timeout: Any = None) -> list:
    resolver = _current_resolver.get()
    try:
        if qtype == "TXT":
            return [((name, qtype), (rec.encode(),)) for rec in resolver.txt(name)]
        if qtype == "A":
            return [((name, qtype), ip) for ip in resolver.a(name)]
        if qtype == "AAAA":
            return [((name, qtype), ip) for ip in resolver.aaaa(name)]
        if qtype == "MX":
            return [((name, qtype), (pref, host)) for pref, host in resolver.mx(name)]
        if qtype == "PTR":
            return [((name, qtype), host) for host in resolver.ptr(name)]
    except DnsTemporaryError as exc:
        raise spf.TempError(f"DNS {exc}") from exc
    return []  # the obsolete SPF (type 99) record type: TXT is authoritative


spf.DNSLookup = _spf_dns_lookup


def parse_dmarc_record(record: str) -> dict[str, str]:
    """``"v=DMARC1; p=reject; adkim=s"`` -> ``{"v": "DMARC1", "p": "reject", "adkim": "s"}``."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, eq, val = part.strip().partition("=")
        if eq:
            tags[key.strip().lower()] = val.strip()
    return tags


def _lookup_dmarc(resolver: DnsResolver, from_domain: str) -> str:
    """Find the DMARC TXT record: exact From domain first, then the organisational domain."""
    for domain in dict.fromkeys([from_domain, registered_domain(from_domain)]):
        for txt in resolver.txt(f"_dmarc.{domain}"):
            if txt.lower().startswith("v=dmarc1"):
                return txt
    return ""


def _check_spf(
    resolver: DnsResolver, ip: str, mail_from: str, helo: str, timeout: float
) -> tuple[str, int, str]:
    token = _current_resolver.set(resolver)
    try:
        return spf.query(ip, mail_from, helo, querytime=int(timeout) + 1).check()
    finally:
        _current_resolver.reset(token)


def _check_dkim(resolver: DnsResolver, raw: bytes) -> list[dict[str, Any]]:
    """Verify every DKIM-Signature header on the message, one result per signature."""
    results: list[dict[str, Any]] = []
    try:
        headers, _ = dkim.rfc822_parse(raw)
    except Exception:
        return results
    sig_headers = [v for k, v in headers if k.lower() == b"dkim-signature"]
    for idx, value in enumerate(sig_headers):
        try:
            tags = dkim.util.parse_tag_value(value)
        except Exception:
            tags = {}
        entry: dict[str, Any] = {
            "domain": tags.get(b"d", b"").decode("ascii", "replace").lower(),
            "selector": tags.get(b"s", b"").decode("ascii", "replace"),
            "result": "fail",
        }
        temp_error = False

        def dnsfunc(name: bytes, timeout: int = 5) -> bytes | None:
            nonlocal temp_error
            try:
                records = resolver.txt(name.decode("ascii").rstrip("."))
            except DnsTemporaryError:
                temp_error = True
                return None
            return records[0].encode() if records else None

        try:
            ok = dkim.DKIM(raw).verify(idx, dnsfunc=dnsfunc)
            entry["result"] = "pass" if ok else "fail"
        except dkim.DKIMException as exc:
            entry["reason"] = type(exc).__name__
        except Exception as exc:  # malformed signature tags etc.
            entry["result"] = "permerror"
            entry["reason"] = type(exc).__name__
        if temp_error and entry["result"] == "fail":
            entry["result"] = "temperror"  # we could not fetch the key, so we cannot say "fail"
        results.append(entry)
    return results


async def run_live_checks(
    email: ParsedEmail,
    connecting_ip: str,
    helo: str,
    resolver: DnsResolver,
    timeout: float = 4.0,
) -> LiveAuth:
    """Run SPF, DKIM and DMARC against live DNS. Individual failures are recorded, not raised."""
    live = LiveAuth(performed=True, connecting_ip=connecting_ip)
    from_domain = email.from_.domain if email.from_ else ""

    # ---- SPF: evaluated for the envelope sender (Return-Path) from the connecting IP.
    mail_from = email.return_path.address if email.return_path else ""
    sender = mail_from or (f"postmaster@{helo}" if helo else "")
    live.spf_domain = domain_of(sender)
    if connecting_ip and sender:
        try:
            result, _code, explanation = await asyncio.to_thread(
                _check_spf, resolver, connecting_ip, sender, helo or live.spf_domain, timeout
            )
            live.spf_result = str(result).lower()
            live.spf_explanation = str(explanation)
        except Exception as exc:
            log.info("live SPF check failed: %s", type(exc).__name__)
            live.spf_result = "temperror"
            live.spf_explanation = type(exc).__name__
    else:
        live.spf_result = "none"
        live.spf_explanation = "No connecting IP or envelope sender available"

    # ---- DKIM
    live.dkim_results = await asyncio.to_thread(_check_dkim, resolver, email.raw)

    # ---- DMARC
    if from_domain:
        try:
            record = await asyncio.to_thread(_lookup_dmarc, resolver, from_domain)
        except DnsTemporaryError:
            record = ""
            live.disagreements.append("DMARC record lookup failed (DNS error)")
        live.dmarc_record = record
        tags = parse_dmarc_record(record) if record else {}
        live.dmarc_policy = tags.get("p", "").lower()
        live.dmarc_adkim = tags.get("adkim", "r").lower()
        live.dmarc_aspf = tags.get("aspf", "r").lower()

        # DMARC alignment uses the identifiers that actually *passed*.
        if live.spf_result == "pass":
            live.spf_alignment = compute_alignment(from_domain, live.spf_domain)
        live.dkim_alignment = [
            compute_alignment(from_domain, r["domain"])
            for r in live.dkim_results
            if r["result"] == "pass" and r["domain"]
        ]
        if not record:
            live.dmarc_result = "none"
        else:
            spf_al = live.spf_alignment
            spf_ok = bool(spf_al and (spf_al.strict if live.dmarc_aspf == "s" else spf_al.relaxed))
            dkim_ok = any(
                (a.strict if live.dmarc_adkim == "s" else a.relaxed) for a in live.dkim_alignment
            )
            live.dmarc_result = "pass" if (spf_ok or dkim_ok) else "fail"
    return live
