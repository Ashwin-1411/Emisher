"""Orchestrates the authentication checks and turns them into signals.

Primary signal  : the ``Authentication-Results`` header stamped by the receiving provider.
Secondary signal: our own live SPF/DKIM/DMARC evaluation (only when a resolver is supplied).
"""

from __future__ import annotations

import logging

from app.auth_checks.alignment import compute_alignment, domain_of
from app.auth_checks.live import run_live_checks
from app.auth_checks.resolver import DnsResolver
from app.auth_checks.results_parser import parse_authentication_results
from app.models import (
    AuthReport,
    DeliveryAuth,
    HopReport,
    LiveAuth,
    ParsedEmail,
    Signal,
)
from app.netutil import registered_domain

log = logging.getLogger(__name__)


def _same_provider(authserv_id: str, receiving_host: str) -> bool:
    """Does the header's authserv-id name the server that received the message?"""
    if not authserv_id or not receiving_host:
        return False
    if authserv_id == receiving_host:
        return True
    a, b = registered_domain(authserv_id), registered_domain(receiving_host)
    return bool(a and b and "." in a and a == b)


def parse_delivery_auth(email: ParsedEmail, hops: HopReport) -> DeliveryAuth:
    """Pick the Authentication-Results header written by the final receiving provider.

    Anyone upstream can insert a header named ``Authentication-Results`` claiming
    ``dmarc=pass``. The only one worth believing was added by the server that accepted the
    message, whose name appears as the ``by`` host of the topmost ``Received`` hop. So we
    trust a header only if its authserv-id matches that host (same organisational domain).
    """
    values = email.get_headers("Authentication-Results")
    delivery = DeliveryAuth(header_found=bool(values))
    if not values:
        delivery.note = "No Authentication-Results header was present."
        return delivery

    parsed = [parse_authentication_results(v) for v in values]
    for authserv_id, results in parsed:  # topmost first = newest first
        if _same_provider(authserv_id, hops.receiving_host):
            delivery.authserv_id = authserv_id
            delivery.results = results
            delivery.trusted = True
            return delivery

    authserv_id, results = parsed[0]
    delivery.authserv_id = authserv_id
    delivery.results = results  # shown for the analyst, but not used for scoring
    delivery.note = (
        f"Authentication-Results was stamped by {authserv_id or 'an unknown server'}, which does "
        f"not match the receiving server ({hops.receiving_host or 'unknown'}). "
        "It may have been inserted by the sender, so it is not trusted."
    )
    return delivery


def _delivery_alignment(from_domain: str, delivery: DeliveryAuth, report: AuthReport) -> None:
    """Compute alignment from delivery-time results (works offline)."""
    spf = next((r for r in delivery.results if r.method == "spf" and r.result == "pass"), None)
    if spf:
        ident = spf.properties.get("smtp.mailfrom") or spf.properties.get("smtp.helo", "")
        if ident:
            report.spf_alignment = compute_alignment(from_domain, domain_of(ident))
    for r in delivery.results:
        if r.method == "dkim" and r.result == "pass":
            ident = r.properties.get("header.d") or domain_of(r.properties.get("header.i", ""))
            if ident:
                report.dkim_alignment.append(compute_alignment(from_domain, domain_of(ident)))


def _disagreements(delivery: DeliveryAuth, live: LiveAuth) -> list[str]:
    out: list[str] = []
    live_dkim = (
        "pass"
        if any(r["result"] == "pass" for r in live.dkim_results)
        else (live.dkim_results[0]["result"] if live.dkim_results else "none")
    )
    pairs = [
        ("SPF", delivery.result_for("spf"), live.spf_result),
        ("DKIM", delivery.result_for("dkim"), live_dkim),
        ("DMARC", delivery.result_for("dmarc"), live.dmarc_result),
    ]
    for name, then, now in pairs:
        if then and now and then != now and "temperror" not in (then, now):
            out.append(
                f"{name}: the receiving server recorded '{then}' at delivery, but a live check "
                f"now returns '{now}'. DNS records and DKIM keys can change after delivery, so "
                "this is a difference to investigate, not proof of tampering."
            )
    return out


def _signals(email: ParsedEmail, report: AuthReport) -> list[Signal]:
    out: list[Signal] = []
    d, live = report.delivery, report.live
    from_domain = report.from_domain

    if not d.header_found:
        out.append(
            Signal(rule_id="auth_results_missing", detail="No Authentication-Results header")
        )
    elif d.header_found and not d.trusted:
        out.append(
            Signal(
                rule_id="auth_results_untrusted", detail=d.note, context={"server": d.authserv_id}
            )
        )

    # Use the trusted delivery-time verdict when we have one; otherwise fall back to the live one.
    if d.trusted:
        spf, dkim_res, dmarc = d.result_for("spf"), d.result_for("dkim"), d.result_for("dmarc")
        source = "at delivery"
    elif live.performed:
        dkim_pass = any(r["result"] == "pass" for r in live.dkim_results)
        dkim_res = "pass" if dkim_pass else ("fail" if live.dkim_results else None)
        spf, dmarc = live.spf_result or None, live.dmarc_result or None
        source = "in a live re-check"
    else:
        return out

    ctx = {"domain": from_domain}
    if dmarc == "fail":
        out.append(
            Signal(
                rule_id="dmarc_fail", detail=f"DMARC failed {source} for {from_domain}", context=ctx
            )
        )
    if spf in ("fail", "permerror"):
        out.append(Signal(rule_id="spf_fail", detail=f"SPF {spf} {source}", context=ctx))
    elif spf == "softfail":
        out.append(Signal(rule_id="spf_softfail", detail=f"SPF softfail {source}", context=ctx))
    if dkim_res == "fail":
        out.append(
            Signal(rule_id="dkim_fail", detail=f"DKIM signature failed {source}", context=ctx)
        )
    if spf == "pass":
        al = report.spf_alignment if d.trusted else live.spf_alignment
        if al is not None and not al.relaxed:
            out.append(
                Signal(
                    rule_id="spf_misaligned",
                    detail=f"SPF passed for {al.authenticated_domain} but the From domain is {al.from_domain}",
                    context={"domain": al.from_domain, "spf_domain": al.authenticated_domain},
                )
            )
    return out


async def check_auth(
    email: ParsedEmail,
    hops: HopReport,
    resolver: DnsResolver | None = None,
    dns_timeout: float = 4.0,
) -> tuple[AuthReport, list[Signal]]:
    """Run delivery-time parsing and, if ``resolver`` is given, the live re-checks."""
    report = AuthReport(from_domain=email.from_.domain if email.from_ else "")
    report.delivery = parse_delivery_auth(email, hops)
    if report.delivery.trusted and report.from_domain:
        _delivery_alignment(report.from_domain, report.delivery, report)

    if resolver is None:
        report.live = LiveAuth(performed=False, skipped_reason="Live DNS checks were not requested")
    elif not report.from_domain:
        report.live = LiveAuth(performed=False, skipped_reason="No From domain to check")
    else:
        helo = ""
        for hop in hops.hops:
            if hop.from_ip == hops.connecting_ip and hop.from_host:
                helo = hop.from_host
        report.live = await run_live_checks(email, hops.connecting_ip, helo, resolver, dns_timeout)
        if report.delivery.trusted:
            report.live.disagreements.extend(_disagreements(report.delivery, report.live))

    report.explanation = _explain(report)
    return report, _signals(email, report)


def _explain(report: AuthReport) -> list[str]:
    """Short plain-English notes shown at the top of the Authentication tab."""
    d, lines = report.delivery, []
    if not d.header_found:
        lines.append("The receiving server did not record any SPF/DKIM/DMARC results.")
    elif not d.trusted:
        lines.append(d.note)
    else:
        for r in d.results:
            if r.method in ("spf", "dkim", "dmarc"):
                lines.append(f"{r.method.upper()} was '{r.result}' when the message was delivered.")
    if report.spf_alignment is not None:
        a = report.spf_alignment
        lines.append(
            f"SPF authenticated {a.authenticated_domain}; From is {a.from_domain} "
            f"(relaxed alignment: {'yes' if a.relaxed else 'NO'}, strict: {'yes' if a.strict else 'no'})."
        )
    lines.extend(report.live.disagreements)
    return lines
