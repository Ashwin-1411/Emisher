"""The analysis pipeline: raw ``.eml`` bytes in, :class:`~app.models.Report` out.

Each stage is wrapped so a failure (for example a DNS timeout) is recorded in
``Report.warnings`` and the remaining stages still run. This module is the only place that
knows the order of the stages; every stage itself is a plain function over models.

Deviation from the spec's folder tree: this file and ``ioc.py``/``services.py``/``netutil.py``
sit directly in ``app/`` because they are cross-cutting rather than belonging to one stage.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TypeVar

from app.attachments import analyze_attachments
from app.auth_checks import check_auth
from app.enrichment.asn import annotate_hops
from app.heuristics import analyze_heuristics, domain_age_signals
from app.hops import trace_hops
from app.ioc import build_iocs
from app.models import (
    AttachmentFinding,
    AuthReport,
    EmailSummary,
    EnrichmentReport,
    HeuristicsReport,
    HopReport,
    ParsedEmail,
    Report,
    Signal,
    UrlFinding,
)
from app.netutil import registered_domain
from app.parsing import parse_email
from app.scoring import evaluate
from app.services import Services
from app.urls import analyze_urls, expand_shorteners, extract_raw_links, resolve_candidates

log = logging.getLogger(__name__)
T = TypeVar("T")


async def _stage(name: str, warnings: list[str], default: T, fn: Callable[[], Awaitable[T]]) -> T:
    """Run one stage; on any exception record a warning and return ``default``."""
    try:
        return await fn()
    except Exception as exc:
        # Log the exception type only: messages can contain fragments of email content.
        log.warning("stage %s failed: %s", name, type(exc).__name__)
        warnings.append(
            f"The '{name}' stage failed ({type(exc).__name__}); results may be incomplete."
        )
        return default


async def analyze_email(raw: bytes, services: Services, enrich: bool = True) -> Report:
    """Run every analysis stage and assemble the final report."""
    settings = services.settings
    warnings: list[str] = []
    signals: list[Signal] = []

    email: ParsedEmail = await _stage(
        "parsing",
        warnings,
        ParsedEmail(raw_size=len(raw)),
        lambda: asyncio.to_thread(parse_email, raw),
    )

    async def _hops() -> HopReport:
        report, sigs = trace_hops(email)
        signals.extend(sigs)
        return report

    hops = await _stage("hops", warnings, HopReport(), _hops)

    live_resolver = services.resolver if (enrich and settings.live_auth_checks) else None

    async def _auth() -> AuthReport:
        report, sigs = await check_auth(email, hops, live_resolver, settings.dns_timeout_seconds)
        signals.extend(sigs)
        return report

    auth = await _stage("authentication", warnings, AuthReport(), _auth)

    async def _urls() -> list[UrlFinding]:
        links = extract_raw_links(email)
        expansions: dict[str, str] = {}
        if enrich and settings.expand_shorteners:
            expansions = await expand_shorteners(resolve_candidates(links), services.http)
        findings, sigs = analyze_urls(links, expansions)
        signals.extend(sigs)
        return findings

    urls = await _stage("urls", warnings, [], _urls)

    async def _attachments() -> list[AttachmentFinding]:
        # olevba is CPU-bound and synchronous: keep it off the event loop.
        findings, sigs = await asyncio.to_thread(analyze_attachments, email.attachments)
        signals.extend(sigs)
        return findings

    attachments = await _stage("attachments", warnings, [], _attachments)

    async def _heuristics() -> HeuristicsReport:
        report, sigs = analyze_heuristics(email, urls)
        signals.extend(sigs)
        return report

    heuristics = await _stage("heuristics", warnings, HeuristicsReport(), _heuristics)

    async def _enrich() -> EnrichmentReport:
        if not enrich:
            return EnrichmentReport(enabled=False, sources={"all": "skipped: enrich=false"})
        sender = registered_domain(email.from_.domain) if email.from_ else ""
        lookalikes = {registered_domain(d["domain"]) for d in heuristics.lookalikes}
        res = await services.enricher.enrich(sender, urls, attachments, lookalikes)
        signals.extend(res.signals)
        heuristics.domain_ages = res.domain_ages
        signals.extend(domain_age_signals(res.domain_ages, sender, {u.domain for u in urls}))
        if settings.hop_asn_lookup_enabled:
            await asyncio.to_thread(annotate_hops, hops, services.resolver)
        return res.report

    enrichment = await _stage("enrichment", warnings, EnrichmentReport(enabled=False), _enrich)
    if any("MIME defect" in w for w in email.parse_warnings):
        signals.append(Signal(rule_id="mime_malformed", detail="; ".join(email.parse_warnings[:3])))

    result = evaluate(signals, services.ruleset)
    return Report(
        id=uuid.uuid4().hex,
        created_at=datetime.now(UTC),
        verdict=result.verdict,
        score=result.score,
        reasons=result.reasons,
        fired_rules=result.fired_rules,
        overrides_applied=result.overrides_applied,
        email=_summary(email),
        auth=auth,
        hops=hops,
        urls=urls,
        attachments=attachments,
        heuristics=heuristics,
        enrichment=enrichment,
        iocs=build_iocs(email, hops, urls, attachments),
        warnings=warnings,
        parse_warnings=email.parse_warnings,
    )


def _summary(email: ParsedEmail) -> EmailSummary:
    return EmailSummary(
        subject=email.subject[:200],
        from_display=email.from_.display_name if email.from_ else "",
        from_address=email.from_.address if email.from_ else "",
        date=email.date,
        message_id=email.message_id,
        attachment_count=len(email.attachments),
    )
