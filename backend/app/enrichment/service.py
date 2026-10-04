"""Coordinates the external lookups for one report.

Every source is optional and isolated: a missing key, a rate limit or an outage turns into a
line in ``EnrichmentReport.sources`` (and sometimes a warning), never into a failed analysis.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

from app.cache import Cache
from app.config import Settings
from app.enrichment.rdap import RdapClient
from app.enrichment.urlscan import UrlscanClient
from app.enrichment.virustotal import VirusTotalClient, VtUnavailable
from app.heuristics.lookalike import load_brands
from app.models import (
    AttachmentFinding,
    DomainAge,
    EnrichmentReport,
    Signal,
    UrlFinding,
    UrlscanResult,
    VtResult,
)
from app.netutil import registered_domain

log = logging.getLogger(__name__)

VT_MALICIOUS_MIN = 3  # engines that must agree before we call something malicious


@dataclass
class EnrichmentResult:
    report: EnrichmentReport
    domain_ages: list[DomainAge] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _url_priority(url: UrlFinding, lookalike_domains: set[str]) -> int:
    """Higher = more worth spending scarce quota on."""
    score = 0
    if url.text_mismatch:
        score += 3
    if url.domain in lookalike_domains:
        score += 3
    if {"ip_host", "userinfo", "shortener", "punycode_host"} & set(url.flags):
        score += 2
    return score


class Enricher:
    """Holds the three API clients and runs them concurrently for each report."""

    def __init__(
        self,
        settings: Settings,
        http: httpx.AsyncClient,
        cache: Cache,
        *,
        sleep=None,
    ) -> None:
        self.settings = settings
        kw = {"sleep": sleep} if sleep else {}
        self.vt = VirusTotalClient(
            settings.vt_api_key,
            http,
            cache,
            per_minute=settings.vt_requests_per_minute,
            daily_quota=settings.vt_daily_quota,
            ttl_seconds=settings.cache_ttl_vt_seconds,
            max_wait=settings.vt_max_wait_seconds,
            **kw,
        )
        self.urlscan = UrlscanClient(
            settings.urlscan_api_key,
            http,
            cache,
            visibility=settings.urlscan_visibility,
            ttl_seconds=settings.cache_ttl_urlscan_seconds,
            max_wait=settings.urlscan_max_wait_seconds,
            **kw,
        )
        self.rdap = RdapClient(
            http,
            cache,
            base_url=settings.rdap_base_url,
            ttl_seconds=settings.cache_ttl_rdap_seconds,
            **kw,
        )

    async def enrich(
        self,
        sender_domain: str,
        urls: list[UrlFinding],
        attachments: list[AttachmentFinding],
        lookalike_domains: set[str],
    ) -> EnrichmentResult:
        result = EnrichmentResult(report=EnrichmentReport(enabled=True))
        ranked = sorted(urls, key=lambda u: -_url_priority(u, lookalike_domains))
        await asyncio.gather(
            self._run_rdap(result, sender_domain, ranked),
            self._run_vt(result, ranked, attachments),
            self._run_urlscan(result, ranked),
        )
        return result

    # ------------------------------------------------------------------ RDAP
    async def _run_rdap(
        self, out: EnrichmentResult, sender_domain: str, urls: list[UrlFinding]
    ) -> None:
        if not self.settings.rdap_enabled:
            out.report.sources["rdap"] = "skipped: disabled in configuration"
            return
        # Well-known brand domains are decades old; don't waste lookups (or leak queries) on them.
        known = {d for b in load_brands() for d in b.domains}
        candidates: list[str] = []
        for domain in [
            registered_domain(sender_domain),
            *(u.domain for u in urls if "ip_host" not in u.flags),
        ]:
            if domain and "." in domain and domain not in known and domain not in candidates:
                candidates.append(domain)
        candidates = candidates[: self.settings.rdap_max_lookups_per_report]
        if not candidates:
            out.report.sources["rdap"] = "skipped: no domains to look up"
            return
        results = await asyncio.gather(
            *(self.rdap.domain_age(d) for d in candidates), return_exceptions=True
        )
        failed = 0
        for domain, res in zip(candidates, results, strict=True):
            if isinstance(res, BaseException):
                failed += 1
                log.info("rdap lookup failed: %s", type(res).__name__)
                out.domain_ages.append(DomainAge(domain=domain))
            else:
                out.domain_ages.append(res)
        out.report.sources["rdap"] = "ok" if not failed else f"partial: {failed} lookup(s) failed"

    # ------------------------------------------------------------------ VirusTotal
    async def _run_vt(
        self, out: EnrichmentResult, urls: list[UrlFinding], attachments: list[AttachmentFinding]
    ) -> None:
        if not self.vt.enabled:
            out.report.sources["virustotal"] = "skipped: no API key configured"
            return
        # (kind, target, filename) in priority order: files first, they can force a verdict.
        jobs: list[tuple[str, str, str]] = [("file", a.sha256, a.filename) for a in attachments]
        jobs += [("url", u.url, "") for u in urls]
        jobs = jobs[: self.settings.vt_max_lookups_per_report]
        skipped = 0
        reasons: set[str] = set()
        for kind, target, filename in jobs:
            try:
                res = await (
                    self.vt.lookup_file(target) if kind == "file" else self.vt.lookup_url(target)
                )
            except VtUnavailable as exc:
                skipped += 1
                reasons.add(str(exc))
                continue
            except httpx.HTTPError as exc:
                skipped += 1
                reasons.add(f"VirusTotal unreachable ({type(exc).__name__})")
                continue
            out.report.virustotal.append(res)
            out.signals.extend(self._vt_signals(res, filename))
        total_skipped = skipped + max(0, len(urls) + len(attachments) - len(jobs))
        if skipped:
            out.report.sources["virustotal"] = (
                f"partial: {skipped} lookup(s) skipped ({'; '.join(sorted(reasons))})"
            )
        elif total_skipped:
            out.report.sources["virustotal"] = (
                f"ok (limited to the {len(jobs)} most relevant indicators)"
            )
        else:
            out.report.sources["virustotal"] = "ok"

    @staticmethod
    def _vt_signals(res: VtResult, filename: str) -> list[Signal]:
        if not res.found:
            return []
        if res.kind == "file" and res.malicious >= VT_MALICIOUS_MIN:
            return [
                Signal(
                    rule_id="vt_file_malicious",
                    detail=f"{res.malicious} engines flag sha256 {res.target[:16]}... ({filename})",
                    context={"filename": filename, "engines": res.malicious},
                )
            ]
        if res.kind == "url":
            if res.malicious >= VT_MALICIOUS_MIN:
                return [
                    Signal(
                        rule_id="vt_url_malicious",
                        detail=f"{res.malicious} engines flag {res.target}",
                        context={"url": res.target, "engines": res.malicious},
                    )
                ]
            if res.malicious or res.suspicious:
                return [
                    Signal(
                        rule_id="vt_url_suspicious",
                        detail=f"{res.malicious} malicious / {res.suspicious} suspicious for {res.target}",
                        context={"url": res.target},
                    )
                ]
        return []

    # ------------------------------------------------------------------ urlscan.io
    async def _run_urlscan(self, out: EnrichmentResult, urls: list[UrlFinding]) -> None:
        if not self.urlscan.enabled:
            out.report.sources["urlscan"] = "skipped: no API key configured"
            return
        chosen = urls[: self.settings.urlscan_max_scans_per_report]
        if not chosen:
            out.report.sources["urlscan"] = "skipped: no links in the email"
            return

        async def one(url: UrlFinding) -> UrlscanResult | None:
            try:
                return await self.urlscan.scan(url.url)
            except httpx.HTTPError as exc:
                log.info("urlscan failed: %s", type(exc).__name__)
                return None

        results = await asyncio.gather(*(one(u) for u in chosen))
        errors = 0
        for res in results:
            if res is None:
                errors += 1
                continue
            out.report.urlscan.append(res)
            if res.status == "done" and res.malicious:
                out.signals.append(
                    Signal(
                        rule_id="urlscan_malicious",
                        detail=f"urlscan.io verdict malicious (score {res.score}) for {res.url}",
                        context={"url": res.url},
                    )
                )
        pending = sum(1 for r in out.report.urlscan if r.status == "pending")
        failed = sum(1 for r in out.report.urlscan if r.status == "failed")
        notes = []
        if pending:
            notes.append(f"{pending} scan(s) still running; open the result link later")
        if failed or errors:
            notes.append(f"{failed + errors} scan(s) failed")
        out.report.sources["urlscan"] = "ok" if not notes else "partial: " + "; ".join(notes)
