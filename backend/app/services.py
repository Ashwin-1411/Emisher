"""Long-lived objects shared by requests (resolver, HTTP client, cache, report store...).

Bundling them in one dataclass keeps ``create_app`` the single place where wiring happens and
lets tests swap any piece (static DNS, mocked HTTP, in-memory cache) without monkeypatching.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from app.api.ratelimit import RateLimiter
from app.api.store import ReportStore
from app.auth_checks.resolver import DnsResolver, SystemResolver
from app.cache import Cache, build_cache
from app.config import Settings
from app.enrichment import Enricher
from app.scoring import RuleSet, load_rules


@dataclass
class Services:
    settings: Settings
    resolver: DnsResolver
    http: httpx.AsyncClient
    cache: Cache
    ruleset: RuleSet
    enricher: Enricher
    reports: ReportStore = field(default_factory=ReportStore)
    limiter: RateLimiter = field(default_factory=RateLimiter)


def build_services(settings: Settings) -> Services:
    """Production wiring from settings."""
    http = httpx.AsyncClient(
        timeout=settings.http_timeout_seconds,
        headers={"User-Agent": "phishing-email-analyzer/0.1"},
    )
    cache = build_cache(settings)
    return Services(
        settings=settings,
        resolver=SystemResolver(settings.dns_timeout_seconds),
        http=http,
        cache=cache,
        ruleset=load_rules(
            settings.scoring_rules_path,
            settings.score_suspicious_threshold,
            settings.score_phishing_threshold,
        ),
        enricher=Enricher(settings, http, cache),
        reports=ReportStore(settings.report_ttl_seconds, settings.report_store_max),
        limiter=RateLimiter(settings.rate_limit_per_minute),
    )
