"""RDAP (Registration Data Access Protocol) domain-age lookups. No API key needed.

RDAP is the JSON successor to WHOIS (RFC 7480-7483). ``rdap.org`` is a public bootstrap
service that redirects each query to the registry responsible for the TLD, so we do not have
to maintain the IANA bootstrap file ourselves.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import httpx

from app.cache import Cache
from app.enrichment.limits import Sleep, request_with_retry
from app.heuristics.domain_age import age_in_days
from app.models import DomainAge

log = logging.getLogger(__name__)


class RdapClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        cache: Cache,
        base_url: str = "https://rdap.org",
        ttl_seconds: int = 7 * 24 * 3600,
        sleep: Sleep | None = None,
    ) -> None:
        self.client = client
        self.cache = cache
        self.base_url = base_url.rstrip("/")
        self.ttl = ttl_seconds
        self._sleep = sleep

    async def domain_age(self, domain: str, now: datetime | None = None) -> DomainAge:
        """Registration date and age in days; ``registered`` is None when unknown."""
        key = f"rdap:{domain}"
        cached = await self.cache.get(key)
        if cached is not None:
            registered = (
                datetime.fromisoformat(cached["registered"]) if cached["registered"] else None
            )
        else:
            registered = await self._fetch(domain)
            await self.cache.set(
                key,
                {"registered": registered.isoformat() if registered else None},
                self.ttl if registered else 3600,  # unknowns are retried sooner
            )
        return DomainAge(
            domain=domain,
            registered=registered,
            age_days=age_in_days(registered, now) if registered else None,
        )

    async def _fetch(self, domain: str) -> datetime | None:
        kwargs = {"sleep": self._sleep} if self._sleep else {}
        resp = await request_with_retry(
            self.client,
            "GET",
            f"{self.base_url}/domain/{domain}",
            headers={"accept": "application/rdap+json"},
            follow_redirects=True,
            **kwargs,
        )
        if resp.status_code != 200:
            return None
        try:
            events = resp.json().get("events", [])
        except ValueError:
            return None
        for event in events:
            if event.get("eventAction") == "registration" and event.get("eventDate"):
                try:
                    parsed = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                except ValueError:
                    return None
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return None
