"""urlscan.io client: submit a URL for a live scan, poll for the result.

Privacy note: urlscan.io *visits* the URL from its own infrastructure. We submit with
``visibility: unlisted`` by default so the scan is not shown in the public feed, but the URL is
still sent to a third party (see docs/privacy.md).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import httpx

from app.cache import Cache, url_key
from app.enrichment.limits import Sleep, request_with_retry
from app.models import UrlscanResult
from app.urls.normalize import defang

log = logging.getLogger(__name__)
BASE = "https://urlscan.io"


class UrlscanClient:
    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient,
        cache: Cache,
        *,
        visibility: str = "unlisted",
        ttl_seconds: int = 6 * 3600,
        max_wait: float = 30.0,
        poll_interval: float = 3.0,
        initial_delay: float = 5.0,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.api_key = api_key
        self.client = client
        self.cache = cache
        self.visibility = (
            visibility if visibility in ("public", "unlisted", "private") else "unlisted"
        )
        self.ttl = ttl_seconds
        self.max_wait = max_wait
        self.poll_interval = poll_interval
        self.initial_delay = initial_delay
        self._sleep = sleep
        self.enabled = bool(api_key)

    async def scan(self, url: str) -> UrlscanResult:
        """Submit and poll. Returns status ``pending`` if the scan is not ready within the budget."""
        key = url_key("urlscan", url)
        cached = await self.cache.get(key)
        if cached is not None:
            result = UrlscanResult(**cached)
            result.cached = True
            return result

        shown = defang(url)
        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        resp = await request_with_retry(
            self.client,
            "POST",
            f"{BASE}/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": self.visibility},
            sleep=self._sleep,
        )
        if resp.status_code != 200:
            # 400 usually means urlscan could not resolve/accept the domain: a finding in itself.
            detail = ""
            with contextlib.suppress(ValueError):
                detail = resp.json().get("message", "")
            return UrlscanResult(url=shown, status="failed", detail=detail[:160])
        uuid = resp.json().get("uuid", "")
        result_url = f"{BASE}/result/{uuid}/"
        await self._sleep(min(self.initial_delay, self.max_wait))
        # Count attempts instead of reading the clock: deterministic, and easy to test.
        attempts = max(1, int(self.max_wait // self.poll_interval))
        for attempt in range(attempts):
            poll = await self.client.get(f"{BASE}/api/v1/result/{uuid}/", headers=headers)
            if poll.status_code == 200:
                result = self._parse(poll.json(), shown, uuid, result_url)
                await self.cache.set(key, result.model_dump(), self.ttl)
                return result
            if poll.status_code not in (404, 410):
                return UrlscanResult(url=shown, status="failed", uuid=uuid, result_url=result_url)
            if attempt < attempts - 1:
                await self._sleep(self.poll_interval)  # 404 = scan still running
        return UrlscanResult(url=shown, status="pending", uuid=uuid, result_url=result_url)

    @staticmethod
    def _parse(payload: dict, shown: str, uuid: str, result_url: str) -> UrlscanResult:
        overall = payload.get("verdicts", {}).get("overall", {})
        task = payload.get("task", {})
        page = payload.get("page", {})
        return UrlscanResult(
            url=shown,
            status="done",
            uuid=uuid,
            malicious=bool(overall.get("malicious", False)),
            score=int(overall.get("score", 0)),
            final_url=defang(page.get("url", "")) if page.get("url") else "",
            screenshot_url=task.get("screenshotURL") or f"{BASE}/screenshots/{uuid}.png",
            result_url=result_url,
        )
