"""VirusTotal v3 client: URL and file-hash reputation, plus consented file upload.

Free tier: about 4 requests/minute and 500/day, so every lookup goes through a token bucket
and a daily counter, and results are cached by hash so the same indicator is never asked twice.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging

import httpx

from app.cache import Cache, url_key
from app.enrichment.limits import DailyQuota, Sleep, TokenBucket, request_with_retry
from app.models import VtResult
from app.urls.normalize import defang

log = logging.getLogger(__name__)
BASE = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # larger files need a special upload URL; out of scope


class VtUnavailable(Exception):
    """Raised when a lookup is skipped (rate limit, quota, no key). The message is shown."""


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        client: httpx.AsyncClient,
        cache: Cache,
        *,
        per_minute: int = 4,
        daily_quota: int = 500,
        ttl_seconds: int = 86400,
        max_wait: float = 20.0,
        sleep: Sleep | None = None,
    ) -> None:
        self.api_key = api_key
        self.client = client
        self.cache = cache
        self.bucket = (
            TokenBucket(per_minute) if sleep is None else TokenBucket(per_minute, sleep=sleep)
        )
        self.quota = DailyQuota(daily_quota)
        self.ttl = ttl_seconds
        self.max_wait = max_wait
        self._sleep = sleep
        self.enabled = bool(api_key)

    @property
    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key, "accept": "application/json"}

    async def _get(self, path: str) -> httpx.Response:
        if not self.quota.try_use():
            raise VtUnavailable("VirusTotal daily quota used up")
        if not await self.bucket.acquire(self.max_wait):
            raise VtUnavailable("VirusTotal rate limit: lookup skipped to keep the analysis fast")
        return await request_with_retry(
            self.client,
            "GET",
            f"{BASE}{path}",
            headers=self._headers,
            sleep=self._sleep or asyncio.sleep,
        )

    @staticmethod
    def _parse(kind: str, target: str, payload: dict, permalink: str) -> VtResult:
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return VtResult(
            kind=kind,
            target=target,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            permalink=permalink,
        )

    async def _lookup(self, kind: str, key: str, path: str, shown: str, link: str) -> VtResult:
        cached = await self.cache.get(key)
        if cached is not None:
            result = VtResult(**cached)
            result.cached = True
            return result
        resp = await self._get(path)
        if resp.status_code == 404:  # VT has never seen it: not evidence either way
            result = VtResult(kind=kind, target=shown, found=False)
            await self.cache.set(key, result.model_dump(), min(self.ttl, 3600))
            return result
        if resp.status_code != 200:
            raise VtUnavailable(f"VirusTotal returned HTTP {resp.status_code}")
        result = self._parse(kind, shown, resp.json(), link)
        await self.cache.set(key, result.model_dump(), self.ttl)
        return result

    async def lookup_url(self, url: str) -> VtResult:
        """Reputation of a URL. The URL id is the unpadded URL-safe base64 of the URL (VT API)."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._lookup(
            "url",
            url_key("vt:url", url),
            f"/urls/{url_id}",
            defang(url),
            f"https://www.virustotal.com/gui/url/{url_id}",
        )

    async def lookup_file(self, sha256: str) -> VtResult:
        """Reputation of a file by hash. The file itself is never sent."""
        return await self._lookup(
            "file",
            f"vt:file:{sha256}",
            f"/files/{sha256}",
            sha256,
            f"https://www.virustotal.com/gui/file/{sha256}",
        )

    async def upload_file(self, filename: str, data: bytes) -> tuple[str, str]:
        """Upload bytes to VirusTotal. Only call this after explicit user consent.

        Returns ``(analysis_id, permalink)``. Uploaded files are shared with VirusTotal's
        security partners, so this is never done implicitly.
        """
        if len(data) > MAX_UPLOAD_BYTES:
            raise VtUnavailable("File is larger than 32 MB, the limit for direct upload")
        if not self.quota.try_use():
            raise VtUnavailable("VirusTotal daily quota used up")
        if not await self.bucket.acquire(self.max_wait):
            raise VtUnavailable("VirusTotal rate limit reached; try again in a minute")
        resp = await self.client.post(
            f"{BASE}/files",
            headers={"x-apikey": self.api_key},
            files={"file": (filename or "attachment", data)},
        )
        if resp.status_code != 200:
            raise VtUnavailable(f"VirusTotal upload failed (HTTP {resp.status_code})")
        analysis_id = resp.json().get("data", {}).get("id", "")
        sha256 = hashlib.sha256(data).hexdigest()
        return analysis_id, f"https://www.virustotal.com/gui/file/{sha256}"
