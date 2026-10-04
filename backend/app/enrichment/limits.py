"""Outbound rate limiting and retry helpers shared by the enrichment clients."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx

Sleep = Callable[[float], Awaitable[None]]
RETRY_STATUSES = {429, 500, 502, 503, 504}


class TokenBucket:
    """Async token bucket. Waiters queue up on a lock, so requests are served in order.

    ``acquire(max_wait)`` returns False instead of waiting longer than ``max_wait`` seconds:
    an analysis must stay responsive, so we would rather skip a lookup (and say so in the
    report) than hold the user's request for minutes behind the free-tier quota.
    """

    def __init__(
        self,
        per_minute: float,
        capacity: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.rate = per_minute / 60.0
        self.capacity = capacity if capacity is not None else max(1.0, per_minute)
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    async def _take(self, max_wait: float) -> bool:
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                if wait > max_wait:
                    return False
                await self._sleep(wait)
                self._refill()
            self._tokens = max(0.0, self._tokens - 1)
            return True

    async def acquire(self, max_wait: float = 20.0) -> bool:
        try:
            return await asyncio.wait_for(self._take(max_wait), timeout=max_wait + 1)
        except TimeoutError:
            return False


class DailyQuota:
    """Counts requests per UTC day (in memory; resets on restart or at midnight)."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._day = datetime.now(UTC).date()
        self._used = 0

    def try_use(self) -> bool:
        today = datetime.now(UTC).date()
        if today != self._day:
            self._day, self._used = today, 0
        if self._used >= self.limit:
            return False
        self._used += 1
        return True


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 2,
    backoff: float = 0.5,
    sleep: Sleep = asyncio.sleep,
    **kwargs,
) -> httpx.Response:
    """HTTP request with exponential backoff on timeouts, 429 and 5xx.

    Honours a numeric ``Retry-After`` (capped at 10 s). Jitter avoids retrying in lockstep
    with other callers. The final response (even an error status) is returned to the caller;
    only transport errors on the last attempt are raised.
    """
    for attempt in range(retries + 1):
        delay = backoff * (2**attempt)
        try:
            resp = await client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError):
            if attempt == retries:
                raise
        else:
            if resp.status_code not in RETRY_STATUSES or attempt == retries:
                return resp
            retry_after = resp.headers.get("retry-after", "")
            if retry_after.isdigit():
                delay = min(float(retry_after), 10.0)
        await sleep(delay + random.uniform(0, delay / 4))  # noqa: S311 - jitter, not security
    raise AssertionError("unreachable")  # pragma: no cover
