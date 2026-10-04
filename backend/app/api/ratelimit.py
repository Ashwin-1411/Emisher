"""Per-client rate limiting (sliding window, in memory)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    """Allow at most ``limit`` requests per ``window`` seconds for each client key.

    In-memory means limits reset on restart and are per process; with several workers each
    would count separately. That is acceptable for a single-container deployment; a shared
    store (Redis) would be needed to scale out.
    """

    def __init__(self, limit: int = 30, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, now: float | None = None) -> float | None:
        """Record a hit. Returns None if allowed, else the seconds to wait before retrying."""
        now = time.monotonic() if now is None else now
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(0.0, hits[0] + self.window - now)
        hits.append(now)
        return None
