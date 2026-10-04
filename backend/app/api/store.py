"""Short-lived in-memory report store.

Reports contain derived metadata (headers summary, URLs, hashes), never message bodies or
attachment bytes. They live in RAM only, expire after a TTL and are capped in number, so
nothing about an analysed email survives a restart.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from app.models import Report


class ReportStore:
    def __init__(self, ttl_seconds: int = 900, max_entries: int = 200) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._items: OrderedDict[str, tuple[float, Report]] = OrderedDict()

    def _purge(self) -> None:
        now = time.monotonic()
        for key in [k for k, (exp, _) in self._items.items() if exp < now]:
            del self._items[key]
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)  # evict the oldest

    def put(self, report: Report) -> None:
        self._items[report.id] = (time.monotonic() + self.ttl, report)
        self._purge()

    def get(self, report_id: str) -> Report | None:
        self._purge()
        item = self._items.get(report_id)
        return item[1] if item else None
