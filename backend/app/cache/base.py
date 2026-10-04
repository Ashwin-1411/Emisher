"""Cache interface. Today: SQLite or in-memory. Tomorrow: Redis, by implementing these 3 methods."""

from __future__ import annotations

from typing import Any, Protocol


class Cache(Protocol):
    """Async key/value store with per-entry TTL. Values must be JSON-serialisable.

    Keys are namespaced strings such as ``vt:file:<sha256>``. Callers must only ever store
    enrichment results here, never email content (see docs/privacy.md).
    """

    async def get(self, key: str) -> Any | None: ...

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None: ...

    async def delete(self, key: str) -> None: ...

    async def close(self) -> None: ...
