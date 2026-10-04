"""SQLite and in-memory cache implementations."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class MemoryCache:
    """Process-local dict cache. Used in tests and when ``CACHE_BACKEND=memory``."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}

    async def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, payload = item
        if expires < time.time():
            self._data.pop(key, None)
            return None
        return json.loads(payload)

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._data[key] = (time.time() + ttl_seconds, json.dumps(value))

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def close(self) -> None:
        self._data.clear()


class SqliteCache:
    """Persistent cache in a single SQLite file.

    sqlite3 is synchronous, so each call runs in a worker thread (``asyncio.to_thread``) behind
    one lock. That is plenty for a cache that sees a handful of writes per analysed email, and
    it avoids adding an async SQLite dependency.
    """

    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL)"
        )
        self._conn.commit()
        self._lock = asyncio.Lock()

    def _get(self, key: str) -> Any | None:
        row = self._conn.execute(
            "SELECT value, expires FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if row[1] < time.time():
            self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(row[0])

    def _set(self, key: str, value: Any, ttl: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, value, expires) VALUES (?, ?, ?)",
            (key, json.dumps(value), time.time() + ttl),
        )
        # Opportunistic cleanup keeps the file from growing without a background job.
        self._conn.execute("DELETE FROM cache WHERE expires < ?", (time.time(),))
        self._conn.commit()

    def _delete(self, key: str) -> None:
        self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        self._conn.commit()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            return await asyncio.to_thread(self._get, key)

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        async with self._lock:
            await asyncio.to_thread(self._set, key, value, ttl_seconds)

    async def delete(self, key: str) -> None:
        async with self._lock:
            await asyncio.to_thread(self._delete, key)

    async def close(self) -> None:
        self._conn.close()
