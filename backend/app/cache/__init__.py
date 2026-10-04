"""Enrichment cache."""

from __future__ import annotations

import hashlib

from app.cache.base import Cache
from app.cache.sqlite import MemoryCache, SqliteCache
from app.config import Settings


def build_cache(settings: Settings) -> Cache:
    """Pick the backend named in settings. A Redis backend would be added here."""
    if settings.cache_backend == "memory":
        return MemoryCache()
    return SqliteCache(settings.cache_path)


def url_key(prefix: str, url: str) -> str:
    """Cache key for a URL. Only a hash of the URL is stored, never the URL itself, because
    links in a phishing email can embed the recipient's address or a personal token."""
    return f"{prefix}:{hashlib.sha256(url.encode()).hexdigest()}"


__all__ = ["Cache", "MemoryCache", "SqliteCache", "build_cache", "url_key"]
