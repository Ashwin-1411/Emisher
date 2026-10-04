"""Expand URL shorteners over the network (backend only, strictly limited).

Safety rules, each one a deliberate limit on what a hostile email can make our server do:

* only hosts in ``data/shorteners.json`` are ever contacted;
* a HEAD request, redirects NOT followed automatically, at most 5 hops, short timeout;
* we read the ``Location`` header and, if it points to another *shortener*, follow that;
  as soon as it points anywhere else we stop and report it without visiting it.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin, urlsplit

import httpx

from app.urls.normalize import shortener_hosts

log = logging.getLogger(__name__)
MAX_REDIRECTS = 5


async def expand_one(client: httpx.AsyncClient, url: str) -> str | None:
    """Return the destination of a shortener URL, or None if it cannot be determined."""
    current = url
    for _ in range(MAX_REDIRECTS):
        host = urlsplit(current).hostname or ""
        if host not in shortener_hosts():
            return current if current != url else None
        try:
            resp = await client.head(current, follow_redirects=False)
        except httpx.HTTPError as exc:
            log.info("shortener expansion failed: %s", type(exc).__name__)
            return current if current != url else None
        location = resp.headers.get("location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            return current if current != url else None
        current = urljoin(current, location)
    return current


async def expand_shorteners(
    urls: list[str], client: httpx.AsyncClient, limit: int = 5
) -> dict[str, str]:
    """Expand up to ``limit`` shortener URLs concurrently; failures are simply omitted."""
    chosen = urls[:limit]
    results = await asyncio.gather(*(expand_one(client, u) for u in chosen))
    return {u: r for u, r in zip(chosen, results, strict=True) if r}
