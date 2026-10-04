# cache/

## 1. Purpose
A small async key/value cache with per-entry expiry, used so the same URL, hash or domain is never looked up twice within its time-to-live. It stores enrichment results only, never email content.

## 2. Where it fits
Used by `enrichment/` (VirusTotal, urlscan, RDAP). Built in `app/services.py` from `CACHE_BACKEND` / `CACHE_PATH`. Nothing else depends on its storage.

## 3. Concepts you need to know
- **TTL (time to live)**: how long a cached answer is trusted. Reputation changes slowly (hours), registration dates almost never (days), "not found" answers should expire sooner.
- **Why cache at all**: the VirusTotal free tier allows only ~4 requests/minute.
- **Interface (Protocol) pattern**: callers depend on `get/set/delete/close`, so SQLite can be swapped for Redis by writing one class.

## 4. File-by-file walkthrough
- `base.py` - the `Cache` protocol.
- `sqlite.py` - `SqliteCache` (one table `cache(key, value JSON, expires)`, sync `sqlite3` calls run via `asyncio.to_thread` behind a lock, expired rows removed opportunistically on writes) and `MemoryCache` (dict, for tests/`CACHE_BACKEND=memory`).
- `__init__.py` - `build_cache(settings)` and `url_key(prefix, url)` which stores only `sha256(url)`.

## 5. Design decisions and why
- **Decision:** Stdlib `sqlite3` in threads rather than `aiosqlite`.
  **Why:** One fewer dependency; the cache sees a few operations per email.
  **Alternatives considered:** `aiosqlite`, Redis now.
  **Trade-off:** A global lock serialises cache calls.
- **Decision:** Keys use a hash of the URL.
  **Why:** Links can contain recipient addresses/tokens; the cache file should not become a trove of them.
  **Alternatives considered:** Plain URLs.
  **Trade-off:** Entries aren't human-searchable.
- **Decision:** JSON values only.
  **Why:** Portable to Redis, inspectable, no unpickling risks.
  **Alternatives considered:** `pickle`.
  **Trade-off:** Models are converted with `model_dump()`.

## 6. Edge cases and limitations
- Single-process: two workers sharing one SQLite file work, but the lock is per process.
- No size cap besides TTL expiry.
- The SQLite file is created under `CACHE_PATH`; in Docker it sits on the `cache-data` volume.

## 7. How to test it
`backend/tests/test_cache.py`
```
cd backend && python -m pytest tests/test_cache.py -q
```

## 8. Further reading
SQLite docs (WAL, locking), Redis `SET key value EX ttl`, RFC 9111 (HTTP caching concepts).
