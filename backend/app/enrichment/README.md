# enrichment/

## 1. Purpose
Asks external services what they know: VirusTotal (URL and file-hash reputation, plus consented upload), urlscan.io (live page scan, verdict, final URL, screenshot) and RDAP (domain registration date). Optionally maps hop IPs to ASN/country. Everything is optional; no key means that source is skipped and says so.

## 2. Where it fits
Called by `app/pipeline.py` only when `enrich=true`, after offline analysis. Results become signals (`vt_file_malicious`, `urlscan_malicious`, `young_domain_*`) for `scoring/`. Uses `cache/` for results and `app/netutil.py` helpers.

## 3. Concepts you need to know
- **Reputation vs sandboxing.** VirusTotal tells you what ~70 antivirus engines *already think* about a hash/URL. That is a lookup, not detonation: a brand-new malware sample has no reputation yet. Real sandboxes (running the file in an instrumented VM) are future work.
- **Hash lookups are privacy-friendly**: only the SHA-256 leaves the machine. **Uploads are not**: a file sent to VirusTotal is shared with its partners - hence the separate consent endpoint.
- **urlscan.io** visits the URL from its servers. `visibility: unlisted` keeps the scan out of the public feed but the URL still reaches a third party.
- **Rate limits**: VirusTotal free tier = about 4 requests/minute, 500/day. **Token bucket**: a bucket refills at a fixed rate; each request takes a token; an empty bucket makes the caller wait.
- **Exponential backoff with jitter**: retry after 0.5 s, 1 s, 2 s... plus randomness so many clients don't retry together.

## 4. File-by-file walkthrough
- `limits.py` - `TokenBucket` (FIFO via a lock; refuses instead of waiting past `max_wait`), `DailyQuota`, `request_with_retry` (timeouts, 429/5xx, honours `Retry-After`).
- `virustotal.py` - `VirusTotalClient.lookup_url` (id = unpadded urlsafe base64 of the URL), `lookup_file`, `upload_file` (32 MB limit). Cache by hash; 404s cached briefly.
- `urlscan.py` - `UrlscanClient.scan`: POST scan, wait, poll the result endpoint (404 = still running), return `done|pending|failed`.
- `rdap.py` - `RdapClient.domain_age` via `rdap.org` (follows redirects to the registry), reads the `registration` event.
- `asn.py` - Team Cymru DNS lookup for IPv4 (`HOP_ASN_LOOKUP_ENABLED`).
- `service.py` - `Enricher.enrich` runs RDAP, VirusTotal and urlscan concurrently, ranks URLs (mismatch/lookalike/shortener first), enforces per-report caps, and writes status lines to `EnrichmentReport.sources`.

## 5. Design decisions and why
- **Decision:** Per-report caps and a wait budget instead of queuing indefinitely.
  **Why:** At 4 requests/min a naive implementation would hold the user's request for minutes.
  **Alternatives considered:** Background job queue with polling (more moving parts).
  **Trade-off:** With the free tier only the most relevant indicators (attachments first, then most suspicious URLs) are checked; the report says "limited".
- **Decision:** urlscan polling happens inside the request, bounded by `URLSCAN_MAX_WAIT_SECONDS`; a still-running scan returns `pending` with its result link.
  **Why:** Simple and stateless.
  **Alternatives considered:** Background task that patches the stored report.
  **Trade-off:** Slow scans need a manual follow-up.
- **Decision:** Hash lookups by default; upload only through `/attachments/{sha256}/submit` with `consent=true`.
  **Why:** Uploading leaks file content.
  **Alternatives considered:** Auto-upload unknown hashes.
  **Trade-off:** Unknown/new malware shows "not known to VirusTotal".
- **Decision:** Cache keys for URLs are hashes.
  **Why:** URLs may embed personal tokens or addresses.
  **Alternatives considered:** Store URL text.
  **Trade-off:** Cache entries can't be inspected by URL.
- **Decision:** All clients take an `httpx.AsyncClient` and an injectable `sleep`.
  **Why:** Tests mock transports and skip waiting, so the suite needs no network or keys.
  **Alternatives considered:** `respx` patches.
  **Trade-off:** Slightly more constructor arguments.

## 6. Edge cases and limitations
- Daily quota and token bucket are in-memory per process.
- A VT "malicious" verdict needs 3+ engines; fewer produces only the weaker `vt_url_suspicious`.
- Live API behaviour was only tested against mocks of the documented responses; run once with real keys and check `sources` in the report.
- RDAP bootstrap via a third-party service (`rdap.org`) reveals queried domains to it.

## 7. How to test it
`backend/tests/test_enrichment.py`, `test_cache.py`
```
cd backend && python -m pytest tests/test_enrichment.py -q
```

## 8. Further reading
VirusTotal API v3 docs, urlscan.io API docs, RFC 7480-7483 (RDAP), RFC 9110 section 10.2.3 (Retry-After), "token bucket algorithm".
