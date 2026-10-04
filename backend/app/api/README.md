# api/

## 1. Purpose
The HTTP layer: routes, per-install token authentication, per-client rate limiting, bounded in-memory uploads, and the short-lived report store.

## 2. Where it fits
`app/main.py` mounts `routes.router`. Routes call `app/pipeline.py` and `enrichment` (for the consent upload). The extension's background worker is the only intended client.

## 3. Concepts you need to know
- **CORS**: browsers block cross-origin requests unless the server allows the caller's origin. We allow only the extension origin (`chrome-extension://<id>`).
- **Shared-secret token**: the extension sends `X-API-Token`. This is **not strong authentication**: the token sits in the extension's local storage, so malware on that machine or anyone who extracts it can call the API. A production deployment would add per-user login (OIDC), short-lived tokens, mTLS or signed requests, and per-user quotas.
- **Rate limiting (sliding window)**: at most N requests/minute per client.
- **Constant-time comparison**: comparing secrets with `==` leaks, via timing, how many leading characters matched; `secrets.compare_digest` doesn't.

## 4. File-by-file walkthrough
- `routes.py` (prefix `/api/v1`, auth dependency on the whole router)
  - `POST /analyze?enrich=` - multipart `file` or raw `message/rfc822` body -> `Report`.
  - `GET /reports/{id}` and `GET /reports/{id}/iocs?format=json|csv`.
  - `POST /attachments/{sha256}/submit` - multipart `file` (the original .eml) + `consent=true`; uploads only the matching attachment to VirusTotal.
  - (`GET /health` is in `main.py`, unauthenticated.)
- `deps.py` - `require_client` (503 if no tokens configured, 401 on mismatch, 429 with `Retry-After`), `read_body_limited` (413 over `MAX_UPLOAD_BYTES`, checked on `Content-Length` *and* while streaming), `extract_form_file/field` (in-memory multipart splitter).
- `ratelimit.py` - `RateLimiter` sliding window.
- `store.py` - `ReportStore`: TTL (default 15 min) + max entries, RAM only.
- `schemas.py` - `SubmitResponse`.

## 5. Design decisions and why
- **Decision:** Parse multipart ourselves instead of Starlette's `UploadFile`.
  **Why:** Starlette spools uploads larger than 1 MB to temp files; we promised emails never touch disk.
  **Alternatives considered:** Raw body only (the extension does use that), configure larger in-memory spool.
  **Trade-off:** Small custom parser to maintain; it is tested.
- **Decision:** Consent upload re-sends the original `.eml` rather than keeping attachment bytes server-side.
  **Why:** Stateless server, no retained attachments, and the upload request visibly carries the user's consent.
  **Alternatives considered:** Holding bytes in RAM with a short TTL.
  **Trade-off:** The client must still have the email (popup keeps the file; for Gmail messages the popup flow requires downloading the .eml).
- **Decision:** In-memory report store.
  **Why:** Satisfies "do not persist email data"; IDs work for IOC export for a short while.
  **Alternatives considered:** SQLite store.
  **Trade-off:** Reports vanish on restart or after the TTL.
- **Decision:** Auth fails closed when no tokens are configured.
  **Why:** Avoids an accidentally open analyzer; `AUTH_DISABLED=true` is explicit.
  **Alternatives considered:** Open by default for dev.
  **Trade-off:** One extra setup step.

## 6. Edge cases and limitations
- Rate limits and report store are per process.
- A client that can reach the API can make the server resolve DNS and (with keys) spend VirusTotal/urlscan quota; keep it on localhost or behind a VPN/reverse proxy.
- Responses are not signed.

## 7. How to test it
`backend/tests/test_api.py`, `test_enrichment.py` (consent endpoint)
```
cd backend && python -m pytest tests/test_api.py -q
```

## 8. Further reading
FastAPI docs (dependencies, CORS), RFC 6585 (429), RFC 9110 (Retry-After), OWASP API Security Top 10.
