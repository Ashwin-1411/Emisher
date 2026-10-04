# background/

## 1. Purpose
The service worker. It owns all communication with the backend, reads the stored URL and token, and caches reports per Gmail message.

## 2. Where it fits
Receives `analyze`, `submitAttachment` and `testConnection` messages from `popup/`, `content/` and `options/`; calls `shared/api.ts`.

## 3. Concepts you need to know
MV3 workers are stopped when idle, so nothing important is kept in variables. `chrome.storage.session` is in-memory, survives worker restarts and is cleared when the browser closes (nothing reaches disk). Returning `true` from `onMessage` keeps the response channel open for async work.

## 4. File-by-file walkthrough
`index.ts`: `handle(msg)` dispatches by `msg.type`; `cacheGet/cacheSet` store reports under `report:<cacheKey>` (cap 50, oldest evicted); the listener wraps results as `{ok, data}` or `{ok:false, error}`.

## 5. Design decisions and why
- **Decision:** Cache by Gmail message id in `storage.session`.
  **Why:** Re-opening a message should not re-send it or spend VirusTotal quota.
  **Alternatives considered:** `storage.local` (persists reports on disk).
  **Trade-off:** The cache is lost when the browser restarts.
- **Decision:** Refuse to call the backend without a token.
  **Why:** Fail early with an actionable message instead of a bare 401.
  **Alternatives considered:** Let the backend reject.
  **Trade-off:** None significant.

## 6. Edge cases and limitations
Large emails are base64-encoded across the message channel (about 33% bigger). Only `analyze` results are cached, and only when a `cacheKey` is supplied.

## 7. How to test it
Manual: load the unpacked extension, run an analysis, inspect the service worker console at `chrome://extensions`.

## 8. Further reading
Chrome docs: extension service worker lifecycle; `chrome.storage.session`.
