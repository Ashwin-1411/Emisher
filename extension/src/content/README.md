# content/

## 1. Purpose
Detects an opened Gmail message, gets its raw source through the user's existing Gmail session, requests analysis from the background worker and injects a banner above the message body.

## 2. Where it fits
Injected on `https://mail.google.com/*`. Talks to `background/` via messages; uses `shared/` for helpers.

## 3. Concepts you need to know
- **Isolated world**: the script sees the DOM but not Gmail's JavaScript globals.
- **"Show original"**: a Gmail view that returns the full RFC 5322 source of a message, including the `Authentication-Results` and `Received` headers the analyzer needs. The URL used here is `.../mail/u/<n>/?ik=<token>&view=om&permmsgid=msg-f:<decimal id>`; the decimal id comes from the `data-message-id` attribute of the message element.
- **MutationObserver**: Gmail is a single-page app; messages appear without page loads, so we watch DOM changes (debounced 400 ms).

## 4. File-by-file walkthrough
- `gmail-selectors.ts` - **every** Gmail-specific selector, attribute name and URL format: `SELECTORS`, `ATTRS`, `accountIndex`, `messageIdFrom`, `findIk`, `buildOriginalUrl`, `parseOriginalResponse`.
- `index.ts` - observer + `process(container)`: marks the container done, inserts a loading banner, fetches the source (LF to CRLF so DKIM can verify), sends `analyze` with `cacheKey = gmail:<id>`, replaces the banner with the verdict or an error.
- `banner.ts` - closed shadow-root banner (`loadingBanner`, `errorBanner`, `reportBanner`).

## 5. Design decisions and why
- **Decision:** One file for all Gmail internals.
  **Why:** Gmail changes without notice; a fix should touch one place.
  **Alternatives considered:** Selectors inline.
  **Trade-off:** Indirection.
- **Decision:** Errors become a visible grey banner with a fallback hint.
  **Why:** A silent failure looks like "no phishing found".
  **Alternatives considered:** Console logging only.
  **Trade-off:** Banner noise when Gmail changes.
- **Decision:** The content script reads only storage settings to check `gmailAutoScan`; analysis requests go through the worker.
  **Why:** The token is never put into page-facing code paths.
  **Alternatives considered:** Ask the worker for flags.
  **Trade-off:** The content script could technically read the whole settings object.

## 6. Edge cases and limitations
- **Unverified against live Gmail** (see `extension/README.md`). To fix: inspect a message element for `data-message-id`, open "Show original" and compare its URL, then update `gmail-selectors.ts` and `tests/gmail-selectors.test.ts`.
- Only expanded messages are analyzed; collapsed ones are processed when expanded.
- Gmail may require the `ik` token; `findIk` scrapes inline scripts and returns null if absent (the request is then tried without it).
- Multiple signed-in accounts use the `/u/<n>/` slot from the URL.

## 7. How to test it
`npm test` covers URL building, id extraction and response parsing. The DOM integration is checked manually in Gmail.

## 8. Further reading
Chrome content scripts docs; MDN MutationObserver and Shadow DOM.
