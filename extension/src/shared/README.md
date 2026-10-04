# shared/

## 1. Purpose
Code used by more than one extension context: report types, the backend API client, storage helpers, message passing and DOM helpers.

## 2. Where it fits
Imported by `background/`, `popup/`, `options/` and `content/`.

## 3. Concepts you need to know
`chrome.runtime.sendMessage` serialises to JSON, so binary data is passed as base64.

## 4. File-by-file walkthrough
- `types.ts` - TypeScript mirror of the backend `Report`, plus `Settings` and the message types.
- `api.ts` - `analyze`, `submitAttachment`, `testConnection`, base64 helpers, timeouts (90 s for analyze) and friendly errors.
- `storage.ts` - `loadSettings/saveSettings` (`chrome.storage.local`).
- `messaging.ts` - `send<T>()` unwraps the `{ok, data|error}` envelope.
- `dom.ts` - `h()` element builder, verdict labels, safe CSV/download helpers.

## 5. Design decisions and why
- **Decision:** Hand-maintained types.
  **Why:** A handful of interfaces do not justify a code generator.
  **Alternatives considered:** Generating from the backend OpenAPI schema.
  **Trade-off:** Drift risk; the TypeScript compiler and a manual check at release catch most of it.

## 6. Edge cases and limitations
`api.ts` is the only code that knows the REST paths.

## 7. How to test it
`npm test` (base64 round-trip, CSV safety).

## 8. Further reading
MDN Fetch and AbortController.
