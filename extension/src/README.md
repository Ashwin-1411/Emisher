# extension/src

## 1. Purpose
All TypeScript source for the extension, split by execution context.

## 2. Where it fits
Built by Vite into `extension/dist`. Contexts: `background/` (service worker), `content/` (Gmail page), `popup/` and `options/` (extension pages), `shared/` (code used by several).

## 3. Concepts you need to know
Each context is a separate JavaScript environment; they communicate only through `chrome.runtime.sendMessage` (JSON). See `extension/README.md`.

## 4. File-by-file walkthrough
- `background/` - [README](background/README.md)
- `content/` - [README](content/README.md)
- `popup/` - [README](popup/README.md)
- `options/` - one file, `main.ts`: loads/saves settings, requests host permission for the backend origin only, "Test connection".
- `shared/` - [README](shared/README.md)

## 5. Design decisions and why
- **Decision:** The content script is bundled alone as an IIFE.
  **Why:** Classic content scripts cannot import shared chunks.
  **Alternatives considered:** A dynamic `import()` shim.
  **Trade-off:** Two Vite invocations (`npm run build` does both).

## 6. Edge cases and limitations
Types in `shared/types.ts` are hand-copied from the backend models.

## 7. How to test it
`npm test` in `extension/` (see `tests/gmail-selectors.test.ts`).

## 8. Further reading
Vite library mode docs; Chrome MV3 content scripts.
