# Extension (Chrome, Manifest V3)

## 1. Purpose
A popup where you drop a `.eml` file to see a verdict, reasons and technical details, plus a Gmail content script that automatically shows a red/yellow/green banner above an opened message. All analysis happens on your backend; the extension holds no API keys for third-party services.

## 2. Where it fits
```
popup / Gmail page --(chrome.runtime messages)--> background service worker --(HTTPS + X-API-Token)--> backend
```

## 3. Concepts you need to know
- **MV3 service worker**: the background script can be stopped at any time and has no DOM; state must live in `chrome.storage`.
- **Content script**: JavaScript injected into mail.google.com in an *isolated world* (it sees the page DOM but not the page's JS variables).
- **Host permissions**: which sites the extension may call; optional ones are requested at runtime.
- **Shadow DOM**: the banner is rendered in a closed shadow root so Gmail's CSS can't alter it and email content can't reach it.
- **Why no `innerHTML`**: subjects, URLs and filenames come from attacker-controlled email; the UI builds elements with `textContent` only.

## 4. File-by-file walkthrough
- `manifest.json`, `vite.config.ts` (two builds: ES modules for popup/options/background, IIFE for the content script), `popup.html`, `options.html`, `scripts/make-icons.mjs`.
- `src/` - see [`src/README.md`](src/README.md) and one README per subfolder.

### Permissions (minimum, each justified)
| Permission | Why |
|---|---|
| `storage` | Backend URL, API token, preferences (`chrome.storage.local`) and the per-message report cache (`chrome.storage.session`, wiped when the browser closes). |
| host `https://mail.google.com/*` | Content script injection and fetching "Show original" with the user's own session. |
| host `http://127.0.0.1/*`, `http://localhost/*` | Default local backend. |
| optional hosts `https://*/*`, `http://*/*` | Requested **only for the backend origin you type** in Options (`chrome.permissions.request`). |
No `tabs`, `activeTab`, `cookies`, `webRequest` or `<all_urls>`.

## 5. Design decisions and why
- **Decision:** All backend traffic goes through the background worker.
  **Why:** One place holds the token and handles errors/caching; page-injected scripts never see it.
  **Alternatives considered:** Fetching from the content script (CORS and token exposure).
  **Trade-off:** Requests are base64-wrapped for `runtime.sendMessage`.
- **Decision:** Vanilla TypeScript + DOM, Vite.
  **Why:** Small bundle (popup about 8 kB), nothing to audit beyond our code.
  **Alternatives considered:** React.
  **Trade-off:** Hand-written render helpers (`h()`).
- **Decision:** Auto-scan is a setting and nothing is sent until a token is configured.
  **Why:** Sending every opened email to a server must be an informed choice.
  **Alternatives considered:** On by default with no setup gate.
  **Trade-off:** One extra setup step.

## 6. Edge cases and limitations
- **Gmail selectors and the "Show original" URL could not be verified against a live Gmail account while building this.** They are isolated in `src/content/gmail-selectors.ts` with a repair procedure; if the banner shows an error, follow the checklist at the top of that file. The popup flow (download the message as `.eml` and drop it in) always works.
- Outlook web is out of scope for v1; planned via the Microsoft Graph API (`GET /me/messages/{id}/$value` returns MIME).
- Chrome only for now; Firefox needs a `browser_specific_settings` block and `browser.*` polyfill.
- The VirusTotal upload button is in the popup only (it needs the original `.eml` bytes).

## 7. How to test it
```
cd extension
npm install
npm test            # vitest: Gmail helper functions, base64, CSV safety
npm run build       # typecheck + build into dist/
```
Load it: `chrome://extensions` -> Developer mode -> **Load unpacked** -> choose `extension/dist`. Open the extension's Options, set the backend URL (`http://127.0.0.1:8000`) and an API token from `.env`, then drop a fixture such as `backend/tests/fixtures/03_lookalike_punycode.eml` on the popup. To allow only your extension in CORS, copy its ID from `chrome://extensions` into `CORS_ALLOWED_ORIGINS=chrome-extension://<id>`.

## 8. Further reading
Chrome Extensions MV3 docs (service workers, content scripts, `chrome.permissions`), MDN Shadow DOM.
