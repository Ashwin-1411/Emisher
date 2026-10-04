# options/

## 1. Purpose
The options page: backend URL, API token, and two switches (external lookups, Gmail auto-scan).

## 2. Where it fits
Opened from the popup ("Settings") or `chrome://extensions`. Writes `chrome.storage.local`, read by `background/` and `content/`.

## 3. Concepts you need to know
`optional_host_permissions` let an extension ask the user for access to one origin at runtime. Saving a backend URL triggers `chrome.permissions.request` for exactly that origin, so the extension never holds blanket network access.

## 4. File-by-file walkthrough
`main.ts`: loads settings into the form; `ensureHostPermission(url)`; save handler; "Test connection" sends `testConnection` to the worker (calls `/health`).

## 5. Design decisions and why
- **Decision:** Token field is a password input and stored in `storage.local` (not `sync`).
  **Why:** Keep the secret out of the user's synced Google profile.
  **Alternatives considered:** `storage.sync`.
  **Trade-off:** Re-enter the token on each browser profile.

## 6. Edge cases and limitations
Plain HTTP backends other than localhost are allowed but unencrypted; use HTTPS for remote deployments.

## 7. How to test it
Manual: open the options page, save, press "Test connection" with the backend running.

## 8. Further reading
Chrome `permissions` API docs.
