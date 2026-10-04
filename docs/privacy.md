# Privacy

## Principles

1. Email content is processed in memory and never persisted by the backend.
2. Only what is needed leaves the machine, and only when `enrich=true`.
3. Anything that shares file content with a third party needs a separate, explicit consent.

## Data-flow table

| Data | Leaves your browser? | Goes to | When | Stored? |
|---|---|---|---|---|
| Raw email (headers, bodies, attachments) | Yes | **Your own backend** only | Popup analysis; Gmail auto-scan if enabled | Not stored; RAM during the request |
| Report (verdict, reasons, URLs, hashes, headers summary) | No (comes back) | - | - | Backend RAM for 15 min; extension `storage.session` for Gmail messages (cleared on browser close) |
| Link URLs | Yes (from backend) | VirusTotal (lookup), urlscan.io (live scan, visits the URL) | `enrich=true` and key configured | Cache keyed by `sha256(url)`; URL text not stored |
| Attachment SHA-256 | Yes (from backend) | VirusTotal | `enrich=true` and key configured | Cache keyed by hash |
| Domain names (sender, link) | Yes (from backend) | `rdap.org` and the TLD registry | `enrich=true` | Cache by domain |
| Sender/link domains, DKIM selectors, connecting IP | Yes (from backend) | DNS resolvers (SPF/DKIM/DMARC) | `enrich=true` and `LIVE_AUTH_CHECKS=true` | No |
| Hop IPs | Yes (from backend) | DNS (Team Cymru) | only if `HOP_ASN_LOOKUP_ENABLED=true` | No |
| **Attachment file bytes** | Yes | **VirusTotal** | **Only after you click Submit and confirm** | VirusTotal keeps it and shares with partners |
| API token, backend URL | No | stored in `chrome.storage.local` | - | Until you clear it |

Known-brand domains are never sent to RDAP.

## Consent model

- **Default is hash-only.** Files are never uploaded automatically.
- **Upload requires an in-popup confirmation** that names the file and warns that VirusTotal and its partners can see it, plus `consent=true` in the request. The backend refuses without it (HTTP 403) and checks the attachment's SHA-256 matches the path.
- **Gmail auto-scan is a setting.** Nothing is sent from Gmail until a backend token is configured; unchecking the option stops all reading of messages.
- **urlscan visibility** defaults to `unlisted` (not in the public feed). The URL still reaches urlscan.io and the site is visited from their servers. If a link contains a personal token (unsubscribe, magic-login), scanning could trigger it; disable by leaving `URLSCAN_API_KEY` empty or using `enrich=false`.

## Why the upload re-sends the email

The backend does not keep attachment bytes after `/analyze`. To upload, the client sends the `.eml` again with `consent=true`. This keeps the server stateless and ties the upload to a request the user explicitly confirmed.

## Logging

INFO logs contain no bodies and no full addresses; stage failures log only the exception class.

## What is not protected

- The API token is a shared secret in extension storage, not user authentication. Production would add per-user auth (OIDC), short-lived tokens, mTLS/signed requests and per-user quotas, and would terminate TLS (use HTTPS when the backend is not on localhost).
- Anyone operating the backend can see the emails you send it. Run it yourself, or trust the operator.
- Third parties set their own retention for URLs/files they receive.
