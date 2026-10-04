# urls/

## 1. Purpose
Finds every link in an email, undoes known redirector wrappers, normalises and de-duplicates them, flags deceptive ones (text/target mismatch, IP hosts, `user@` tricks, shorteners) and produces defanged copies for safe sharing.

## 2. Where it fits
Called by `app/pipeline.py` after parsing. Its findings feed `heuristics/` (link lookalikes), `enrichment/` (which URLs to look up) and `ioc.py`. Only `expand.py` touches the network, and only when `enrich=true`.

## 3. Concepts you need to know
- **Display text vs target.** In HTML, `<a href="http://evil.example/x">https://paypal.com</a>` shows one address and goes to another. The visible text is what users trust.
- **Redirectors and wrappers.** Security gateways rewrite links so clicks pass through them. Outlook SafeLinks: `https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2F&data=...`. The real destination is in the `url` parameter. Unwrapping means *decoding that parameter*; we never visit the link. Attackers also abuse legitimate redirectors (Google `/url?q=`) to borrow reputation.
- **Shorteners** (`bit.ly`) hide the destination; expansion needs a network request.
- **Userinfo trick**: `https://paypal.com@evil.example/` - everything before `@` is a username; the host is `evil.example`.
- **Defanging**: `hxxps://evil[.]example` cannot be clicked or auto-linked by a ticketing system or chat app.
- **Registered domain (eTLD+1)**: `login.evil.co.uk` -> `evil.co.uk`, computed from the Public Suffix List.

## 4. File-by-file walkthrough
- `extract.py` - `extract_raw_links(email)`: `HTMLParser` collects `<a href>` with its visible text (plus `<area>`, `<form action>`), a regex collects URLs from plain text, and text attachments / filenames are scanned too.
- `normalize.py` - `normalize_url` (lower-case host, IDNA/punycode, default ports and fragment removed, userinfo kept), `unwrap` (up to 5 nested layers using `data/redirectors.json` plus Proofpoint v2/v3 decoders), `defang`.
- `analyze.py` - `analyze_urls(links, expansions)`: normalises, unwraps, applies shortener expansions, judges text mismatch *after* unwrapping (so a SafeLinks-wrapped lie is still caught), merges duplicates and emits signals.
- `expand.py` - `expand_shorteners`: HEAD requests, no automatic redirects, max 5, short timeout.
- `data/redirectors.json`, `data/shorteners.json` - editable lists.

## 5. Design decisions and why
- **Decision:** Only contact hosts in `shorteners.json`, and follow a `Location` only if it is another shortener.
  **Why:** Fetching attacker-chosen URLs from our server is an SSRF vector and could trigger one-time links or tracking.
  **Alternatives considered:** Follow redirects to the end (accurate but unsafe).
  **Trade-off:** We report the first non-shortener destination without verifying it.
- **Decision:** Mismatch compares registered domains and only fires when the link text *contains* a domain with a real public suffix.
  **Why:** Avoids false hits on prose like "Terms.Conditions" and on subdomain differences.
  **Alternatives considered:** Exact-host comparison (noisy).
  **Trade-off:** Same-organisation spoofing (`paypal.com` text to `paypal.com.evil.net`) is caught, but text mentioning only a brand name (no TLD) is not.
- **Decision:** Keep link-wrapper rules in JSON.
  **Why:** New wrappers appear often; data changes don't need code review.
  **Alternatives considered:** Hard-coded dict.
  **Trade-off:** Regexes in JSON need escaping care.
- **Decision:** Pure functions plus one small async function.
  **Why:** Extraction and analysis are easy to unit-test; only expansion needs `await`.
  **Alternatives considered:** Everything async.
  **Trade-off:** Pipeline coordinates the two.

## 6. Edge cases and limitations
- JavaScript-built links, QR codes in images, and links inside images/PDF attachments are not extracted.
- Proofpoint v3 uses placeholder characters that are not fully reversed.
- Only `http(s)` URLs are analysed (`mailto:`, `tel:`, `javascript:` are ignored).
- Tracking redirectors that need a server round-trip cannot be unwrapped offline.

## 7. How to test it
`backend/tests/test_urls.py`
```
cd backend && python -m pytest tests/test_urls.py -q
```

## 8. Further reading
RFC 3986 (URI syntax), RFC 3492 (Punycode), UTS #46 (IDNA), Microsoft docs on Safe Links, Public Suffix List (publicsuffix.org).
