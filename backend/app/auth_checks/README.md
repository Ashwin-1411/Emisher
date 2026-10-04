# auth_checks/

## 1. Purpose
Decides whether the email really came from the domain it claims, using SPF, DKIM and DMARC. It reads the result the receiving provider stamped at delivery (primary signal) and optionally re-runs the checks against live DNS (secondary signal), then computes DMARC alignment.

## 2. Where it fits
Called by `app/pipeline.py` after `hops/` (it needs the receiving host and the connecting IP). Uses `ParsedEmail` and `HopReport`; calls DNS only through the `DnsResolver` interface in `resolver.py`. Emits signals such as `dmarc_fail` for `scoring/`.

## 3. Concepts you need to know
**SPF (RFC 7208)** - the domain owner publishes which IPs may send mail for it. The receiver compares the *connecting IP* with the policy of the **envelope sender** (`MAIL FROM`, which ends up in `Return-Path`).
```
example.com.  TXT  "v=spf1 ip4:93.184.216.34 include:_spf.google.com -all"
```
`-all` = fail anything else, `~all` = softfail.

**DKIM (RFC 6376)** - the sending server signs selected headers and the body with a private key. The public key sits in DNS at `<selector>._domainkey.<domain>`.
```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=from:to:subject:date; bh=...; b=...
```
`d=` is the signing domain, `s=` the selector. If the body or a signed header changes, verification fails.

**DMARC (RFC 7489)** - a policy at `_dmarc.<domain>` saying what to do when authentication fails, *and* requiring **alignment**:
```
_dmarc.example.com. TXT "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:..."
```
SPF and DKIM can pass for *any* domain, e.g. the attacker's own. DMARC passes only if SPF or DKIM passed **for a domain aligned with the visible From domain**:
- *relaxed*: same organisational domain (`mail.example.com` aligns with `example.com`)
- *strict*: identical domains

Example of the failure this project's fixture `04` demonstrates: SPF passes for `spammer-bulk.net` (the envelope domain) but the From header says `example.com` -> not aligned -> DMARC fails.

**Authentication-Results (RFC 8601)** - the header a receiving provider adds with its verdicts:
```
Authentication-Results: mx.google.com; dkim=pass header.d=example.com;
  spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com
```
Anyone can *write* such a header into a message, so only the one added by the server that accepted the mail is trustworthy.

## 4. File-by-file walkthrough
- `results_parser.py` - `parse_authentication_results(value)` splits on `;` outside parentheses/quotes, strips `(comments)`, and returns `(authserv_id, [AuthMethodResult])`.
- `checker.py`
  - `parse_delivery_auth` - picks the header whose authserv-id belongs to the same organisational domain as the topmost `Received` hop's `by` host. If none match the data is shown but marked untrusted and **not scored**.
  - `_delivery_alignment` - alignment from delivery-time results (works offline).
  - `check_auth` - entry point: delivery parse, then (if a resolver was passed) live checks, disagreement notes, plain-English `explanation`, and signals.
- `live.py`
  - `run_live_checks` - SPF via `pyspf` for the Return-Path from `hops.connecting_ip`; every DKIM signature via `dkimpy`; DMARC record lookup (From domain, then organisational domain) and our own DMARC evaluation honouring `adkim`/`aspf`.
  - `spf.DNSLookup` is replaced once by a dispatcher that reads the resolver from a `ContextVar`, so concurrent requests cannot see each other's DNS.
- `alignment.py` - `compute_alignment(from_domain, auth_domain)` returns strict and relaxed booleans using the Public Suffix List (`co.uk` is not an organisation).
- `resolver.py` - `DnsResolver` protocol, `SystemResolver` (dnspython), `DnsTemporaryError`.

## 5. Design decisions and why
- **Decision:** Trust Authentication-Results only if its authserv-id matches the receiving host.
  **Why:** Otherwise a phisher can ship `dmarc=pass` in their own message.
  **Alternatives considered:** Trust the topmost header unconditionally (breaks when a gateway adds its own).
  **Trade-off:** Unusual internal naming can make a genuine header look untrusted; the analyst still sees it, flagged.
- **Decision:** Live checks are a separate, labelled secondary signal.
  **Why:** DNS and DKIM keys change after delivery, so a mismatch is informative, not conclusive.
  **Alternatives considered:** Replace the delivery result with the live one.
  **Trade-off:** Two sources to explain to users; disagreements get their own note.
- **Decision:** `pyspf` + `dkimpy` run in threads (`asyncio.to_thread`).
  **Why:** Both are synchronous libraries.
  **Alternatives considered:** `checkdmarc` (heavier, does its own DNS), rewriting SPF (error-prone).
  **Trade-off:** One thread per check; fine at this scale.
- **Decision:** Resolver interface with a static test implementation.
  **Why:** Tests run offline, including a real DKIM signature verification (fixture `01` is signed with a throw-away key).
  **Alternatives considered:** Mocking `dns.resolver` globally.
  **Trade-off:** One extra abstraction.
- **Decision:** `enrich=false` skips live checks.
  **Why:** `enrich=false` means "no external lookups"; DNS is one.
  **Alternatives considered:** Always run DNS.
  **Trade-off:** Offline mode relies on the delivery-time header alone.

## 6. Edge cases and limitations
- No `Received` headers -> receiving host unknown -> Authentication-Results cannot be trusted.
- The connecting IP is the topmost *public* hop; behind unusual gateways/NAT it can be an intermediary and SPF may legitimately fail.
- SPF is evaluated for Return-Path, falling back to `postmaster@HELO`; the real SMTP envelope is not available from a saved `.eml`.
- `Received-SPF`, ARC (`ARC-Authentication-Results`) and BIMI are not interpreted.
- Only DMARC's `p`, `adkim`, `aspf` are used (`pct`, `sp`, reporting tags are ignored).
- DKIM `l=` body-length tricks and weak keys are not specially flagged.

## 7. How to test it
`backend/tests/test_auth.py`
```
cd backend && python -m pytest tests/test_auth.py -q
```

## 8. Further reading
RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8601 (Authentication-Results), RFC 8617 (ARC), dmarc.org overview.
