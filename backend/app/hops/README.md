# hops/

## 1. Purpose
Reconstructs the path an email took by parsing every `Received:` header, orders it in time, and flags hops that look wrong. It also identifies the IP address that actually delivered the message.

## 2. Where it fits
Runs right after `parsing/` and before `auth_checks/` (which needs `receiving_host` and `connecting_ip`). Output goes to the report's Hops tab and `scoring/` (signals) and `ioc.py` (IPs).

## 3. Concepts you need to know
Every server that handles a message **prepends** a `Received:` header. So they are read **bottom-up**: the bottom one is the oldest hop (closest to the sender), the top one was written by the server that finally accepted the mail.

```
Received: from mail.example.com (mail.example.com [93.184.216.34])    <- top: newest, written by us
        by mx.example.org with ESMTPS id abc; Tue, 05 Mar 2024 10:00:05 +0000
Received: from app01.internal (app01 [10.0.0.5])                       <- bottom: oldest
        by mail.example.com with ESMTP; Tue, 05 Mar 2024 10:00:03 +0000
```
Within one hop: `from <HELO name> (<reverse-DNS name> [<IP the receiver saw>])`, `by <receiver>`, `with <protocol>`, then `; <timestamp>`.

**Why they can be forged:** a sender can pre-load a message with fake `Received` headers before sending it. Each later server just adds on top. Only the headers written by servers *you* trust (the top ones) are reliable; everything below is a claim made by someone else. This module therefore marks hops as `trusted` (newest N, default 1) and applies "forged" heuristics only to the untrusted ones.

## 4. File-by-file walkthrough
- `tracer.py`
  - `parse_received(raw)` - regex extraction of from-host, IP (from `[...]` or a bare address), by-host, `with` protocol and timestamp; hops missing the essentials get a `malformed` flag.
  - `trace_hops(email, trusted_hops=1)` - reverses the header list to chronological order, marks trust, calls `_flag_timing` (delay, `large_delay` > 1 h, `timestamp_out_of_order` beyond 5 min of clock skew) and `_flag_ips_and_chain` (`private_ip_after_public`, informational `chain_break`), adds `likely_forged` to suspect untrusted hops, picks IPs, and returns signals.
- **Connecting IP**: newest hop with a *public* IP - what our provider saw. **Originating IP**: oldest public IP; reported but labelled "unverified claim" when its hop is untrusted.

## 5. Design decisions and why
- **Decision:** Trust boundary = newest 1 hop by default.
  **Why:** Only the top `Received` is certainly written by the system that handed us the message.
  **Alternatives considered:** Matching hop hosts against a provider list (maintenance burden).
  **Trade-off:** Legit second-hop headers from the same provider are shown as "untrusted" - harmless because only anomalies are scored.
- **Decision:** A private IP is only flagged if it appears *after* a public one.
  **Why:** Private addresses at the very start (office LAN, client) are normal.
  **Alternatives considered:** Flag every private IP (floods legit mail).
  **Trade-off:** A forged private-first chain isn't caught by this rule.
- **Decision:** Public-IP test uses `ipaddress.is_global`.
  **Why:** It also excludes documentation, CGNAT, link-local and reserved ranges.
  **Alternatives considered:** `not is_private` (misses some reserved space).
  **Trade-off:** Test fixtures must use real public-looking addresses.
- **Decision:** Pure synchronous function.
  **Why:** No I/O; the optional ASN lookup lives in `enrichment/asn.py`.
  **Alternatives considered:** Doing geo lookups here.
  **Trade-off:** ASN/country are filled in by a later step.

## 6. Edge cases and limitations
- Received formats vary widely (qmail, Exchange, webmail internal hops); parsing is best-effort and unmatched headers are flagged `malformed`.
- Time zones are taken from the header; a missing/invalid zone is assumed UTC.
- An attacker who controls the *final* hop's provider could still forge everything; this is a heuristic, not proof.
- `chain_break` (a hop's from-host differs from the previous by-host) is informational because relays commonly rename themselves.

## 7. How to test it
`backend/tests/test_hops.py` (fixture `10_forged_received.eml` shows an impossible timestamp ordering)
```
cd backend && python -m pytest tests/test_hops.py -q
```

## 8. Further reading
RFC 5321 section 4.4 (trace information), RFC 5322 section 3.6.7, Team Cymru IP-to-ASN mapping docs.
