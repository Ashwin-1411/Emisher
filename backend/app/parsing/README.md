# parsing/

## 1. Purpose
Turns raw `.eml` bytes into a structured `ParsedEmail` (headers, identities, bodies, MIME tree, attachments). It never raises on bad input: every oddity becomes a string in `parse_warnings`.

## 2. Where it fits
Called first by `app/pipeline.py`. Everything else (hops, auth, urls, attachments, heuristics) consumes the `ParsedEmail` it returns. It calls only the stdlib `email` package and `app/netutil.py`.

```
raw bytes -> parsing -> ParsedEmail -> hops / auth_checks / urls / attachments / heuristics
```

## 3. Concepts you need to know
- **RFC 5322 message**: a block of `Name: value` headers, a blank line, then the body. Long headers are *folded* onto continuation lines that start with whitespace.
- **MIME (RFC 2045-2049)**: lets a message carry several parts. `Content-Type: multipart/mixed; boundary=X` means "parts follow, separated by `--X`". Parts nest: a typical mail is `multipart/mixed` -> (`multipart/alternative` -> text + html) + attachments.
- **Transfer encodings**: binary data is carried as `base64` or `quoted-printable` so it survives 7-bit mail systems.
- **RFC 2047 encoded words**: non-ASCII header text is written `=?utf-8?b?SsO8cmdlbg==?=` ("Jürgen"). Attackers use odd charsets to confuse filters, so we decode them before any comparison.
- **message/rfc822**: an entire email attached to another (a "forward as attachment"). Malware is often hidden one level down, so nested attachments are surfaced too.

```
Content-Type: multipart/mixed; boundary="b1"      <- the tree root
  text/plain                                       <- body
  application/pdf; name="invoice.pdf"              <- attachment
  message/rfc822                                   <- forwarded email (recursed into)
```

## 4. File-by-file walkthrough
- `parser.py`
  - `parse_email(raw)` - entry point. Parses with `policy.default`, then fills headers, identity fields and walks the MIME tree.
  - `_collect_headers` - iterates `msg.raw_items()` (which keeps repeated headers like `Received` separate and in wire order) and stores both the decoded `value` and the `raw` text.
  - `_collect_identity_fields` - From, Reply-To, Return-Path, Sender, To, Subject, Date, Message-ID. Domains are converted to punycode so later comparisons are consistent.
  - `_WalkState.walk` - recursive MIME traversal. Leaves of type `text/plain`/`text/html` with no filename and no `attachment` disposition become bodies; everything else becomes an `AttachmentData` (including inline images). `message/rfc822` is recorded as an attachment *and* recursed into with `nested_in` set; its text bodies are not mixed into the outer body.
- `__init__.py` - exports `parse_email`.

## 5. Design decisions and why
- **Decision:** Use the stdlib `email` package with `policy.default`.
  **Why:** It is the reference RFC 5322/2045 implementation in Python, handles RFC 2047 decoding, and is lenient with broken input.
  **Alternatives considered:** `mail-parser`, `flanker` (extra dependencies, flanker is unmaintained on modern Python).
  **Trade-off:** The API is verbose and some malformed headers behave unexpectedly, so each access is wrapped defensively.
- **Decision:** Record warnings instead of raising.
  **Why:** A hostile or sloppy email must still produce a report; malformed structure is itself a signal (`mime_malformed`).
  **Alternatives considered:** Reject unparsable mail with HTTP 400.
  **Trade-off:** Callers must tolerate partially filled models.
- **Decision:** Keep `raw` bytes on the model (excluded from serialisation).
  **Why:** DKIM verification needs the exact original bytes.
  **Alternatives considered:** Re-serialising the parsed message (breaks signatures).
  **Trade-off:** The model holds the whole message in memory for the request's lifetime.
- **Decision:** Parsing is sync but run via `asyncio.to_thread`.
  **Why:** It is CPU work on up to 25 MB; running it on the event loop would stall other requests.
  **Alternatives considered:** A process pool (overkill here).
  **Trade-off:** Thread overhead is small but non-zero.

## 6. Edge cases and limitations
- If a header block has a line without a colon, Python treats the rest as body; the MIME tree is then flat (see fixture `09_malformed.eml` for a different malformation that keeps structure).
- Multiple `From` headers: only the first is used (a warning is added).
- Bodies are decoded with `errors="replace"`, so undecodable bytes become `?`.
- Nesting deeper than 20 levels is cut off.
- Attachments inside encrypted/signed (S/MIME, PGP) envelopes are not opened.

## 7. How to test it
`backend/tests/test_parser.py`
```
cd backend && python -m pytest tests/test_parser.py -q
```

## 8. Further reading
RFC 5322 (message format), RFC 2045-2049 (MIME), RFC 2047 (encoded words), RFC 2183 (Content-Disposition), Python docs for `email.policy`.
