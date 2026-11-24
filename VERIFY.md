# Verification guide

Follow these steps in order. Each has a **pass** condition. Stop at the first failure and use the troubleshooting notes at the end.

Paths assume you are in the repo root (`phishing-email-analyzer/`).

## 0. One-time setup

```
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
Put the printed value in `.env` as `API_TOKENS=<value>`. Keep it; you enter it in the extension later.

Start the backend:
```
docker compose up --build
```
(No Docker? `cd backend`, create a venv, `pip install -e ".[dev]"`, then `python -m uvicorn app.main:app`.)

**Pass:** `curl http://127.0.0.1:8000/health` prints `{"status":"ok"}`.

## 1. Automated tests (2 min)

```
cd backend && python -m pytest -q          # expect: 143 passed
cd ../extension && npm install && npm test # expect: 7 passed
```

## 2. Backend alone, with curl

```
curl -X POST "http://127.0.0.1:8000/api/v1/analyze?enrich=false" \
  -H "X-API-Token: <your token>" -H "Content-Type: message/rfc822" \
  --data-binary @backend/tests/fixtures/03_lookalike_punycode.eml
```
**Pass:** JSON with `"verdict":"PHISHING"` and reasons mentioning a lookalike of paypal. A wrong token must give HTTP 401.

Expected verdicts for all fixtures are in `backend/tests/fixtures/expected.json`.

## 3. Load the extension in Chrome

```
cd extension && npm run build
```
1. Open `chrome://extensions`, turn on **Developer mode**.
2. **Load unpacked** and select `extension/dist`.
3. Pin the extension. Click it, then **Settings**.
4. Backend URL `http://127.0.0.1:8000`, paste your token, tick both boxes if you want, **Save** (accept the permission prompt if one appears), then **Test connection**.

**Pass:** the message says "Backend reachable".

## 4. Popup end-to-end

Drag these onto the popup and compare:

| File (`backend/tests/fixtures/`) | Expected |
|---|---|
| `01_legit.eml` | green "Looks safe", no reasons |
| `02_display_name_spoof.eml` | yellow, "PayPal Support" reason |
| `03_lookalike_punycode.eml` | red, lookalike of paypal |
| `04_dmarc_alignment_fail.eml` | yellow, DMARC failed |
| `07_double_extension.eml` | red, disguised program attachment |
| `08_macro_doc.eml` | yellow, macro runs automatically |

Also check: open **Technical details** and click each tab (Authentication, Hops, URLs, Attachments, IOCs); **Export JSON/CSV** downloads a file; URLs appear defanged (`hxxp://...[.]...`).

**Pass:** verdict colours and reasons match the table and no tab is blank or throws.

If nothing happens, right-click the popup, choose **Inspect**, and read the Console. For background errors, open `chrome://extensions`, click **service worker** on the extension card.

## 5. Strict CORS (optional)

Copy the extension ID from `chrome://extensions`, set `CORS_ALLOWED_ORIGINS=chrome-extension://<id>` in `.env`, restart the backend, repeat step 4.

**Pass:** it still works.

## 6. Real API keys

Add `VT_API_KEY` and `URLSCAN_API_KEY` to `.env`, restart the backend, then analyze with **external lookups** ticked in Settings (or curl without `enrich=false`).

1. Drop `05_link_text_mismatch.eml` or `06_safelinks.eml`.
2. Open **URLs** tab. **Pass:** the "Sources" line shows `virustotal: ok`, `urlscan: ok` (or `partial: ... still running`), `rdap: ok`; a urlscan result link or screenshot appears.
3. Hash check: the **Attachments** tab for `07_double_extension.eml` shows a VirusTotal line ("unknown hash" is normal for these stubs).
4. Known-malicious path with the harmless EICAR test string (do not save it in the repo; antivirus will quarantine it). Create it in a scratch folder:
   ```
   python - <<'EOF'
   from email.message import EmailMessage
   m = EmailMessage(); m["From"]="a@example.net"; m["To"]="b@example.org"; m["Subject"]="t"; m.set_content("x")
   e = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
   m.add_attachment(e, maintype="application", subtype="octet-stream", filename="eicar.com")
   open("eicar-test.eml","wb").write(m.as_bytes())
   EOF
   ```
   Drop `eicar-test.eml`. **Pass:** red verdict, reason "matches known malware" (VirusTotal must know the hash, which it does for EICAR). Windows Defender may still flag the `.eml`; allow it for the test or delete it afterwards.
5. Consent upload: on that attachment click **Submit to VirusTotal...**, confirm. **Pass:** a "View on VirusTotal" link. Cancel must upload nothing.
6. Without keys the Sources line must say `skipped: no API key configured` and the verdict must still appear.

## 7. Gmail banner

1. Backend running, extension configured, **Automatically analyze emails I open in Gmail** ticked.
2. Open `https://mail.google.com`, reload the tab, open any email.
3. **Pass:** a coloured banner appears above the message body (briefly "Analyzing this message...").

If you instead see "Phishing Email Analyzer could not check this message", Gmail's internals differ from what the code assumes. Fix them:
1. Right-click the message area, **Inspect**. Find the element wrapping the message and check it has a `data-message-id` attribute (or `data-legacy-message-id`), and that the body wrapper matches `div.ii.gt`. Update `SELECTORS`/`ATTRS` in `extension/src/content/gmail-selectors.ts` if not.
2. In Gmail, message menu (three dots) > **Show original**. Compare the new tab's URL with `buildOriginalUrl()` (`?ik=...&view=om&permmsgid=msg-f:<id>`). Update that function if the parameters differ.
3. In the Gmail tab's DevTools Network panel, filter on `view=om` while opening a message and see the status code the extension's request gets (403/404 means a URL/`ik` problem).
4. Edit `tests/gmail-selectors.test.ts` to match, then `npm test && npm run build`, and click the reload icon on the extension in `chrome://extensions`.

Fallback that always works: Gmail three dots > **Download message**, drop the `.eml` in the popup.

## 8. Demo GIF (optional)

Record the popup flow from step 4 (any screen recorder, e.g. ScreenToGif), save as `docs/demo.gif`, and add `![demo](docs/demo.gif)` to `README.md`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Could not reach the backend" | Backend not running, wrong URL, or host permission not granted (re-save in Settings). |
| 401 "Missing or invalid X-API-Token" | Token in Settings differs from `API_TOKENS` in `.env`; restart backend after editing `.env`. |
| 503 "no API_TOKENS configured" | `API_TOKENS` empty in `.env`. |
| 429 | Rate limit (`RATE_LIMIT_PER_MINUTE`, default 30) or VirusTotal free-tier limit; wait a minute. |
| CORS error in console after step 5 | Wrong extension ID in `CORS_ALLOWED_ORIGINS` (the ID changes if you reload from a different folder). |
| Popup blank after code changes | `npm run build`, then reload the extension in `chrome://extensions`. |
| Docker build fails | Check `docker info` works; or use the venv route in step 0. |
