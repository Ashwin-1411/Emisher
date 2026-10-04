# Backend

## 1. Purpose
A FastAPI service that accepts a raw email, runs the analysis pipeline and returns an explainable `Report`. It is the only component that holds API keys, caches enrichment results and enforces limits.

## 2. Where it fits
The Chrome extension's background worker calls it over HTTP. Internals are documented per package in [`app/`](app/README.md).

## 3. Concepts you need to know
See the READMEs in `app/auth_checks`, `app/hops`, `app/urls`, `app/attachments` and `docs/email-auth-primer.md` for the email-security background.

## 4. File-by-file walkthrough
- `pyproject.toml` - dependencies, `ruff`, `pytest`, `mypy` config. Python 3.11+.
- `Dockerfile` - python:3.12-slim + `libmagic1`, runs as a non-root user, health-checked.
- `app/` - the application. `tests/` - the suite.

## 5. Design decisions and why
- **Decision:** `pyspf`, `dkimpy`, `dnspython` rather than `checkdmarc`.
  **Why:** Mature, single-purpose libraries that fit a resolver we can stub in tests.
  **Alternatives considered:** `checkdmarc` (broad but does its own DNS and policy reporting).
  **Trade-off:** We implement DMARC lookup and alignment ourselves (about 60 lines, tested).
- **Decision:** SQLite cache behind an interface.
  **Why:** Zero ops; swap to Redis by adding a class.
  **Alternatives considered:** Redis now (extra container).
  **Trade-off:** Single-node only.
- **Decision:** `python-magic` is only a fallback to an internal signature table.
  **Why:** `libmagic` is unavailable on Windows by default.
  **Alternatives considered:** Hard dependency.
  **Trade-off:** See `app/attachments/README.md`.
- **Decision:** `confusable_homoglyphs` works on Python 3.14 here; if it breaks in future, `app/heuristics/lookalike.py` only needs a character-mapping source (e.g. the Unicode `confusables.txt`).
  **Why:** Library is small and unmaintained-but-stable.
  **Alternatives considered:** `homoglyphs` package.
  **Trade-off:** Watch for upstream changes.

## 6. Edge cases and limitations
- No sandbox detonation; reputation lookups only.
- Single process: rate limits and report store are in memory.
- The API token is a shared secret (see `app/api/README.md`).

## 7. How to test it
```
cd backend
python -m venv .venv && .venv/Scripts/activate      # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
python -m uvicorn app.main:app --reload             # needs a .env (copy ../.env.example)
```
Try it: `curl -X POST "http://127.0.0.1:8000/api/v1/analyze?enrich=false" -H "X-API-Token: <token>" -H "Content-Type: message/rfc822" --data-binary @tests/fixtures/07_double_extension.eml`

## 8. Further reading
FastAPI, Pydantic v2, httpx docs; RFC 5322, 7208, 6376, 7489.
