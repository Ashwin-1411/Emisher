# app/

## 1. Purpose
The backend application package: an analysis pipeline (one subpackage per stage) wrapped by a FastAPI app.

## 2. Where it fits
```
HTTP request -> api/ -> pipeline.py -> parsing -> hops -> auth_checks -> urls -> attachments
                                     -> heuristics -> enrichment (optional) -> scoring -> Report
```
Run with `uvicorn app.main:app` (or `docker compose up` from the repo root).

## 3. Concepts you need to know
- **Pipeline of pure-ish stages**: each stage takes models in and returns findings plus `Signal`s, so it can be tested alone.
- **Graceful degradation**: a failing stage adds a warning and the rest still run.
- **Dependency injection via `Services`**: DNS resolver, HTTP client, cache and clients are bundled in one dataclass so tests can replace them.

## 4. File-by-file walkthrough
- `main.py` - `create_app(settings, services)`; lifespan builds/closes services; strict CORS; `/health`.
- `config.py` - `Settings` (pydantic-settings); every env var is listed in `.env.example`.
- `pipeline.py` - `analyze_email(raw, services, enrich)`: runs the stages in order, wraps each in `_stage` (exceptions become `Report.warnings`), scores, builds the `Report`.
- `services.py` - `Services` and `build_services`.
- `ioc.py` - `build_iocs` and `iocs_to_csv` (formula-injection-safe).
- `netutil.py` - registered-domain extraction (bundled Public Suffix List, no downloads), IDNA helpers, public-IP test.
- Subpackages: `api/`, `parsing/`, `auth_checks/`, `hops/`, `urls/`, `attachments/`, `heuristics/`, `enrichment/`, `scoring/`, `cache/`, `models/`, each with a README.

**Deviation from the requested tree:** `pipeline.py`, `services.py`, `ioc.py` and `netutil.py` sit in `app/` because they are cross-cutting rather than belonging to one stage.

## 5. Design decisions and why
- **Decision:** Stages mutate a shared `signals` list via closures in `pipeline.py`.
  **Why:** Keeps each stage's own return type clean while collecting signals centrally.
  **Alternatives considered:** Returning `(result, signals)` tuples everywhere through a generic runner.
  **Trade-off:** Slightly implicit data flow; contained in one short file.
- **Decision:** Logging never includes bodies or full addresses; failures log only the exception type.
  **Why:** Privacy requirement.
  **Alternatives considered:** Verbose debug logs.
  **Trade-off:** Harder debugging; reproduce with the `.eml` and tests instead.
- **Decision:** `enrich=false` means no network at all (not even DNS).
  **Why:** One simple promise for privacy-sensitive users.
  **Alternatives considered:** Separate flags per source.
  **Trade-off:** Offline results rely on delivery-time authentication headers.

## 6. Edge cases and limitations
- Analysis of a 25 MB message with many attachments is CPU-bound in threads; there is no job queue.
- Settings are read once at startup.

## 7. How to test it
```
cd backend && python -m pytest -q          # full suite, no network or keys needed
python -m ruff check . && python -m ruff format --check .
```

## 8. Further reading
FastAPI "Bigger applications" and lifespan docs; pydantic-settings docs.
