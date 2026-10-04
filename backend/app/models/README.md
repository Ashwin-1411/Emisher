# models/

## 1. Purpose
The shared vocabulary of the backend: Pydantic models for a parsed email (`email.py`) and for findings and the final `Report` (`report.py`). The extension's `src/shared/types.ts` mirrors the `Report`.

## 2. Where it fits
Imported by every module. `parsing/` produces `ParsedEmail`; analysis modules consume it and produce findings and `Signal`s; `pipeline.py` assembles a `Report`; `api/` returns it as JSON.

## 3. Concepts you need to know
- **Pydantic v2** validates and serialises data classes; `Field(exclude=True)` keeps a field out of JSON.
- **Signal**: an observation (`rule_id`, `detail`, `context`) - the only thing analysis modules hand to scoring.
- **IOC (indicator of compromise)**: an artefact (domain, URL, IP, hash) that identifies malicious activity and can be blocked or hunted for.
- **Defanging**: rewriting indicators (`hxxp://evil[.]com`) so they can't be clicked.

## 4. File-by-file walkthrough
- `email.py` - `Header`, `Address`, `MimeNode`, `AttachmentData` (bytes excluded from JSON), `ParsedEmail` (`get_headers(name)` returns all values in wire order).
- `report.py` - verdict enum; `Signal`; auth models (`AuthMethodResult`, `DeliveryAuth`, `Alignment`, `LiveAuth`, `AuthReport`); `Hop`/`HopReport`; `UrlFinding`; `AttachmentFinding`/`MacroInfo`; heuristics, enrichment (`VtResult`, `UrlscanResult`, `EnrichmentReport`); `Reason`, `FiredRule`, `IOC`, `EmailSummary`; `Report`.
- `__init__.py` - re-exports.

## 5. Design decisions and why
- **Decision:** Models describe *derived* data; the `Report` has no bodies or attachment bytes.
  **Why:** Privacy - the report can be kept in memory and returned without leaking content.
  **Alternatives considered:** Include body excerpts for context.
  **Trade-off:** Analysts must keep the original `.eml` for body review.
- **Decision:** One flat models package.
  **Why:** Avoids circular imports between analysis modules.
  **Alternatives considered:** Per-module models.
  **Trade-off:** A single file grows; sections are commented.
- **Decision:** `StrEnum` verdicts and string flags.
  **Why:** Serialises cleanly and is easy to mirror in TypeScript.
  **Alternatives considered:** Enum flags.
  **Trade-off:** Typos in flag strings are not type-checked.

## 6. Edge cases and limitations
- The TypeScript mirror is maintained by hand; changing a model requires editing `extension/src/shared/types.ts`.
- `ParsedEmail.raw` is kept in memory only for DKIM and is excluded from serialisation.

## 7. How to test it
Indirectly through every test; `backend/tests/test_api.py` asserts the JSON shape (no `data` field leaks).
```
cd backend && python -m pytest -q
```

## 8. Further reading
Pydantic v2 docs; STIX 2.1 (a standard format for sharing indicators).
