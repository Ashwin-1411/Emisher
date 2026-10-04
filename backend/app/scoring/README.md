# scoring/

## 1. Purpose
Converts the signals emitted by every analysis module into a 0-100 risk score, a verdict (`SAFE`, `SUSPICIOUS`, `PHISHING`), plain-English reasons and the full list of fired rules. All weights and wording live in `rules.yaml`.

## 2. Where it fits
Last analysis step in `app/pipeline.py`. Input: `list[Signal]` from parsing/hops/auth/urls/attachments/heuristics/enrichment. Output: a `ScoringResult` copied into the `Report`.

## 3. Concepts you need to know
- **Rule-based vs ML**: a rule engine is transparent - every point in the score maps to a named rule an analyst can read, argue with and tune. That matters more here than raw accuracy.
- **Signal vs rule**: modules only *observe* (emit `Signal(rule_id, detail, context)`). The rule decides how much it is worth and how to explain it.
- **Hard overrides**: some evidence is decisive no matter what else is true (a hash VirusTotal knows as malware).
- **Thresholds**: the score maps to a verdict at configurable cut-offs (defaults: 25 = suspicious, 60 = phishing).
- **Correlated rules**: several rules can describe one underlying fact (DMARC fail, SPF misaligned, Return-Path mismatch), so weights are chosen with that overlap in mind.

## 4. File-by-file walkthrough
- `rules.yaml` - `thresholds`, `rules` (`id, category, weight, description, explanation`) and `overrides` (`requires_all`, `verdict`, `explanation`). `explanation` is a Python format string filled from the signal's `context`; missing keys render as "unknown".
- `engine.py`
  - `load_rules(path, suspicious, phishing)` - validates ids, override references, applies env threshold overrides (cached).
  - `evaluate(signals, ruleset)` - groups signals by rule, each rule counts **once** (details and a count are kept), sums weights capped at 100, picks the verdict, applies overrides (an override can only raise the verdict; the score is raised to the threshold to stay consistent), sorts reasons by weight (top 5).
- Full rule table with rationale: `docs/scoring-rules.md`.

## 5. Design decisions and why
- **Decision:** Each rule contributes once.
  **Why:** Ten bad links aren't ten times worse than one, and a bounded score is easier to explain.
  **Alternatives considered:** Per-occurrence or diminishing-returns weights.
  **Trade-off:** The count is shown in details but not scored.
- **Decision:** Weights in YAML, detection in code.
  **Why:** Tune without redeploying code; reviewers can audit the whole policy in one file.
  **Alternatives considered:** Weights as constants beside detectors.
  **Trade-off:** A rule id typo is a silent no-op, so unknown signal ids are logged and `test_scoring.py` checks the file.
- **Decision:** Overrides are generic (`requires_all`).
  **Why:** Both required overrides fit one mechanism; new ones are data.
  **Alternatives considered:** Special-case code.
  **Trade-off:** Only AND-conditions are expressible.
- **Decision:** Weak signals (wording) are low weight and can never reach SUSPICIOUS alone (6 + 8 = 14 < 25).
  **Why:** Legit mail uses the same words.
  **Alternatives considered:** Heavier text rules.
  **Trade-off:** Pure social-engineering text with no technical tells scores low.

## 6. Edge cases and limitations
- Weights are hand-set judgement calibrated on ten synthetic fixtures, not trained on real data; expect to tune.
- A clean score is **not** proof of safety (compromised legitimate accounts pass all checks).
- `SAFE` with warnings (for example failed stages) means "no findings from the stages that ran".

## 7. How to test it
`backend/tests/test_scoring.py` and `test_fixtures_expected.py` (every fixture's verdict)
```
cd backend && python -m pytest tests/test_scoring.py tests/test_fixtures_expected.py -q
```

## 8. Further reading
NIST SP 800-61 (incident handling), "SpamAssassin scoring" (a long-lived rule-and-weight system), MITRE ATT&CK T1566 (Phishing).
