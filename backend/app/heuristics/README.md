# heuristics/

## 1. Purpose
Rules of thumb that catch identity deception: display-name spoofing, Reply-To/Return-Path mismatches, lookalike domains (punycode, homoglyphs, typosquats), young domains, and weak phishing wording.

## 2. Where it fits
Called by `app/pipeline.py` after `urls/` (it needs link domains). `domain_age.py` is fed by `enrichment/rdap.py`. Output: signals for `scoring/` and the Heuristics part of the report.

## 3. Concepts you need to know
- **Display-name spoofing**: the `From` header has a friendly name and an address. Mail clients often show only the name: `"PayPal Support" <x@random.xyz>`.
- **Homoglyphs / IDN**: Unicode contains characters that look identical to Latin ones (Cyrillic "а" U+0430 vs "a"). International domain names are stored as **punycode** (`xn--pypal-4ve.com`). Mixed-script labels are a red flag.
- **Typosquatting**: `paypall.com`, `rnicrosoft.com` ("rn" looks like "m"), `paypa1.com`.
- **Edit distance**: the minimum single-character changes to turn one string into another.
- **Domain age**: phishing infrastructure is usually registered days before use; RDAP (the JSON successor of WHOIS) exposes the registration date.
- **Why wording is weak**: genuine banks also write "verify your account". These rules are low-weight nudges only.

## 4. File-by-file walkthrough
- `lookalike.py` - `skeleton(label)` folds Unicode confusables to ASCII (via `confusable_homoglyphs`), drops hyphens, maps `0/1/3/5` and `rn/vv/cl`. `check_domain(domain)` compares the skeleton with each brand: equal -> `homoglyph`/`character_swap`/`hyphenation`/`brand_tld_swap`; Levenshtein within 1-2 -> `typosquat`; brand inside a label -> `brand_keyword`. Domains that *are* the brand are skipped. Brands live in `data/brands.json`.
- `sender.py` - `check_display_name` (brand in the name but sender off-brand; address/domain in the name that differs from the real sender) and `check_header_mismatch` (Reply-To, Return-Path vs From, compared at organisational-domain level).
- `language.py` - phrase lists in `data/phrases.json`; HTML is stripped to text first.
- `domain_age.py` - `domain_age_signals` flags sender/link domains younger than 30 days.
- `analyze.py` - `analyze_heuristics(email, urls)` runs the offline ones.

## 5. Design decisions and why
- **Decision:** Skeleton comparison plus edit distance, brand data in JSON.
  **Why:** One mechanism covers many tricks; brand coverage can grow without code changes.
  **Alternatives considered:** Hard-coded regexes per brand; ML model.
  **Trade-off:** Common words that are also brands (`chase`, `apple`) cause occasional false positives, which is why strong kinds need a *near-exact* match.
- **Decision:** Brand names shorter than 5 letters are exact-skeleton only (no fuzzy match), and 4-letter-or-less names need whole-word match in display names.
  **Why:** `ups` appears in "Groups"; fuzzy matching short names is noise.
  **Alternatives considered:** Global distance threshold.
  **Trade-off:** Typosquats of very short brands are missed.
- **Decision:** `brand_keyword` is a weaker rule than `lookalike_domain`, and is not applied to links.
  **Why:** Legit sites embed brand names in paths and tracking domains.
  **Alternatives considered:** Treat as strong.
  **Trade-off:** `paypal-login.com` scores 15 on its own.
- **Decision:** Wording stays a keyword list.
  **Why:** Transparent and weak by design; ML is out of scope.
  **Alternatives considered:** TF-IDF classifier.
  **Trade-off:** Easy to evade, so never decisive.

## 6. Edge cases and limitations
- The brand list is small and English/US-centric.
- Legit IDN domains (`bücher.de`) get only a low-weight `punycode_domain`.
- Compromised legitimate accounts pass every identity check.
- Domain age depends on RDAP coverage (some ccTLDs don't publish dates) - unknown age is never scored.

## 7. How to test it
`backend/tests/test_heuristics.py`
```
cd backend && python -m pytest tests/test_heuristics.py -q
```

## 8. Further reading
UTS #39 (Unicode security mechanisms, confusables), RFC 5890-5892 (IDNA 2008), RFC 7480-7483 (RDAP), "Levenshtein distance".
