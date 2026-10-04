# Scoring rules

Source of truth: [`backend/app/scoring/rules.yaml`](../backend/app/scoring/rules.yaml). This table was generated from it. Weights are hand-set judgements, calibrated on the ten synthetic fixtures; re-tune them against real mail before relying on them.

## How the score works

1. Analysis modules emit *signals*; each signal id maps to one rule.
2. Each fired rule counts **once** (details keep every occurrence). The score is the sum of weights, capped at 100.
3. Verdict: `SAFE` < 25 <= `SUSPICIOUS` < 60 <= `PHISHING` (override with `SCORE_SUSPICIOUS_THRESHOLD` / `SCORE_PHISHING_THRESHOLD`).
4. Hard overrides can only raise the verdict; the score is lifted to the threshold so both stay consistent.

### Hard overrides

- **known_malware_hash**: requires `vt_file_malicious` -> forces `PHISHING`. An attachment matches known malware.
- **dmarc_fail_with_lookalike**: requires `dmarc_fail`, `lookalike_domain` -> forces `PHISHING`. The email fails sender verification AND uses a lookalike of a trusted brand.

## Rules

| Rule | Category | Weight | Rationale | Example trigger |
|---|---|---|---|---|
| `dmarc_fail` | authentication | 40 | The domain owner's own policy rejects this message; the strongest single authentication signal. | Fixture 04 |
| `spf_fail` | authentication | 15 | Sending IP is explicitly not authorised by the envelope domain. | SPF `-all` and an unlisted IP |
| `spf_softfail` | authentication | 8 | Domain says 'probably not authorised'; often misconfiguration, so lower. | SPF `~all` and an unlisted IP |
| `dkim_fail` | authentication | 15 | A signature that does not verify means tampering or forgery (or a rotated key). | Body edited after signing |
| `spf_misaligned` | authentication | 10 | SPF passed, but for someone else's domain; the classic way to pass checks while spoofing From. | Fixture 04 |
| `auth_results_untrusted` | authentication | 8 | A header claiming verification results that our receiving server did not write could be planted. | authserv-id differs from the receiving host |
| `auth_results_missing` | authentication | 5 | No provider verdict at all; we are blind on authentication. | Fixture 09 |
| `hop_forged_suspected` | routing | 20 | Fabricated Received lines are used to disguise the origin; only untrusted hops are judged. | Fixture 10 |
| `hop_timestamp_out_of_order` | routing | 8 | Time cannot run backwards along a real chain. | Fixture 10 |
| `hop_private_ip_unexpected` | routing | 5 | A private address cannot hand over a message that already crossed the Internet. | 10.x hop after a public hop |
| `hop_large_delay` | routing | 3 | Slightly unusual; low weight because queueing delays are common. | >1 h between hops |
| `display_name_brand_spoof` | sender | 35 | Mail clients often show only the display name; brand names there are the cheapest impersonation. | Fixture 02 |
| `display_name_domain_mismatch` | sender | 30 | A name that shows a different address/domain than the real sender is deliberate deception. | "billing@bank.com" <x@evil.example> |
| `reply_to_mismatch` | sender | 15 | Replies are diverted to another organisation; common in business email compromise. | From example.com, Reply-To gmail.com |
| `return_path_mismatch` | sender | 5 | Often legitimate (mailing services), hence low; correlates with DMARC/SPF findings. | Fixture 04 |
| `lookalike_domain` | sender | 45 | Domain visually imitates a known brand: strong intent signal. Also half of an override. | Fixture 03 |
| `punycode_domain` | sender | 10 | IDN labels can hide look-alike characters, but plenty of legitimate IDNs exist, so low. | xn-- label |
| `brand_keyword_domain` | sender | 15 | Brand name inside an unrelated domain; frequent in phishing but also in tracking domains. | paypal-secure-login.com |
| `young_domain_sender` | sender | 25 | Phishing domains are typically days old; needs RDAP (enrich=true). | Sender registered 4 days ago |
| `link_text_mismatch` | links | 30 | Visible URL differs from the real target: deliberate deception of the reader. | Fixture 05, 06 |
| `lookalike_link_domain` | links | 30 | A link goes to a brand lookalike. | Fixture 03 |
| `young_domain_link` | links | 20 | Linked site is brand new. | Link domain 3 days old |
| `url_ip_host` | links | 15 | Legitimate organisations rarely link to raw IPs. | http://192.0.2.7/login |
| `url_userinfo` | links | 20 | `user@host` syntax exists mainly to disguise the real host. | https://paypal.com@evil.example |
| `url_shortener` | links | 8 | Hides the destination; legit marketing uses them too, hence low. | bit.ly link |
| `url_redirector_wrapped` | links | 2 | Informational: wrapper stripped so the real target is judged. | SafeLinks URL |
| `attachment_double_extension` | attachments | 45 | Designed to trick Windows users who do not see real extensions. | Fixture 07 |
| `attachment_executable` | attachments | 40 | Programs/scripts in email are rarely legitimate. | Fixture 07 |
| `attachment_type_mismatch` | attachments | 25 | Content does not match the claimed extension. | report.pdf that is HTML |
| `attachment_macro` | attachments | 30 | Macros are the dominant Office malware delivery method. | Fixture 08 |
| `attachment_macro_autoexec` | attachments | 20 | Auto-run on open removes the user's last chance to stop it. | Fixture 08 |
| `attachment_password_protected` | attachments | 20 | Prevents scanning; the password is usually in the email body. | Encrypted ZIP |
| `attachment_html` | attachments | 10 | HTML smuggling and fake login pages travel as attachments. | invoice.html |
| `attachment_rtlo` | attachments | 40 | Bidi override characters have no legitimate use in attachment names. | invoice\u202egpj.exe |
| `urgency_language` | language | 6 | Weak: genuine alerts also use urgency. Never decisive alone. | "within 24 hours" |
| `credential_request_language` | language | 8 | Weak: banks also ask you to sign in. Never decisive alone. | "verify your password" |
| `mime_malformed` | structure | 5 | Broken structure is used to evade filters but also produced by buggy tools. | Fixture 09 |
| `vt_url_malicious` | reputation | 40 | Three or more engines agree a linked URL is malicious. | VirusTotal stats |
| `vt_url_suspicious` | reputation | 15 | Weaker reputation hit (1-2 engines or 'suspicious'). | VirusTotal stats |
| `vt_file_malicious` | reputation | 60 | Known-malware hash; forces PHISHING via override. | EICAR hash in tests |
| `urlscan_malicious` | reputation | 35 | A live scan judged the destination malicious. | urlscan verdict |

## Expected fixture results

| Fixture | Verdict | Main rules |
|---|---|---|
| `01_legit.eml` | SAFE | (none) |
| `02_display_name_spoof.eml` | SUSPICIOUS | `display_name_brand_spoof`, `urgency_language`, `credential_request_language` |
| `03_lookalike_punycode.eml` | PHISHING | `lookalike_domain`, `punycode_domain`, `lookalike_link_domain` |
| `04_dmarc_alignment_fail.eml` | SUSPICIOUS | `dmarc_fail`, `spf_misaligned`, `return_path_mismatch` |
| `05_link_text_mismatch.eml` | SUSPICIOUS | `link_text_mismatch`, `credential_request_language` |
| `06_safelinks.eml` | SUSPICIOUS | `link_text_mismatch`, `url_redirector_wrapped` |
| `07_double_extension.eml` | PHISHING | `attachment_double_extension`, `attachment_executable` |
| `08_macro_doc.eml` | SUSPICIOUS | `attachment_macro`, `attachment_macro_autoexec` |
| `09_malformed.eml` | SAFE | `mime_malformed`, `auth_results_missing` |
| `10_forged_received.eml` | SUSPICIOUS | `hop_forged_suspected`, `hop_timestamp_out_of_order` |

## Known weaknesses

- Correlated rules (DMARC fail + SPF misalignment + Return-Path mismatch) all describe one underlying fact and add up.
- Wording rules are intentionally weak: text alone can never reach SUSPICIOUS (6 + 8 = 14 < 25).
- A compromised legitimate account passes every identity rule; only content and reputation rules can catch it.
- Thresholds trade false positives for false negatives; for a SOC queue, lower them, for end users, raise them.
