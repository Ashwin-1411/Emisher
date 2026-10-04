# Architecture

## Components

```mermaid
flowchart LR
  subgraph Browser
    P[Popup<br/>drop .eml, results UI]
    C[Gmail content script<br/>banner]
    O[Options page]
    B[Background service worker<br/>token, backend calls, cache]
  end
  subgraph Backend[FastAPI backend]
    API[api/ auth, rate limit, size cap]
    PIPE[pipeline.py]
    SCORE[scoring/ rules.yaml]
    CACHE[(SQLite cache<br/>hash/URL keyed)]
    STORE[(Report store<br/>RAM, 15 min)]
  end
  VT[VirusTotal]
  US[urlscan.io]
  RD[RDAP]
  DNS[DNS]
  P -->|message| B
  C -->|message| B
  O -->|settings| B
  B -->|HTTPS + X-API-Token| API
  API --> PIPE --> SCORE
  PIPE --> CACHE
  PIPE -.enrich=true.-> VT & US & RD & DNS
  API --> STORE
```

## Pipeline stages

```mermaid
flowchart TD
  RAW[raw .eml bytes] --> PARSE[parsing]
  PARSE --> HOPS[hops: Received chain]
  HOPS --> AUTH[auth_checks: delivery-time + optional live SPF/DKIM/DMARC]
  AUTH --> URLS[urls: extract, unwrap, defang, shortener expansion*]
  URLS --> ATT[attachments: hashes, magic bytes, macros]
  ATT --> HEUR[heuristics: spoofing, lookalikes, wording]
  HEUR --> ENR[enrichment*: VirusTotal, urlscan, RDAP, ASN]
  ENR --> SC[scoring: signals -> score, verdict, reasons]
  SC --> REP[Report + IOCs]
```
`*` only when `enrich=true`. Each stage runs inside a guard: an exception becomes an entry in `Report.warnings` and the pipeline continues.

## Flow 1: popup upload

```mermaid
sequenceDiagram
  actor U as User
  participant P as Popup
  participant B as Background worker
  participant A as Backend /api/v1
  participant X as VT / urlscan / RDAP
  U->>P: drop message.eml
  P->>B: analyze(base64 bytes)
  B->>A: POST /analyze?enrich=true (X-API-Token)
  A->>A: parse, hops, auth, urls, attachments, heuristics
  A->>X: hash/URL lookups, scans, domain age (cached, rate-limited)
  X-->>A: reputation data
  A->>A: score, build Report, keep in RAM store
  A-->>B: Report JSON
  B-->>P: Report
  P-->>U: verdict card, reasons, tabs
  opt user clicks "Submit to VirusTotal"
    U->>P: confirm consent dialog
    P->>B: submitAttachment(sha256, bytes, consent)
    B->>A: POST /attachments/{sha256}/submit (file + consent=true)
    A->>X: upload that one attachment
  end
```

## Flow 2: Gmail auto-scan

```mermaid
sequenceDiagram
  actor U as User
  participant G as Gmail page
  participant C as Content script
  participant B as Background worker
  participant A as Backend
  U->>G: opens a message
  G-->>C: DOM mutation (div.adn[data-message-id])
  C->>G: fetch "Show original" (same-origin, session cookie)
  G-->>C: raw RFC 5322 source
  C->>B: analyze(base64, cacheKey=gmail:id)
  alt cache hit (storage.session)
    B-->>C: cached Report
  else miss
    B->>A: POST /analyze
    A-->>B: Report
    B->>B: cache by message id
    B-->>C: Report
  end
  C->>G: insert closed-shadow-root banner above body
```

## Data held where

| Data | Where | Lifetime |
|---|---|---|
| Raw email, attachments | request memory in the backend | the request |
| Report (no bodies/bytes) | backend RAM `ReportStore` | 15 min (configurable) |
| VT/urlscan/RDAP results | SQLite, keyed by hash | per-source TTL |
| Backend URL, token | `chrome.storage.local` | until removed |
| Report per Gmail message | `chrome.storage.session` | until browser closes |

## Failure model

- Missing API key -> source skipped, reported in `enrichment.sources`.
- DNS/HTTP error -> that item skipped or a stage warning; verdict still produced.
- Rate limit reached -> lookup skipped with an explanation (never blocks the request for long).
- `enrich=false` -> no outbound network of any kind.
