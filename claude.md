# Claude — draw this project in Miro

Your job: design a **simple, high-level workflow diagram** of this project in
**Miro.com**. This file contains everything you need. Keep the design clean and
visual — swimlanes or clear stages, big labeled shapes, arrows showing the flow,
one colour per logical zone. Do NOT draw every detail; the goal is a board an
analyst or manager can read in 30 seconds.

## Project in one sentence

A free, €0-cost CSIRT (Computer Security Incident Response Team) threat
intelligence platform: ~16 open-source threat feeds are polled, normalised and
stored in ClickHouse, an AI worker turns CVEs into structured "Alert Sheets",
every malicious IP is geolocated, and a React dashboard lets analysts browse,
search and export it all. On top sits an autonomous triage agent.

## Layout suggestion for Miro

Arrange as 5 swimlanes (columns) left → right:

1. **SOURCES (inputs)** — the feed boxes, grouped by type.
2. **INGESTION ENGINE** — one box: poll → normalise → extract IOC → classify.
3. **STORAGE** — ClickHouse database box listing the 8 tables.
4. **WORKERS & SERVICES** — AI worker, geolocation worker, triage agent,
   FastAPI backend.
5. **PRESENTATION** — the React dashboard with its pages.

Below everything, a thin swimlane for **INFRASTRUCTURE** (Docker Compose
services). Draw the main data path as bold arrows (SOURCES → INGESTION →
STORAGE → WORKERS → DASHBOARD); draw lighter dashed arrows for the agent's own
flow and for notifications (Telegram).

## The exact flow to show

- Feeds → 16 async collectors → **Ingestion Engine**
  (`app/ingestion_engine.py`): normalises each item into an `IntelRecord`,
  extracts indicators (IP, hash, domain, CVE), classifies threat category
  (deterministic, no AI needed).
- → **ClickHouse** (columnar OLAP, 8 `ReplacingMergeTree` tables, partitioned
  by month).
- Three consumers of ClickHouse:
  - **AI worker** — raw text → structured **Alert Sheet** (LLM + schema).
  - **Geolocation worker** — malicious IP → country via ipwho.is, cached per IP.
  - **FastAPI backend** (`/api/v1/...`) — serves data + the built React SPA.
- **React dashboard** pages: Executive Overview · Threat Landscape · Live
  Feeds · Alert Sheets · IoC Search & Shodan · Search & Export · Data Explorer ·
  Dark Web · Autonomous Triage · (Notifications).
- **Notifications** → Telegram (ClickHouse-backed, real-time alerting).

## The 16 sources (group them visually)

- **CISA** — KEV catalogue + advisories.
- **NVD** — National Vulnerability Database (incremental, watermark-based).
- **EU/FR CERTs** — CERT-EU + CERT-FR RSS.
- **News RSS** — general cyber news feed.
- **abuse.ch** — URLhaus (malicious URLs), ThreatFox (IOCs), Feodo Tracker
  (C2), SSLBL (JA3 TLS fingerprints).
- **IP reputation** — blocklist.de, Spamhaus DROP.
- **Phishing** — OpenPhish.
- **Threat intel platforms** — AlienVault OTX, MISP.
- **Shodan InternetDB** — passive enrichment: ports, CVEs, hostnames.
- **Dark web** — .onion scraping routed through a Tor SOCKS5 proxy
  (`dockurr/tor`, port 9050) + optional Telegram channel poll.

## Storage — the 8 ClickHouse tables

- `raw_threat_intel` · `processed_iocs` · `vulnerability_alerts` ·
  `alert_sheet_pending` · `notifications` · `ip_geo_cache` ·
  `agent_triage_results` · `ingest_state` (watermarks for incremental feeds).

## The triage agent ("Agent Detection & Response" = ADR)

A LangGraph pipeline triggered when an analyst pastes one indicator + raw
context. Nodes in order:

`sensor_sanitizer` → (`quarantine` if clearly unsafe) → `triage_evaluator` →
`tools_execution` (read-only: Shodan InternetDB + the platform's own corpus
lookup) → `synthesis` (LLM risk score 0–100 + verdict + recommendations) →
`sheet_generator` (optional Alert Sheet).

Inputs: indicator, type, raw context. Outputs: verdict (flagged/clean), risk
score, key findings, recommended actions, quarantine reasons, execution trace,
sheet data. Every run is stored in `agent_triage_results` and shown with its
full execution trace in the UI.

## Infrastructure (Docker Compose — show as a thin frame)

- `cti-app` — FastAPI backend + React SPA (built static assets).
- `cti-clickhouse` — the OLAP database.
- `cti-ollama` — local LLM (primary). Fallback: free Gemini/Groq APIs
  (keeps the project at €0).
- `cti-tor` — `dockurr/tor` SOCKS5 proxy for dark-web scraping only.

## Style rules for Miro

- Use **swimlanes or labelled frames**, one colour per zone (e.g. blue =
  sources, purple = storage, green = services, orange = UI).
- Big bold shapes, short labels, **fewer than ~30 nodes** total.
- Bold arrows = main data flow; dashed arrows = secondary (agent, Telegram).
- Add a 2-line legend box (colour meaning + arrow meaning).
- Keep it flat and horizontal; no nested stacks of detail.

## Truthfulness rule

Only use facts from this file. If something is ambiguous, leave it out rather
than inventing it — the diagram must be an accurate high-level view.
