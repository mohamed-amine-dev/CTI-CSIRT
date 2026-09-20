# Antigravity — Argus CTI Platform

> Everything about the project in one file: what the platform does, why it
> exists, how it is built, what we have actually done so far, what is running
> right now, and where it can go next.
>
> Authoritative sources: `internship-report.md` (full walkthrough), the ADRs in
> `adr/`, `SESSION_CONTEXT.md` (session handoff), and the code in `app/` /
> `frontend/`.

---

## 1. What the platform is — in one sentence

A **zero-cost (€0/month) Cyber Threat Intelligence (CTI) platform for a CSIRT
team**: ~16 free open-source threat feeds are polled, normalised and stored in
ClickHouse; an AI worker turns every CVE into a structured **Alert Sheet**;
every malicious IP is geolocated; a React dashboard lets analysts browse,
search, visualise and export it all — and on top sits an **autonomous triage
agent** that investigates one indicator at a time.

The whole point: a large commercial platform (SOCRadar, OpenCTI, Recorded
Future) answers "what happened overnight, does it affect us, what do we do?"
but costs thousands of euros a year. This project delivers the **same kind of
value for free** — free feeds, free open-source software, free AI tiers.

---

## 2. Why it exists (the problem)

A CSIRT team needs to answer, every morning, three questions:

1. **What happened overnight?** — new threats, vulnerabilities, malicious IPs, malware.
2. **Does it affect us?** — is a reported vulnerability present in our environment?
3. **What do we do about it?** — which patch, hardening or isolation action?

The supervisor's key deliverable is the **Alert Sheet**: a structured one-page
summary per CVE following a fixed 4-point template:

1. **Environmental impact** — is it present in our env? Which versions? How to check?
2. **Risk level** — severity + concrete exploitation paths + impact if compromised.
3. **Exploitation status** — public exploit/PoC? Under what conditions?
4. **Remediation** — patch + hardening + isolation + access restrictions.

**Two hard rules run through everything** (from the supervisor briefs):

- **Never fabricate data.** Use real feeds, real geolocation, real CVSS scores;
  if something is unknown, say so honestly.
- **Stay at €0.** Local model first (Ollama), free tiers as fallback, free feeds
  and free services only.

---

## 3. Architecture — the big picture

```
16 free threat feeds
   │  16 async collectors (CISA, NVD, CERT-FR/EU, abuse.ch, blocklist.de,
   │  Spamhaus, OpenPhish, OTX, MISP, Shodan InternetDB, Tor dark-web, Telegram…)
   ▼
INGESTION ENGINE  (app/ingestion_engine.py)
   • normalises every item into an IntelRecord
   • extracts indicators (IP, hash, domain, CVE, URL, JA3, email)
   • classifies a threat category (deterministic rules, no AI)
   ▼
ClickHouse  (columnar OLAP, 8 ReplacingMergeTree tables, partitioned monthly)
   │
   ├──▶ AI worker        raw text → structured Alert Sheet (LLM + strict schema)
   ├──▶ Geo enricher     every malicious IP → country (ipwho.is, cached per IP,
   │                     monthly 9k/10k quota guard)
   └──▶ FastAPI backend  serves /api/v1/... + the built React SPA (same origin)
   ▼
REACT DASHBOARD (Vite + Tailwind + Recharts + D3)
   Executive Overview · Threat Landscape · Live Feeds · Alert Sheets ·
   IoC Search & Shodan · Search & Export · Data Explorer · Dark Web ·
   Autonomous Triage
   ▼
Notifications ▶ Telegram (ClickHouse-backed, code ready)
```

On top of that sits the **Autonomous Triage Agent**: an analyst pastes one
indicator + raw context, and the agent sanitises the input, checks it against
read-only tools (Shodan InternetDB + the platform's own corpus), asks the LLM,
and returns a risk score, verdict, findings and optionally an Alert Sheet —
every step recorded in an audit trail.

---

## 4. Technology stack

| Layer | Technology | Why | Cost |
|---|---|---|---|
| Backend | **Python + FastAPI** (async) | Fast, one origin serves API + UI | Free |
| Storage | **ClickHouse** | Columnar OLAP: instant aggregations over 200k+ rows; `ReplacingMergeTree` = idempotent upserts | Free |
| AI | **LangChain + LangGraph + Ollama → Gemini → Groq** | One LLM interface; local model first, free tiers auto-fallback | Free |
| Frontend | **React 18 + Vite + Tailwind + Recharts + D3** | Components + bundler + styling + charts + world map | Free |
| Geolocation | **ipwho.is** | Free, no key, ~10k/month | Free |
| Scraping | **aiohttp + aiohttp-socks** | Async HTTP for collectors; SOCKS5 routes dark-web through Tor | Free |
| Deploy | **Docker / docker compose** | One command = whole stack | Free |
| Config | **pydantic-settings** | Typed settings from `.env` | Free |

Key terms, simply: **IOC** = Indicator of Compromise (IP, domain, hash, CVE…);
**CVE/CVSS** = vulnerability id / 0–10 severity score; **STIX 2.1** = standard
JSON format to share threat intel; **ReplacingMergeTree** = ClickHouse engine
that collapses duplicate rows keeping the newest version (microsecond timestamp
= newest wins); **.onion** = dark-web site reached through Tor.

---

## 5. What we have done — the full build log

Everything below is **implemented in source and currently running**.

### 5.1 Ingestion — the 16 collectors (`app/ingestion_engine.py`)

Collectors (grouped):

- **CISA** — KEV catalogue + advisories.
- **NVD** — National Vulnerability Database (incremental, watermark-based sync
  via the `ingest_state` table — never a full re-download).
- **EU/FR CERTs** — CERT-EU + CERT-FR RSS.
- **News RSS** — general cyber news for context.
- **abuse.ch** — URLhaus (malicious URLs), ThreatFox (IOCs), Feodo Tracker (C2
  IPs), SSLBL (JA3 TLS fingerprints).
- **IP reputation** — blocklist.de, Spamhaus DROP.
- **Phishing** — OpenPhish.
- **Threat-intel platforms** — AlienVault OTX (auto-disables without a key),
  MISP.
- **Shodan InternetDB** — free passive enrichment: ports, CVEs, hostnames.
- **Dark web** — `.onion` search scraping routed through Tor SOCKS5
  (`dockurr/tor`, port 9050) + optional Telegram channel poll.

Each collector: poll → parse → normalise to an `IntelRecord` → persist raw
text → extract IOCs (regex) → classify threat (deterministic) → fan out CVEs to
the AI queue. Failures in one feed never abort the others; each collector runs
on its own `poll_interval`.

**Dark-web detail (verified live)**: the collector routes through Tor, confirms
Tor is working via `check.torproject.org` first (circuit build can take 30–90 s),
then probes DuckDuckGo's onion `/lite/?q=` search with threat queries
(`ransomware leak`, `database leak`, `stolen data dump`, `credential dump`).
Results go through a real browser User-Agent, dedup happens within a poll and
via the `(source, url)` table key across polls. Hourly cadence.

### 5.2 Storage — 8 ClickHouse tables (`app/db_init.py`)

All `ReplacingMergeTree`, partitioned by month:

| Table | Key | Purpose |
|---|---|---|
| `raw_threat_intel` | `(source, url)` | every raw feed item |
| `processed_iocs` | `(type, indicator)` | normalised indicators + severity |
| `vulnerability_alerts` | `vuln_cve` | the Alert Sheet (4 JSON content columns + threat_score) |
| `alert_sheet_pending` | `cve` | durable AI job queue: pending/processing/done/failed |
| `notifications` | `id` | real-time alerts + read flag |
| `ip_geo_cache` | `ip` | per-IP geolocation cache (country, ok/fail) |
| `agent_triage_results` | `id` | append-only audit trail of every agent run |
| `ingest_state` | `source` | watermarks for incremental feeds (e.g. NVD) |

### 5.3 AI Alert Sheet pipeline (`app/ai_processor.py`)

- Strict Pydantic schema `AlertSheetModel` = the supervisor's 4-point template.
- `with_structured_output()` forces the LLM to emit matching JSON.
- **Provider failover**: Ollama (local) health-checked first (2s probe, cached
  30 s) → Gemini → Groq.
- **Global rate limiter** (`ai_min_interval_seconds`), per-engine retries with
  exponential backoff + jitter, English-only guard with a French-detection
  recovery pass.
- **Ground-truth overrides**: real CVSS score wins over the model's free-form
  severity; the CVE extracted from text wins over a hallucinated one.
- **Dedup**: re-seeing a CVE re-inserts it with `threat_score + 1`, no LLM call.

### 5.4 Durable pipeline (Phase 4)

CVEs are tracked in `alert_sheet_pending` — nothing is silently dropped. Failed
CVEs keep `attempts` + `last_error` + `retry_at`, get re-enqueued after cooldown
up to a max attempts, and `pending/processing` rows orphaned by a crash are
recovered on restart. The UI shows the honest pipeline state.

### 5.5 Alerting (`app/notifications.py`)

New sheets above the risk threshold, or any KEV CVE (always alerts), create a
notification row → top-bar bell + unread badge. **Telegram push is implemented
but off** (`ALERT_TELEGRAM=false`) until activation is confirmed. Best-effort
by design — a failed push never touches ingestion.

### 5.6 Threat Landscape module (the "Brief #3" module)

- **By Origin** — D3 choropleth (`geoNaturalEarth1` + `world-atlas` TopoJSON +
  ipwho.is data, country codes joined via `utils/countryCodes.js`), time-range
  switch (24h/7d/30d/60d), click country → filtered IoC list.
- **By Technique** — ATT&CK tactic heatmap (rows = threat categories, columns =
  tactics) built on the analyst-owned `category → tactic` table in
  `app/tactics.py`; "Other" lands honestly in an **Unclassified** column.
- Deterministic classifier (`app/threat_classify.py`) + explicit tactic table —
  never let an LLM guess these.
- Executive Overview preview tiles link into the full page.
- Honest caveat in the UI: the map shows where the malicious **indicator IPs
  are hosted**, not the attacker's physical location.

### 5.7 Autonomous Triage Agent ("Agent Detection & Response")

A LangGraph pipeline. Triggered when an analyst pastes one indicator + raw
context:

```
sensor_sanitizer → (quarantine if flagged) → triage_evaluator → tools_execution
                                                                (read-only: Shodan
                                                                 InternetDB + corpus)
   → synthesis (LLM risk 0–100 + verdict + recommendations) → sheet_generator
```

- `app/agent/sensor.py` — sanitisation + prompt-injection detection before any
  tool or LLM sees the input. Flagged input → terminal **quarantine** node (no
  tool, no LLM), `is_flagged_unsafe: true` + reasons.
- `app/agent/tools.py` — strictly read-only tools that never raise (a failure
  becomes `{found: false, detail: …}`).
- Synthesis falls back to a **deterministic baseline risk** (base 10, +30 CVE,
  +15 ipv4/domain/hash, tool hits add more) if the LLM fails — honest either way.
- CVE inputs reuse the main pipeline's `generate_alert_sheet()` (same dedup +
  CVSS-override); the sheet lands in `vulnerability_alerts` with source
  `AGENT-TRIAGE`. Non-CVE indicators get a sheet in the response only.
- Every run is stored in `agent_triage_results` and shown in the UI with the
  full execution trace (sensor → quarantine/tools/synthesis/sheet).
- HTTP: `POST /api/v1/agent/triage` (bearer-token auth, per-type validation,
  `context` mandatory) + `GET /api/v1/agent/history`.

### 5.8 Search, Export & Data Explorer

- Global search across feeds + indicators + sheets.
- Bulk export to **CSV / JSON / STIX 2.1** (sheet → STIX `vulnerability`, IOC →
  STIX `indicator` with proper pattern literals, raw item → STIX `report`).
- Read-only SQL playground guarded by the `cti_ro` ClickHouse account (can only
  SELECT — even ad-hoc queries can never write).

### 5.9 Frontend — pages

| Route | Page |
|---|---|
| `/dashboard` | **Executive Overview** — KPIs, live map, charts, preview tiles, PDF report |
| `/threat-landscape` | Threat Landscape — By Origin (choropleth) / By Technique (heatmap) |
| `/feeds` | Live Threat Feeds — filterable intel stream |
| `/vulnerabilities` | Alert Sheets — 4-point sheets + export |
| `/ioc-search` | IoC Search & Shodan — indicator lookup + enrichment |
| `/indicators` | Indicators — IoC list (also the map's country drill-down) |
| `/search` | Search & Export hub |
| `/explore` | Data Explorer — read-only SQL playground |
| `/darkweb` | Dark Web & Telegram monitor |
| `/agent` | Autonomous Triage — form, verdict, risk, trace UI, audit history |

### 5.10 Latest UI session — shadcn foundation + OpenCTI-style dashboard

The most recent work moved the frontend from hand-rolled styling to a proper
**shadcn/ui design system** and gave the dashboard the dense, statistics-heavy
look of commercial CTI products like OpenCTI:

- **Added the shadcn stack**: `class-variance-authority`, `clsx`,
  `tailwind-merge`, `tailwindcss-animate` + Radix primitives; new `cn()` helper
  in `src/lib/utils.js`; shadcn HSL tokens (dark + light) in
  `src/index.css` / `tailwind.config.js` mirroring the existing palette; real
  Inter + JetBrains Mono font loading.
- **New shadcn component kit** in `src/components/ui/`: `Dialog`, `Tabs`,
  `Tooltip`, `Select`, `DropdownMenu`, `Separator`, `Skeleton`, `Switch`,
  `Progress`, `Input`, `Label` — plus `Button`, `Card`, `Badge`, `Table`
  rebuilt on `cva()` with the same APIs (so every page inherits the new look
  without being rewritten), and `Modal` rewritten on Radix Dialog.
- **OpenCTI-style dashboard overhaul**:
  - KPI stat cards with **sparklines** + real day-over-day **delta chips**
    (the ingestion card plots the last 14 days and shows % change vs yesterday
    — all real timeline data).
  - New **Platform Intelligence row**: "AI Alert Sheet Pipeline" (live queue
    counts + completion % + LLM provider), "Geolocation Coverage" (IPs cached,
    countries, monthly quota progress bars), "Indicator Corpus by Type" (real
    per-type split).
  - Chart polish: donut with side legend + centered total, compact axis ticks,
    rounded bars, legend row on the landscape trend chart.
- Verified: frontend builds clean, app image redeployed, all 4 containers
  healthy, dashboard/queries return real data.

---

## 6. Verified state of the running stack

Last full verification (2026-08-15), plus the UI redeploy from the latest
session:

- **Raw corpus ≈ 223,000 rows** across all feed families; feeds still landing
  live (CERT-FR +80, NEWS +65, CERT-EU +10 in one poll cycle).
- **Dark web**: `DARKWEB-ONION` ≥73 rows; a live poll stored 39 items from 4
  queries × 10 DDG-onion results (1 deduped, 0 errors). `TELEGRAM` = 0 rows (no
  token configured — by design).
- **Geolocation**: `ip_geo_cache` = 1,015 cached (1,000 ok / 15 fail), 70
  countries, monthly budget 1,015/9,000. `/api/v1/geo/summary` returns real
  per-country counts.
- **Agent**: verified 401/422 validation, prompt-injection → quarantine, real
  IP → HTTP 200 + full trace + persisted audit row. Fixed the LangGraph bug
  along the way: node params must be typed `RunnableConfig`, not `dict`.
- **Dashboard**: all endpoints live (`/health`, `/api/v1/ai/status`,
  `/api/v1/geo/status`, `/api/v1/iocs/stats`…); new shadcn bundle served.
- **Containers**: `cti-app`, `cti-clickhouse`, `cti-ollama`, `cti-tor` all
  healthy.

**Known honest limitations**:
- `llama3.2:3b` structured output is flaky → synthesis sometimes falls back to
  the deterministic baseline (stated in the response). A better local model
  would fix it with zero code changes.
- Agent runs can take minutes while a big sheet backlog drains (one global LLM
  throttle).

---

## 7. Deployment & how to run

**Docker (recommended):**

```bash
docker compose up -d --build     # only the app image rebuilds; data persists
```

Stack: `cti-app` (FastAPI + SPA, :8000), `cti-clickhouse` (persistent volume
`cti_clickhouse_data`), `cti-ollama` (pulls `llama3.2:3b` on first boot),
`cti-tor` (`dockurr/tor` SOCKS5 proxy on 9050). `.env` holds real credentials —
never commit or print them.

Health check:

```bash
curl -s http://localhost:8000/health   # {"status":"ok",...}
curl -s http://localhost:8000/api/v1/geo/summary?days=60
curl -s http://localhost:8000/api/v1/threats/heatmap?days=60
```

**Bare metal:** ClickHouse up, Python venv, `python -m app.db_init`, then
`uvicorn app.main:app …`.

---

## 8. Architecture Decision Records (`adr/`, Uber format)

| ADR | Decision |
|---|---|
| `0001` | ClickHouse (ReplacingMergeTree, monthly partitions) + FastAPI instead of a relational DB |
| `0002` | AI structured extraction — LLM must emit the exact 4-point JSON contract |
| `0003` | LLM failover chain Ollama → Gemini → Groq (stays at €0) |
| `0004` | Durable sheet pipeline — persisted job queue, never fire-and-forget |
| `0005` | Real-time alerting with an in-app notification centre |
| `0006` | Search & Export hub — global search + CSV/JSON/STIX downloads |

> Terminology warning: in this project "**Uber ADR**" means **Agent Detection
> and Response** (the triage agent). "ADR" on its own means Architecture
> Decision Records. Never conflate the two.

---

## 9. Gotchas we don't want to re-discover

- The app connects to ClickHouse as `clickhouse:8123` on the compose network,
  **not** the published host port.
- ipwho.is is the geolocation provider (ip-api.com is HTTP-only and this host
  blocks outbound HTTP). 9k/10k monthly budget.
- `ReplacingMergeTree` + microsecond `version` = idempotent upsert; use `FINAL`
  on reads.
- `npm run build` emits into `../web/dist`; in Docker the SPA is built inside
  the image (`docker compose up -d --build` ships the latest UI).
- Tor: `dockurr/tor` ships its own healthcheck — never re-add a control-port
  probe (it can never pass). A fresh Tor's first fetch can throw a transient
  `ClientOSError` while circuits build — the collector retries.
- Threat categories & ATT&CK mappings are deterministic tables — never let an
  LLM guess them.
- Branding: the name "**Argus CTI**" is used everywhere but **not yet
  confirmed** by the user.

---

## 10. What's left / open questions / next steps

**Open questions:**
1. **Branding** — confirm "Argus CTI" or provide the real name + logo/colors
   (any change touches sidebar, title, favicon, PDF, footer).
2. **Telegram alerts** — implemented but off; enabled in `.env`? ("yes" needed).
3. Stale doc row: `internship-report.md` §6.2 still lists the removed `/docs`
   ADR-viewer page — clean it once approved.

**Candidate next steps (from §13 of the report, highest value first):**
- Analyst workflow: OpenCTI/TheHive ingestion, case/ticket integration,
  watchlists & subscriptions, **asset inventory → automatic "does it affect
  us?"**, sheet review states.
- Intelligence depth: threat-actor attribution, STIX `attack-pattern` /
  `malware` objects, feed trust scoring, cross-feed correlation, historical
  trends.
- Detection & correlation: alert correlation rules, export the IOC set as a
  live blocklist, JA3↔C2 pivots, ingestion-volume anomaly detection.
- Scale & ops: real auth/multi-user, Prometheus metrics, retention policies,
  split processes, backups.
- UI: keep extending the shadcn design system to the remaining pages (feeds,
  alerts, IoC search, agent) so the whole platform shares the OpenCTI-style
  density introduced on the dashboard.

*End of file. For any claim here, the authoritative source is the code in
`app/`, `frontend/`, and the ADRs in `adr/`.*