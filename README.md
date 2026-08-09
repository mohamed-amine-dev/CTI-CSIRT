# CSIRT Cyber Threat Intelligence Platform

A zero-cost, production-oriented CTI platform for a CSIRT team — architecturally
comparable to SOCRadar / OpenCTI, but built on a strictly **$0 budget**:

| Layer        | Technology                              | Cost |
|--------------|-----------------------------------------|------|
| API          | Python **FastAPI** (async, ASGI)        | Free (OSS) |
| Storage      | **ClickHouse** (OLAP, columnar)         | Free (OSS) |
| AI Engine    | **Groq** free tier → **Gemini** free tier → **Ollama** local fallback | Free |
| Frontend     | React (Vite) + Tailwind + Recharts        | Free (OSS) |
| Sources      | CISA, CERT-FR/EU, NVD, abuse.ch, Spamhaus, Tor, Telegram, ... | Free |

Every architectural decision is recorded in [`adr/`](adr/) (Uber ADR format).

---

## Quick start

```bash
# 1. Start ClickHouse
docker compose up -d clickhouse

# 2. Configure (copy and edit)
cp .env.example .env

# 3. Install Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Create the schema (partitioned, idempotent)
python -m app.db_init

# 5. Run the API (ingestion engine + AI worker start automatically)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Check it's alive: `curl http://localhost:8000/health` → `{"status":"ok", ...}`

### Seed the database with mock data (optional, for immediate testing)

If external feeds are blocked, rate-limited or empty, fill ClickHouse with 50
realistic mock records (APT intel, CVEs, malicious IPs, dummy Fiches d'Alerte)
so every dashboard view is testable right away:

```bash
# ClickHouse must be running; run from the repo root with the backend venv
.venv/bin/python seed_db.py            # seed (idempotent upsert)
.venv/bin/python seed_db.py --reset    # TRUNCATE the 3 tables, then seed
```

It inserts into `raw_threat_intel`, `processed_iocs` and `vulnerability_alerts`
using the same `ReplacingMergeTree` upsert semantics as the real pipeline, so
re-running never duplicates rows.

### Manual feed sync

- The ingestion **scheduler** (`ThreatIntelPipeline._scheduler`) starts a full
  sync immediately at boot, then re-runs each collector as its `poll_interval`
  elapses (RSS ~10 min, JSON ~30 min, NVD 1 h). A failure in one feed is logged
  and never aborts the others.
- `POST /api/v1/ingest/force-sync` (Bearer token) forces **all** collectors to
  run immediately — also exposed in the UI as the **Force Sync Feeds** button
  in the top bar.
- `curl -X POST http://localhost:8000/api/v1/ingest/force-sync -H "Authorization: Bearer $API_ACCESS_TOKEN"`

---

## What it does (Phase 1 + 2)

1. **Asynchronous modular ingestion engine** (`app/ingestion_engine.py`)
   Polls dozens of free feeds concurrently on one event loop, normalises every
   item into an `IntelRecord`, persists the raw text, extracts indicators, and
   fans CVEs out to the AI worker.

2. **ClickHouse storage** (`app/db_init.py`)
   Four `ReplacingMergeTree` tables partitioned by month:
   - `raw_threat_intel` — raw source text
   - `processed_iocs`   — normalised indicators (IP/hash/domain/CVE/url/ja3)
   - `vulnerability_alerts` — the **Fiche d'Alerte** (supervisor's 6 columns +
     `threat_score`)
   - `ingest_state`     — watermarks for incremental sync (NVD)

3. **AI Fiche d'Alerte engine** (`app/ai_processor.py`)
   LangChain `with_structured_output(FicheAlerteModel)` turns raw advisory text
   into a strictly typed fiche enforcing the supervisor's 4-point template:
   1. is the environment affected (versions/modules + check procedure),
   2. risk level + exploitability paths + compromise impact,
   3. public PoC/exploit availability + conditions,
   4. remediation (patch + hardening + isolation + access restriction).
   **Dedup**: if the CVE already exists, no LLM call is made — the row's
   `threat_score` is bumped via a `ReplacingMergeTree` re-insert.

4. **API for the React frontend** (`app/main.py` + `app/routers/`)
   - `GET  /health`
   - `GET  /api/v1/alerts` · `/api/v1/alerts/{cve}` · `/api/v1/alerts/stats`
   - `GET  /api/v1/feeds` · `/api/v1/feeds/sources` · `/feeds/categories` · `/feeds/timeline`
   - `GET  /api/v1/iocs`   · `/api/v1/iocs/{indicator}` · `/api/v1/iocs/stats`
   - `GET  /api/v1/enrich/{ip}` — free Shodan InternetDB proxy (CORS workaround)
   - `POST /api/v1/ingest` *(Bearer token)* — manual "sync now"
   - `POST /api/v1/ingest/force-sync` *(Bearer token)* — force a FULL sync of every collector
     (runs in parallel; per-feed failures are isolated + logged, never a 500)
   - `POST /api/v1/process` *(Bearer token)* — raw text → fiche on demand

---

## Frontend (Phase 3)

A dark-first React 18 + Vite + Tailwind + Recharts dashboard lives in
[`frontend/`](frontend/). It reads the API contract above directly (ClickHouse
behind it) and is served **same-origin** by FastAPI once built.

```bash
cd frontend
cp .env.example .env      # optional: set VITE_API_TOKEN to match API_ACCESS_TOKEN
npm install

# Development (Vite dev server on :5173, proxies /api to :8000)
npm run dev

# Production build -> emits ../web/dist, auto-served by FastAPI on :8000
npm run build
```

Views: Executive Overview (KPIs + charts + live feed ticker), Live Threat
Feeds (filter + one-click IoC copy + generate fiche), Fiches d'Alerte (the
4-point viewer + PDF/STIX 2.1 export), IoC & Shodan lookup, and Dark Web /
Telegram monitor.

---

## Collectors

| Collector                | Source                                        | Free? |
|--------------------------|-----------------------------------------------|-------|
| `CisaCollector`          | CISA KEV catalog + advisories (JSON)          | ✔ |
| `CertFRCollector`        | CERT-FR RSS/Atom                              | ✔ |
| `CertEUCollector`        | CERT-EU RSS/Atom                              | ✔ |
| `NewsCollector`          | The Hacker News, Cybercrime News RSS          | ✔ |
| `NvdCollector`           | NIST NVD v2 API (incremental, rate-limited)   | ✔ (free key optional) |
| `ShodanFreeCollector`    | `internetdb.shodan.io` IP enrichment          | ✔ (no key) |
| `DarkWebCollector`       | Tor `.onion` scraping (SOCKS5) + Telegram hook | ✔ |
| `UrlhausCollector`       | abuse.ch URLhaus (malicious URLs)             | ✔ |
| `ThreatFoxCollector`     | abuse.ch ThreatFox (malware IOCs)             | ✔ |
| `FeodoTrackerCollector`  | abuse.ch botnet C2 IP blocklist               | ✔ |
| `SslblJa3Collector`      | abuse.ch SSLBL JA3 fingerprints               | ✔ |
| `BlocklistDeCollector`   | lists.blocklist.de attacker IPs               | ✔ |
| `SpamhausDropCollector`  | Spamhaus DROP / EDROP netblocks               | ✔ |
| `OpenPhishCollector`     | OpenPhish phishing URL feed                   | ✔ |
| `AlienVaultOTXCollector` | OTX threat pulses                             | ✔ (free key) |
| `MispCollector`          | MISP events (self-hosted)                     | ✔ |

---

## Configuration (`.env`)

Key knobs — see [`.env.example`](.env.example) for all of them:

- **LLM**: the engine auto-selects the first available provider —
  `GROQ_API_KEY` (free, console.groq.com) → `GEMINI_API_KEY` (free, Google
  AI Studio: aistudio.google.com/apikey) → local Ollama. Force one with
  `LLM_PROVIDER=groq|gemini|ollama`.
- **NVD**: set `NVD_API_KEY` (free from NIST) to raise quota 5 → 50 req/30s.
- **Tor**: `TOR_PROXY=socks5h://127.0.0.1:9050` and `DARKWEB_ENABLED=true`.
- **Telegram**: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHANNEL` (free Bot API).
- **OTX / MISP**: optional free keys; collectors auto-disable when unset.

---

## Useful queries (ClickHouse)

```sql
-- Latest 10 alerts, one row per CVE (FINAL applies dedup)
SELECT vuln_cve, jsonExtractString(risk_level,'risk_level') AS rl, threat_score
FROM cti.vulnerability_alerts FINAL
ORDER BY ts DESC LIMIT 10;

-- IOC type distribution
SELECT type, count() FROM cti.processed_iocs FINAL GROUP BY type ORDER BY count() DESC;

-- Drop a partition for retention (e.g. a full month)
ALTER TABLE cti.raw_threat_intel DROP PARTITION '202607';
```

---

## Project layout

```
adr/                         # Uber-format architecture decision records
├── 0001-use-clickhouse-and-fastapi-for-cti.md
└── 0002-ai-structured-extraction-for-fiches-d-alerte.md
app/
├── config.py                # typed settings from .env
├── db.py                    # ClickHouse client factories + helpers
├── db_init.py               # schema bootstrap (partitioned ReplacingMergeTree)
├── ingestion_engine.py      # BaseCollector + 16 collectors + pipeline
├── ai_processor.py          # FicheAlerteModel + dedup/upsert logic
├── main.py                  # FastAPI entry (lifespan, CORS, SPA mount)
└── routers/                 # alerts, feeds, iocs, enrich, ingest
frontend/                    # Phase 3 React dashboard (build -> ../web/dist)
├── src/components/          # ui primitives, layout, dashboard, feeds, vulnerabilities
├── src/pages/               # Dashboard, Feeds, Vulnerabilities, IoCSearch, DarkWeb
├── src/services/api.js      # axios wrappers mapped to the FastAPI endpoints
└── src/hooks/useApi.js      # useApi / useAsync data hooks
docker-compose.yml           # ClickHouse (+ optional Ollama)
requirements.txt
.env.example
```

## Security notes

- Bearer token protects `POST /api/v1/*` — change `API_ACCESS_TOKEN` in prod.
- Tor DNS resolution happens inside Tor (`socks5h://`), never leaks.
- The `DarkWebCollector` defaults are best-effort; review the onion URL list
  and Telegram channel before enabling.
# CTI-CSIRT
