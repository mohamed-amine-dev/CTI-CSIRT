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

### Option A — Docker (recommended, everything in one command)

```bash
# Build + start the full stack: ClickHouse + Ollama (local LLM) + app.
# No .env needed — built-in defaults work out of the box.
docker compose up -d --build

# First boot pulls the llama3.2:3b model (~2 GB, one-time) — check progress:
docker compose logs -f ollama
```

Open **http://localhost:8000** — FastAPI serves both the API and the compiled
React dashboard on the same origin. No separate frontend server needed.

- The app uses `LLM_PROVIDER=ollama` (set in `docker-compose.yml`), so Fiche
  d'Alerte generation is **offline and unlimited** — no Gemini/Groq quota.
- **Token:** out of the box the API token is `change-me-in-production`, shared
  by backend and frontend automatically. To use your own, create `.env`
  (`cp .env.example .env`, set `API_ACCESS_TOKEN`) — compose passes it to both
  sides and the `app` image rebuilds with it.
- `curl http://localhost:8000/health` → `{"status":"ok", ...}`
- Stop everything: `docker compose down` (data persists in the volumes;
  `docker compose down -v` also wipes ClickHouse/Ollama data).
- Dark-web scraping is **off by default in Docker** (no Tor container). To
  enable it with Tor running on the host, uncomment the
  `extra_hosts`/`TOR_PROXY`/`DARKWEB_ENABLED` block in `docker-compose.yml`.

> Why `.env.example` → `.env` at all? `.env` is your *local* secrets file
> (real token, API keys); `.env.example` is the committed template. With
> pydantic-settings every value has a default, so the copy is **optional** —
> do it only when you want to override something.

### Option B — bare metal (ClickHouse + venv)

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
   Six `ReplacingMergeTree` tables partitioned by month:
   - `raw_threat_intel` — raw source text
   - `processed_iocs`   — normalised indicators (IP/hash/domain/CVE/url/ja3)
   - `vulnerability_alerts` — the **Fiche d'Alerte** (supervisor's 6 columns +
     `threat_score`)
   - `ingest_state`     — watermarks for incremental sync (NVD)
   - `fiche_pending`    — durable AI job queue (`pending|processing|done|failed`
     per CVE, with `attempts` / `last_error` / `retry_at` for honest retries)
   - `notifications`    — real-time alert feed (Phase 5): severity/title/body/
     cve/source + `read` flag, backing the top-bar bell and Telegram push

3. **AI Fiche d'Alerte engine** (`app/ai_processor.py`)
   LangChain `with_structured_output(FicheAlerteModel)` turns raw advisory text
   into a strictly typed fiche enforcing the supervisor's 4-point template:
   1. is the environment affected (versions/modules + check procedure),
   2. risk level + exploitability paths + compromise impact,
   3. public PoC/exploit availability + conditions,
   4. remediation (patch + hardening + isolation + access restriction).
   **Dedup**: if the CVE already exists, no LLM call is made — the row's
   `threat_score` is bumped via a `ReplacingMergeTree` re-insert.

4. **Reliable fiche pipeline** (`app/ingestion_engine.py`, Phase 4)
   Fiches are never silently dropped. Every CVE is tracked in `fiche_pending`
   and the UI surfaces the honest pipeline state:
   - free-tier **rate limiter** + retry with jittered exponential backoff;
   - a CVE that keeps failing is marked `failed` (with attempt count + reason)
     and **auto-retried** by the scheduler once its cooldown elapses;
   - `pending`/`processing` rows left by a crash are re-enqueued on restart;
   - the dedup map is rehydrated from ClickHouse at boot, so restarts never
     regenerate finished fiches.

5. **Real-time alerting** (`app/notifications.py`, Phase 5)
   Every **new** fiche meeting `ALERT_MIN_RISK` (default HIGH/CRITICAL) — or any
   CVE from a KEV source — fires a notification that is stored in ClickHouse
   (top-bar bell, unread badge) and pushed to the configured Telegram channel.
   Best-effort by design: a failed persist or Telegram outage never touches the
   pipeline. `POST /api/v1/notifications/test` sends a demo alert end-to-end.

 6. **Search & Export hub** (`app/routers/search.py` + `app/routers/export.py`
    + `app/exporters.py`, Phase 6)
    One query searches **feeds + indicators + fiches** in a single call
    (`GET /api/v1/search?q=…&kind=…`), grouped by corpus for the dedicated
    frontend page. Any read model can be bulk-exported to **CSV / JSON /
    STIX 2.1** (`GET /api/v1/export?resource=…&format=…`): fiches become STIX
    `vulnerability` objects, iocs become `indicator` objects (with STIX
    patterns), feeds become `report` objects — analyst-ready for sharing.

 7. **API for the React frontend** (`app/main.py` + `app/routers/`)
   - `GET  /health`
   - `GET  /api/v1/alerts` · `/api/v1/alerts/{cve}` · `/api/v1/alerts/stats`
   - `GET  /api/v1/feeds` · `/api/v1/feeds/sources` · `/feeds/categories` · `/feeds/timeline`
   - `GET  /api/v1/iocs`   · `/api/v1/iocs/{indicator}` · `/api/v1/iocs/stats`
   - `GET  /api/v1/enrich/{ip}` — free Shodan InternetDB proxy (CORS workaround)
    - `GET  /api/v1/ai/status` — fiche pipeline counts (pending/processing/done/failed)
    - `POST /api/v1/ai/retry-failed` *(Bearer token)* — manually requeue failed
      fiches (optionally `?cve=CVE-…` for a single one); resets their attempts
    - `GET  /api/v1/search` — global search (`q`, optional `kind=feeds|iocs|alerts`)
    - `GET  /api/v1/export` — bulk export (`resource` + `format=csv|json|stix`,
      same filters as the list endpoints; streamed with a `Content-Disposition` filename)
   - `GET  /api/v1/notifications` · `/api/v1/notifications/unread-count`
   - `POST /api/v1/notifications/read-all` · `/notifications/{id}/read` ·
     `/notifications/test` *(Bearer token)*
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
4-point viewer + PDF/STIX 2.1 export), IoC & Shodan lookup, **Search & Export**
(global search + CSV/JSON/STIX bulk downloads), and Dark Web /
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
- **Tor**: run `tools/start_tor.sh` (rootless launcher — downloads the official
  Tor expert bundle on first use and starts a SOCKS5 proxy on `127.0.0.1:9050`),
  then set `TOR_PROXY=socks5h://127.0.0.1:9050` and `DARKWEB_ENABLED=true`.
  Onion search bases live in `DARKWEB_ONION_URLS` (JSON list; defaults to
  DuckDuckGo's public onion index, a clean non-offensive site that validates the
  pipeline). Threat queries to run against each base live in `DARKWEB_QUERIES`
  (JSON list); each query's result links + snippets are stored as individual
  intel items instead of the raw search-page boilerplate. Leave `DARKWEB_QUERIES`
  empty to fall back to scraping the onion root page verbatim.
  Requires outbound TCP to the Tor network.
- **Telegram**: deferred — set `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHANNEL` (free
  Bot API) when you want the channel hook enabled.
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
├── 0002-ai-structured-extraction-for-fiches-d-alerte.md
├── 0003-llm-engine-failover-ollama-gemini.md
├── 0004-durable-fiche-pipeline.md
├── 0005-real-time-alerting.md
└── 0006-search-and-export-hub.md
app/
├── config.py                # typed settings from .env
├── db.py                    # ClickHouse client factories + helpers
├── db_init.py               # schema bootstrap (partitioned ReplacingMergeTree)
├── ingestion_engine.py      # BaseCollector + 16 collectors + pipeline
├── ai_processor.py          # FicheAlerteModel + dedup/upsert logic
├── exporters.py             # CSV / JSON / STIX 2.1 serializers (Phase 6)
├── main.py                  # FastAPI entry (lifespan, CORS, SPA mount)
└── routers/                 # alerts, feeds, iocs, enrich, ai, notifications,
                             # search, export, ingest
frontend/                    # Phase 3 React dashboard (build -> ../web/dist)
├── src/components/          # ui primitives, layout, dashboard, feeds, vulnerabilities
├── src/pages/               # Dashboard, Feeds, Vulnerabilities, IoCSearch, SearchExport, DarkWeb
├── src/services/api.js      # axios wrappers mapped to the FastAPI endpoints
└── src/hooks/useApi.js      # useApi / useAsync data hooks
docker-compose.yml           # full stack: clickhouse + ollama + app (one command)
Dockerfile                   # single image: React SPA + FastAPI backend
requirements.txt
.env.example
```

## Security notes

- Bearer token protects `POST /api/v1/*` — change `API_ACCESS_TOKEN` in prod.
- Tor DNS resolution happens inside Tor (`socks5h://`), never leaks.
- The `DarkWebCollector` defaults are best-effort; review the onion URL list
  and Telegram channel before enabling.
# CTI-CSIRT
