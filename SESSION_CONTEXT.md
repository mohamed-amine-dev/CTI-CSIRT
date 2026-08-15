# SESSION CONTEXT — Argus CTI platform (handoff for the next session)

> **Read this first.** This file gives a new session full context on the
> project: what exists, what's in flight, how to run & verify, and the rules to
> follow. The detailed technical walkthrough is `internship-report.md`; the
> architecture decisions are in `adr/`.

---

## 1. Project at a glance

- **What**: a zero-cost Cyber Threat Intelligence (CTI) platform for a CSIRT
  team. Ingests free threat feeds → stores in ClickHouse → AI turns every CVE
  into a structured "Alert Sheet" (supervisor's 4-point template) → web
  dashboard to browse/search/visualise/export.
- **Location**: `/home/ouallali/internship` (working dir).
- **Stack**: Python FastAPI (async) + ClickHouse + LangChain LLM
  (Ollama local → Gemini/Groq free tiers) + React 18/Vite/Tailwind/Recharts/D3 +
  ipwho.is geolocation + Tor dark-web scraping. Deployed via Docker Compose.
- **Hard rules (from the supervisor briefs)**: never fabricate data; ask before
  assuming a credential or a design decision you have no direction on; verify
  everything actually runs before reporting done. Keep everything at €0.

## 2. Current state of the codebase

Everything below is **implemented in source** and built into `web/dist`:

- **Ingestion**: 16 collectors (CISA KEV/advisories, CERT-FR, CERT-EU, News,
  NVD incremental w/ watermark, Shodan InternetDB, DarkWeb via Tor + Telegram,
  URLhaus, ThreatFox, Feodo C2, SSLBL-JA3, blocklist.de, Spamhaus DROP,
  OpenPhish, OTX, MISP). All in `app/ingestion_engine.py`.
- **Storage**: 7 ClickHouse tables, all `ReplacingMergeTree` partitioned by
  month (raw_threat_intel, processed_iocs, vulnerability_alerts, ingest_state,
  alert_sheet_pending, notifications, ip_geo_cache). See `app/db_init.py`.
- **AI worker**: `app/ai_processor.py` — strict Pydantic schema
  `AlertSheetModel`, provider failover, global rate limiter, backoff,
  English-only guard, CVSS-overrides-risk, dedup via ReplacingMergeTree.
- **Durable pipeline**: `alert_sheet_pending` job queue with pending/processing/
  done/failed + auto-retry + crash recovery.
- **Alerting**: `app/notifications.py` — risk-threshold + KEV alerts, in-app
  bell, Telegram ready-but-off.
- **Search & Export**: `app/routers/search.py` + `export.py` + `exporters.py`
  (CSV / JSON / STIX 2.1).
- **Data Explorer**: read-only SQL playground via `cti_ro` account.
- **Threat Landscape module (newest, Brief #3)**:
  - `app/routers/geo.py` — `/api/v1/geo/summary`, `/api/v1/geo/status`.
  - `app/routers/threats.py` — `/api/v1/threats/landscape|ports|cves|heatmap`.
  - `app/geo.py` — GeoEnricher background task (ipwho.is, per-IP cache,
    monthly quota guard 9k/10k, negative caching, backoff).
  - `app/tactics.py` — analyst-owned category → ATT&CK tactic table.
  - `app/threat_classify.py` — deterministic threat-category classifier.
  - `frontend/src/pages/ThreatLandscape.jsx` — two tabs (By Origin choropleth /
    By Technique heatmap) with 24h/7d/30d/60d range switch + drill-through.
  - `frontend/src/components/threats/ChoroplethMap.jsx` (D3 + world-atlas
    TopoJSON), `TacticHeatmap.jsx`.
  - `frontend/src/components/dashboard/ThreatLandscapePreviews.jsx` — the two
    Executive Overview preview tiles ("Open →" into the full page).
  - `frontend/src/services/api.js` — `getGeoSummary`, `getGeoStatus`,
    `getTacticHeatmap`, etc.
  - `frontend/src/pages/Indicators.jsx` + `iocs/IocListView.jsx` — country
    drill-down via `?country=XX`.
  - New frontend deps added & lockfile updated: `d3`, `d3-geo`,
    `topojson-client`, `world-atlas` (all in `frontend/package.json`).
- **Autonomous Triage Agent (newest work, not yet part of the briefs)**:
  - `app/agent/sensor.py` — sanitisation + prompt-injection detection + trace logger.
  - `app/agent/tools.py` — read-only tools: Shodan InternetDB + ClickHouse corpus search.
  - `app/agent/graph.py` — LangGraph StateGraph (sensor → evaluator → tools →
    synthesis → sheet; quarantine path), `run_agent_triage()` entry point.
  - `app/routers/agent.py` — `POST /api/v1/agent/triage` (bearer-token auth,
    per-type indicator validation, `context` required) + `GET /api/v1/agent/history`
    (read-only audit trail, token-guarded).
  - `app/routers/docs.py` — `GET /api/v1/docs/adr` (list) + `/api/v1/docs/adr/{num}`
    (raw markdown), serves the `adr/` directory (Dockerfile `COPY adr ./adr`,
    `.dockerignore` re-includes `adr/*.md`).
  - `agent_triage_results` table added to `app/db_init.py` (8th table, audit trail).
  - **Dashboard pages**: `/agent` (Autonomous Triage — form + verdict/risk/trace +
    audit history; client waits without the 30 s axios timeout since a run can take
    minutes under LLM throttling) and `/docs` (ADR viewer with a dependency-free
    markdown renderer). Both verified live via the rebuilt app image.
  - **Bug fixed while wiring**: node params must be typed `RunnableConfig`, not
    `dict`, or LangGraph won't inject `config` (500 → fixed → verified HTTP 200).
  - Verified live: 401/422 validation, prompt-injection quarantine, full 5-node
    run on a real IP with persisted audit row. See `internship-report.md` §10.
  - Known limitation: `llama3.2:3b` structured output is flaky → synthesis can
    fall back to the deterministic baseline (by design, honest response).

## 3. Brief #3 checklist status

| Item | Status |
|---|---|
| New "Threat Landscape" sidebar page with two tabs | ✅ done in source |
| Choropleth (D3 + world-atlas, ipwho.is, per-IP ClickHouse cache, rate/backoff) | ✅ done in source |
| Click country → filtered IoC list (reuses IocListView) | ✅ done |
| ATT&CK tactic heatmap with explicit category→tactic table, Unclassified column | ✅ done |
| Preview tiles on Executive Overview (map thumbnail + top-3 tactics) with links | ✅ done |
| Branding update (name/logo/favicon/PDF/footer) | ⚠️ **DO NOT implement without user direction** — current name "Argus CTI" is in use but NOT confirmed |
| Redeploy so the running instance serves the new code | ✅ **DONE — stack is UP and verified (2026-08-15)** |
| Re-verify live geolocated points + real tactic counts after redeploy | ✅ **DONE** — geo: 858 cached (832 ok / 26 fail, 62 countries); heatmap real counts |

## 4. Deployment status & how to run

**The full Docker stack is currently UP and healthy** (cti-app, cti-clickhouse,
cti-ollama, cti-tor all running; verified 2026-08-15). The running `app` image
contains the newest code (agent module included).

To rebuild + restart with the latest source (only the `app` image rebuilds):

```bash
docker compose up -d --build
```

Notes:
- The current user IS in the docker group → no `sudo` needed. (Fallback:
  `sudo docker …` if permissions change.)
- Only the `app` image rebuilds; clickhouse/ollama/tor images are untouched.
- ClickHouse data persists in the named volume `cti_clickhouse_data` (the
  corpus + geo cache survive restarts).
- First boot of `ollama` pulls `llama3.2:3b` (~2 GB, one-time).
- `.env` at repo root is **fully populated with real credentials**
  (GROQ/GEMINI/TELEGRAM/NVD/OTX/API token…). Never print, log or commit those
  values.

Health check after boot:
```bash
curl -s http://localhost:8000/health          # expect {"status":"ok",...}
curl -s http://localhost:8000/api/v1/geo/summary?days=60
curl -s http://localhost:8000/api/v1/threats/heatmap?days=60
```

## 5. Verification (evidence seen so far)

Live stack, re-verified 2026-08-15:

- `raw_threat_intel` ≈ **223k rows** across all feed families; feeds still
  landing live (CERT-FR +80, NEWS +65, CERT-EU +10 in one poll cycle).
- `ip_geo_cache` = **858 cached** (832 `ok`, 26 negative-cached `fail`), 62
  countries, monthly budget 858/9000. `/api/v1/geo/summary` returns real
  per-country counts (US 288, CN 133, FR 43).
- `/api/v1/threats/heatmap` returned real category counts (Ransomware,
  Exploit/PoC, Botnet, Phishing Kit…) mapped via the analyst table.
- `web/dist` holds the NEW build (`<title>Argus CTI — Threat
  Intelligence</title>`).
- **Agent** (`POST /api/v1/agent/triage`) verified: 401/422 validation,
  prompt-injection → quarantine, real IP → HTTP 200 + full trace + persisted
  audit row in `agent_triage_results`. Fixed the `RunnableConfig` bug along
  the way (was 500).

## 6. Key files (map)

- `app/main.py` — FastAPI entry, lifespan, SPA mount, router wiring.
- `app/config.py` — all settings (pydantic-settings, `.env`).
- `app/db.py` — ClickHouse clients (sync/async/read-only).
- `app/db_init.py` — schema DDL (8 tables) + migration.
- `app/ingestion_engine.py` — collectors + pipeline + IOC extraction.
- `app/ai_processor.py` — sheet generation, dedup, failover.
- `app/geo.py` — GeoEnricher.
- `app/threat_classify.py`, `app/tactics.py` — deterministic classifiers.
- `app/agent/` — sensor.py (sanitise + prompt-injection), tools.py (read-only
  Shodan + corpus search), graph.py (LangGraph triage, `run_agent_triage()`).
- `app/exporters.py` — CSV/JSON/STIX.
- `app/routers/` — alerts, feeds, iocs, enrich, ai, notifications, search,
  export, ingest, explore, threats, geo, agent.
- `frontend/src/services/api.js` — endpoint wrappers.
- `frontend/src/pages/ThreatLandscape.jsx`, `components/threats/*`,
  `components/dashboard/ThreatLandscapePreviews.jsx`.
- `docker-compose.yml`, `Dockerfile` — deployment.
- `internship-report.md` — the full walkthrough/report the user requested.
- `adr/` — 6 architecture decision records.

## 7. Gotchas / learnings (don't re-discover these)

- The app container connects to ClickHouse as **`clickhouse:8123` on the compose
  network**, NOT via the published host port. Host `127.0.0.1:8123` is only a
  mirror when the port binding is active.
- Geolocation: ip-api.com is HTTP-only and this host blocks outbound HTTP —
  **ipwho.is (HTTPS) is the provider**. Every IP is cached once ever; monthly
  budget is 9,000 of the free 10,000.
- `ReplacingMergeTree` + `version` (microsecond epoch) = idempotent upsert:
  re-inserting the same key with a higher version updates in place. Use `FINAL`
  on reads.
- `npm run build` emits into `../web/dist` (relative outDir); Docker rebuilds
  the SPA inside the image, so local `web/dist` is only for bare-metal runs.
- NVD collector uses incremental sync via `ingest_state` watermark.
- Free-tier LLM safety: global `ai_min_interval_seconds` throttle + per-engine
  backoff + 2s Ollama health probe (30s cache) + engine timeout.
- Threat categories & ATT&CK mapping are deterministic tables — never let an
  LLM guess them (fabrication rule).

## 8. Open questions for the user

1. **Branding**: the name **"Argus CTI"** is already used everywhere (sidebar,
   browser title, README, API title). Confirm it or provide the real name +
   logo/color direction before any branding change (Brief #3 rule).
2. **Telegram alerts** are implemented but disabled (`ALERT_TELEGRAM=false`),
   even though `.env` has a bot token — ask whether to enable.
3. Whether to run Option A (Docker, recommended) or bare metal for future
   sessions.

## 9. First actions for the next session

1. Read this file, then `internship-report.md` if depth is needed.
2. The stack is already **UP** (verified 2026-08-15). To deploy new source:
   `docker compose up -d --build` (no `sudo` needed — user is in the docker group).
3. Verify `/health`, `/api/v1/geo/summary`, `/api/v1/threats/heatmap`,
   `/api/v1/geo/status`.
4. If the user confirmed branding, apply it in one pass (sidebar, `<title>`,
   favicon, PDF/report headers, footer).
5. Continue from the open questions or the suggestions in
   `internship-report.md` §13.
