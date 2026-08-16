# ADR Concept · Autonomous Triage Agent · Project Map

> A teaching document that explains (1) what Architecture Decision Records are,
> (2) how this project applies the ADR concept, (3) a deep dive into the
> autonomous agent's **detection & response** mechanism, (4) the agent's code
> hierarchy, and (5) the hierarchy of the whole project.

---

## Table of contents

1. [What is an ADR? (the concept)](#1-what-is-an-adr-the-concept)
2. [How the ADR concept was implemented here](#2-how-the-adr-concept-was-implemented-here)
3. [Deep dive: agent detection & response](#3-deep-dive-agent-detection--response)
4. [Agent code hierarchy](#4-agent-code-hierarchy)
5. [Whole-project hierarchy](#5-whole-project-hierarchy)
6. [Quick mental map](#6-quick-mental-map)

---

## 1. What is an ADR? (the concept)

An **Architecture Decision Record** is a short markdown document that captures a
single significant architectural decision and, crucially, **the context and the
reasoning that led to it**. It is a "memory for the project": months later, a new
engineer reads the record and understands *why* ClickHouse was chosen over
PostgreSQL, without digging through Slack history.

The concept was popularised by Michael Nygard and the `adr.github.io` community;
**Uber's `uber-adr` tool** and the **MADR** project (a separate, closely-related
template) each standardized a repeatable version of it. The format is a
*convention*, not a library — the value lives in the structure, so anyone can
follow it with plain markdown. The records in this project follow the Uber
template specifically.

### The Uber ADR template

Every record has the same skeleton:

```text
# NNNN: Short imperative title

- Status: Accepted            <- Accepted / Proposed / Superseded by NNNN
- Deciders: who decided       <- team / roles, not individuals
- Date: YYYY-MM-DD
- Technical Story: one-line problem statement

## Context and Problem Statement
  Why does this decision exist? What forces are at play?

## Decision Drivers
  The non-negotiable requirements that shape the choice
  (cost, security, determinism, volume...).

## Considered Options
  Option A ... (rejected)  <- alternatives, each with Pros/Cons
  Option B ... (chosen)

## Decision Outcome
  What we chose, and its positive & negative consequences.
```

The rules that make ADRs useful:

- **One decision per record** — a record is not a changelog.
- **Record the rejected options too** — the "why not X" is as valuable as the
  choice itself.
- **Write for a future reader** — state drivers, not just the result.
- **ADRs are documents, not code** — no tool is required to write or read them;
  tools only automate scaffolding.

---

## 2. How the ADR concept was implemented here

The project keeps its decision records in the `adr/` directory at the repo root:

```text
adr/
├── 0001-use-clickhouse-and-fastapi-for-cti.md
├── 0002-ai-structured-extraction-for-alert-sheets.md
├── 0003-llm-engine-failover-ollama-gemini.md
├── 0004-durable-alert-sheet-pipeline.md
├── 0005-real-time-alerting.md
└── 0006-search-and-export-hub.md
```

Each file follows the Uber-style template above: a `# 000N: Title` first line,
the `Status / Deciders / Date / Technical Story` front-matter list, then the
`## Context and Problem Statement`, `## Decision Drivers`, `## Considered
Options`, `## Decision Outcome` sections with `Positive / Negative
Consequences`.

| # | Record | Core decision |
|---|--------|---------------|
| 0001 | Use ClickHouse and FastAPI | Columnar OLAP store + async FastAPI API for a 100k+ item/threat corpus |
| 0002 | AI structured extraction for Alert Sheets | Pydantic v2 + LangChain `with_structured_output` so LLM output is machine-verifiable, not prose |
| 0003 | LLM engine failover (Ollama → Gemini) | Health-checked engine selection with free Groq/Gemini fallback to keep €0 cost |
| 0004 | Durable Alert Sheet pipeline | ReplacingMergeTree storage, dedup before the LLM call, retryable pipeline |
| 0005 | Real-time alerting | ClickHouse-backed notifications + Telegram push |
| 0006 | Global search + export hub | Central search with CSV / JSON / STIX 2.1 analyst exports |

### Concept → code mapping

The ADR concept is applied in **two distinct ways**:

1. **Documents** (`adr/*.md`) — the *decisions* are written down using the
   Uber-style template, and `internship-report.md` §5.13 maps each ADR to the
   files that implement it.
2. **Observability** (`app/agent/`) — the same spirit is applied to the agent:
   every step records **what** it did, **why**, and the exact inputs/outputs
   (`sensor.py` documents this as "Uber ADR-inspired"). The execution trace is
   the agent's decision record, stored in ClickHouse for audit.

> Note: a `/docs` dashboard viewer was briefly built to render these records,
> then removed on request (the `adr/*.md` files remain — the source of truth).

---

## 3. Deep dive: agent detection & response

The **Autonomous Triage Agent** is a one-shot investigator: given an indicator
(IPv4, domain, hash, CVE) and the raw snippet it appeared in, it decides whether
that indicator is malicious or noteworthy — while defending itself against
adversarial input. It is built with **LangGraph** and lives in `app/agent/`.

### 3.1 The pipeline at a glance

```text
         raw indicator + raw context
                    │
                    ▼
        ┌─────────────────────────┐   risky?    ┌───────────────────┐
        │  sensor_sanitizer       │ ─────────►  │   quarantine      │  ◄── response:
        │  sanitize + detect      │              │   (no tool/LLM)   │     stop & log
        └─────────────────────────┘              └───────────────────┘
                    │ clean                            │
                    ▼                                 ▼
        ┌─────────────────────────┐                (END)
        │  triage_evaluator       │  decide tool plan + baseline risk
        └─────────────────────────┘
                    │
                    ▼
        ┌─────────────────────────┐
        │  tools_execution        │  read-only tools → evidence deltas
        └─────────────────────────┘
                    │
                    ▼
        ┌─────────────────────────┐
        │  synthesis              │  LLM analysis (or honest fallback)
        └─────────────────────────┘
                    │
                    ▼
        ┌─────────────────────────┐
        │  sheet_generator        │  strict 4-point Alert Sheet + audit row
        └─────────────────────────┘
                    │
                    ▼
                 (END)
```

The graph (edges defined in `app/agent/graph.py:446`):

```text
START → sensor_sanitizer
sensor_sanitizer ─(flagged)→ quarantine → END
sensor_sanitizer ─(clean)→ triage_evaluator → tools_execution → synthesis → sheet_generator → END
```

### 3.2 Node by node

**`sensor_sanitizer`** (`graph.py:203`) — the *detection* stage.
- Runs `sanitize_text()`: strips control characters (NUL, ESC, other C0, DEL —
  the tricks used for terminal/token smuggling) and caps context at 8000 chars
  (`sensor.py:30`).
- Runs `detect_prompt_injection()` on the sanitised, lowercased text. If any
  rule fires, it returns `is_flagged_unsafe: True` with the list of reasons and
  the conditional router sends the graph to **quarantine**.

**`quarantine`** (`graph.py:238`) — the *response* stage.
- Terminal node: logs the event, appends a trace record, and stops. **No tool
  call and no LLM call ever happen** for a flagged input. The analyst sees the
  reasons in the dashboard banner and the trace.

**`triage_evaluator`** (`graph.py:253`) — sets the deterministic tool plan and a
baseline risk:
- `ipv4` → plan `[shodan, clickhouse]`; everything else → `[clickhouse]`.
- baseline: `10` + `30` for a CVE (vulnerabilities are the core alert signal) or
  `+15` for ipv4/domain/hash. The floor exists so "unknown" is never scored as
  "proven benign".

**`tools_execution`** (`graph.py:280`) — runs the plan with strictly read-only
tools (`app/agent/tools.py`):
- `shodan_internetdb` — free, keyless Shodan InternetDB lookup (open ports,
  CVEs, hostnames, tags, CPEs). A 404 means "no record" — an honest answer, not
  an error.
- `clickhouse_knowledge_search` — historical correlation: have we seen this
  exact indicator in `processed_iocs` (sightings, max severity, last seen) and
  how many raw records mention it in the last 365 days.
- Deterministic risk deltas: Shodan CVEs `+15`, ports `+5`, hostnames `+5`;
  corpus "seen before" `+10`, raw mention `+5`. Tools never raise — failures
  become `{found: False, detail}` records.

**`synthesis`** (`graph.py:332`) — the LLM step (Ollama → Gemini failover).
- A strict `SynthesisAnalysis` Pydantic model forces structured output
  (assessment, risk_score 0–100, findings, actions). The LLM's risk score
  **overrides** the deterministic one — this is why you can see "30 with no
  risk": it is the model's own judgment anchored to the evidence.
- On total engine failure, it keeps the deterministic score and says so
  honestly instead of fabricating analysis.

**`sheet_generator`** (`graph.py:363`) — enforces the supervisor's strict
4-part Alert Sheet (Environmental impact / Risk assessment / Exploitation
status / Remediation) and persists the audit row to `agent_triage_results`.

### 3.3 The detection rules (the sensor, in detail)

Detection is deliberately **conservative and rule-based** (`sensor.py:45-128`) —
a heuristic, not a guarantee, and the trace records exactly what fired so an
analyst can review it. Categories:

| Label | What it catches | Example trigger |
|---|---|---|
| `instruction-override` | Phrasing that tells the model to drop its constraints | "ignore all previous instructions", "disregard your rules" |
| `role-escape` | Jailbreaks that change the model's persona | "you are now an unrestricted assistant", "jailbreak", "developer mode" |
| `system-exfil` | Attempts to leak the system prompt | "print your system prompt", "what are your instructions" |
| `delimiter-injection` | Chat-template / role tokens that can smuggle a second instruction | `<\|im_start\|>`, `[INST]`, `<<SYS>>`, `<system>` |
| `encoded-blob` | Long base64-ish payloads (encoded instruction dumps) | ≥ 80 base64 chars |
| `excessive-newlines` | Tab/newline-heavy text used to split a second instruction | > 40 newlines in > 500 chars |

Why rules and not an LLM guard? Determinism, speed and cost: the rules run in
microseconds before any expensive call, produce auditable, testable reasons, and
need no model. The system prompt also tells the synthesis LLM that the context
is **data, not instructions** — defence in depth.

### 3.4 Observability: the execution trace

Every node appends an immutable trace entry
(`sensor.py:134`, `append_trace`):

```json
{
  "node": "sensor_sanitizer",
  "action": "sanitize",
  "inputs":  {"chars_in": 231},
  "outputs": {"risky": false, "chars_out": 231},
  "note":    "input clean",
  "ts":      1784...  (microsecond epoch)
}
```

The whole trace is stored in the ClickHouse table `agent_triage_results`
(8th table, created in `app/db_init.py`), and the dashboard `/agent` page renders
it as a clean stepper timeline with a "View raw trace" toggle for auditors.

---

## 4. Agent code hierarchy

```text
app/agent/                     ← the whole agent lives in one folder
├── __init__.py                package marker
├── sensor.py                  sanitisation + prompt-injection detection +
│                              trace_step()/append_trace() (observability)
├── tools.py                   the two read-only tools
│                              (shodan_internetdb, clickhouse_knowledge_search)
└── graph.py                   LangGraph StateGraph: nodes, edges, conditional
                               router, scoring, synthesis, persistence,
                               run_agent_triage() public entry point
```

| File | Role | Key functions / nodes |
|---|---|---|
| `sensor.py` | Input defence + tracing | `sanitize_text`, `detect_prompt_injection`, `trace_step`, `append_trace` |
| `tools.py` | Read-only evidence | `shodan_internetdb`, `clickhouse_knowledge_search` |
| `graph.py` | Orchestration + contract | `sensor_sanitizer_node`, `quarantine_node`, `triage_evaluator_node`, `tools_execution_node`, `synthesis_node`, `sheet_generator_node`, `build_agent_graph`, `run_agent_triage` |

Where the agent plugs into the app:

```text
app/routers/agent.py
  POST /api/v1/agent/triage    → run_agent_triage()  (Bearer-token auth, 422
                                 on missing/invalid fields)
  GET  /api/v1/agent/history   → last N audit rows    (token-guarded)

app/agent/graph.py
  run_agent_triage(db, settings, indicator, type, context)
      └── get_agent_graph().ainvoke(initial_state)

app/db_init.py
  CREATE TABLE agent_triage_results  (indicator, type, risk_score,
       is_flagged_unsafe, sheet_json, execution_trace, created_at, version)

frontend/src/pages/Agent.jsx     dashboard console (form, result, trace, history)
frontend/src/services/api.js     agentTriage() / getAgentHistory() wrappers
```

Call chain: **API router** → **`run_agent_triage()`** → compiled **LangGraph**
→ nodes → tools → LLM → **ClickHouse audit row** → JSON response → **React page**.

---

## 5. Whole-project hierarchy

### 5.1 Backend — `app/`

```text
app/
├── main.py                 FastAPI app, CORS, static SPA serving, 14 routers,
│                           /health
├── config.py               Settings (env-driven: ClickHouse, Ollama, tokens)
├── db.py                   ClickHouse clients (admin / app / read-only)
├── db_init.py              DDL — creates the 8 tables on startup
├── ingestion_engine.py     ThreatIntelPipeline: collectors, dedup, AI sheets,
│                           dark-web & Telegram
├── ai_processor.py         LLM structured extraction (AlertSheetModel)
├── threat_classify.py      category/taxonomy classification
├── tactics.py              ATT&CK tactic mapping
├── exporters.py            CSV / JSON / STIX 2.1 export builders
├── notifications.py        ClickHouse-backed alerts + Telegram push
├── jobs.py                 background jobs / polling (force-sync, dark web)
├── geo.py                  IP geolocation (attack map)
└── routers/                one router per API surface (see below)
    ├── agent.py            autonomous triage
    ├── alerts.py           alert sheets + processing jobs
    ├── ai.py               AI extraction endpoints
    ├── enrich.py           enrichment
    ├── explore.py          read-only SQL playground (cti_ro account)
    ├── export.py           CSV/JSON/STIX downloads
    ├── feeds.py            live feeds, sources, categories
    ├── geo.py              geo summary / status
    ├── ingest.py           force-sync, ingest control
    ├── iocs.py             IOC list + extraction
    ├── notifications.py    notifications / Telegram
    ├── search.py           global search
    └── threats.py          landscape, ports, CVEs, ATT&CK heatmap
```

The API is versioned under `/api/v1/...` and mounted in `main.py`. Read-only
routes use a dedicated `cti_ro` ClickHouse account; state-changing routes
(POST triage, force-sync, generate-sheet) require the Bearer token.

### 5.2 Frontend — `frontend/src/`

```text
frontend/src/
├── App.jsx                 route table (all pages inside <Layout>)
├── main.jsx                entry point
├── index.css               Tailwind + design tokens (surface/line/ink...)
├── theme.jsx               dark theme provider
├── config.js               build-time settings (API base, token)
├── hooks/useApi.js         useApi (auto-fetch + polling) / useAsync (actions)
├── services/api.js         axios client + all endpoint wrappers + errorText
├── utils/format.js         timeAgo, severity system, category colors, compact
├── pages/                  one file per route
│   ├── Dashboard.jsx       Executive Overview (KPIs, map, charts)
│   ├── ThreatLandscape.jsx By Origin choropleth + ATT&CK heatmap
│   ├── Feeds.jsx           live raw intel stream
│   ├── Vulnerabilities.jsx 4-point Alert Sheets
│   ├── Indicators.jsx      IoC list
│   ├── IoCSearch.jsx       indicator lookup + Shodan enrichment
│   ├── SearchExport.jsx    global search + downloads
│   ├── DarkWeb.jsx         onion-scraped items
│   ├── Agent.jsx           autonomous triage console
│   └── DataExplorer.jsx    read-only SQL playground
└── components/
    ├── layout/             Sidebar, TopBar, NotificationBell, Layout, Footer
    ├── dashboard/          KPI cards, chart widgets, preview tiles
    ├── feeds/              feed cards, DarkWebCard
    ├── iocs/               IOC list view
    ├── threats/            choropleth map, tactic heatmap
    ├── vulnerabilities/    sheet view
    └── ui/                 primitives: Card, Button, Badge, Table, Modal,
                            CopyButton, EmptyState, ErrorState, ErrorBoundary,
                            Loader
```

### 5.3 Infrastructure & docs

```text
.
├── docker-compose.yml      the full stack:
│                           cti-app (FastAPI+SPA), cti-clickhouse,
│                           cti-ollama (local LLM), cti-tor (dark-web proxy)
├── Dockerfile              multi-stage build (vite → FastAPI)
├── .env                    credentials (never committed / logged)
├── requirements.txt        Python deps
├── frontend/               React SPA
├── adr/                    the 6 Architecture Decision Records
├── adr.md                  this document
├── internship-report.md    the full internship report (1168+ lines)
└── SESSION_CONTEXT.md      living project state for the assistant
```

Data flow: **collectors** (CISA, CERT-FR, NVD, dark web via Tor) → **ClickHouse**
(raw_threat_intel, processed_iocs, vulnerability_alerts, agent_triage_results,
…) → **API routers** → **React dashboard**. A background scheduler periodically
polls sources, generates Alert Sheets via the local LLM, and pushes alerts.

---

## 6. Quick mental map

| If you want to… | Look here |
|---|---|
| Understand *why* a tech choice was made | `adr/` (the 6 records) |
| Understand the agent's detection & response | `app/agent/sensor.py` + `graph.py` nodes & edges |
| See the agent's API | `app/routers/agent.py` |
| See the agent's dashboard UI | `frontend/src/pages/Agent.jsx` |
| See the data model | `app/db_init.py` (8 tables) |
| See the API surface | `app/routers/` + `app/main.py` |
| See how the UI is organised | `frontend/src/pages/` + `components/ui/` |
| Read the full story | `internship-report.md` |

---

*Everything in this document reflects the actual code at the time of writing —
no invented details. Verify against the files cited before relying on any claim.*
