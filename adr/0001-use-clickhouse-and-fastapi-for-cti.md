# 0001: Use ClickHouse and FastAPI for the CTI platform

- Status: Accepted
- Deciders: CSIRT engineering team, platform architect, security lead
- Date: 2026-08-09

Technical Story: The CSIRT needs a Threat Intelligence platform capable of ingesting
high-volume security feeds (CISA, CERT-FR/EU, NVD, abuse.ch, Tor scrapes, ...),
storing years of raw intel, and serving an analyst UI (React) without paying for
any commercial database or framework.

## Context and Problem Statement

The platform ingests many independent sources every few minutes. Each poll can
produce thousands of raw records and indicators. Analysts then need:

1. Fast append of raw, semi-structured threat intel with zero loss.
2. Fast point queries ("is this IOC already known?") and big analytical scans
   ("all CVE-X references in the last 12 months").
3. Cheap deduplication — the same CVE or indicator arrives from many feeds and
   must not multiply rows.
4. Date-range slicing on partitions for retention/archival policy.

The two mainstream alternatives (Flask + PostgreSQL) are both reasonable for a
CRUD app but are the wrong shape for this workload.

## Decision Drivers

- **Ingestion concurrency** — collectors perform network I/O (HTTP, SOCKS5/Tor)
  and spend most of their time waiting on sockets. Async event loops maximise
  throughput; thread-per-request sync servers waste memory.
- **Analytical volume** — raw intel is mostly append-only, column-shaped data.
- **Zero cost** — both chosen pieces of software are free/open-source and run on
  commodity hardware (or even a single laptop).
- **Team familiarity** — Python is already the team's language; we only swap the
  web framework and the storage engine.
- **Frontend future-proofing** — API must be JSON, async, and schema-validated so
  a React (Vite) SPA can consume it later.

## Considered Options

### Option A: Flask + PostgreSQL (rejected)

- Flask is synchronous by default. Collectors doing concurrent `aiohttp` fetches
  would require a second asyncio loop bridged awkwardly into the request
  lifecycle, or celery-style workers bolted on.
- PostgreSQL stores rows row-by-row on heap pages; the same JSON body ingested 5
  times from 5 feeds costs 5x storage and 5x insertion time. Columnar
  compression is absent.
- Deduplication requires manual `SELECT ... WHERE` before every insert, which
  adds a round-trip per row under load.
- No native partition-by-date slicing; partitioning exists but is bolted on via
  table inheritance / declarative partitioning and is far less ergonomic for
  retention purges.

### Option B: FastAPI + ClickHouse (chosen)

- FastAPI is ASGI/async natively: one event loop drives `aiohttp` collectors,
  the ClickHouse async client, and the LLM extraction calls concurrently.
- ClickHouse is a true OLAP engine: columnar storage + LZ4 compression makes raw
  intel feeds dramatically smaller on disk than row-oriented storage.
- `ReplacingMergeTree` gives us **idempotent upserts for free**: inserting the
  same logical key (CVE, indicator) multiple times collapses to a single row
  during background merges — exactly the dedup rule we need.
- `PARTITION BY toYYYYMM(...)` gives free date-range pruning and trivial
  retention (`ALTER TABLE ... DROP PARTITION`).

## Decision Outcome

Use **FastAPI (Python, ASGI, async)** as the API and service layer and
**ClickHouse** (`ReplacingMergeTree` + date partitioning) as the single storage
engine for raw intel, processed IOCs, and the AI-generated Alert Sheets.

### Positive Consequences

- One codebase and one event loop from socket → storage → LLM → response.
- Columnar compression and monthly partitions keep total footprint small.
- Idempotent dedup via `ReplacingMergeTree`; "update threat score" becomes a
  re-insert of the same key with a higher version, no `UPDATE` needed.
- Pydantic models (FastAPI-native) double as the contract for the future React
  frontend.

### Negative Consequences

- ClickHouse is not a general-purpose relational DB: no row-level transactions,
  no foreign keys. Mitigated because CTI data is append-mostly and idempotent.
- Async ClickHouse driver is younger than the sync one; we isolate all DB access
  behind `app/db.py` so the implementation can be swapped without touching
  collectors or routes.
- Requires ClickHouse running locally (Docker Compose provided) — a small
  operational addition compared to an embedded SQLite/Postgres dev setup.
