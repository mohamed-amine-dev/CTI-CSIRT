# 0006: Global search + analyst export hub (CSV / JSON / STIX 2.1)

- Status: Accepted
- Deciders: CSIRT engineering team, security lead, platform architect
- Date: 2026-08-10

Technical Story: Analysts need two things the platform did not yet have:
(1) a single search that covers every corpus — raw feeds, indicators and
sheets — instead of one page per table, and (2) a way to take a dataset out of
the platform (for a report, an upstream ISAC, or a supervisor briefing) in a
standard, interoperable format rather than copy-pasting from the UI.

## Context and Problem Statement

After Phase 5 the platform has six ClickHouse tables and five read-only list
endpoints, but:

1. **Search is siloed** — `/api/v1/feeds`, `/api/v1/iocs` and `/api/v1/alerts`
   each search only their own corpus. Answering "what do we know about this
   CVE/IP?" means three separate calls and manual reconciliation.
2. **No bulk export** — the only exit paths are the single-sheet PDF/STIX
   export and eyeballing the dashboard. There is no way to export a filtered
   dataset (e.g. "all HIGH alerts") or an interoperable threat-intel package.
3. **STIX coverage** — Phase 3 added per-sheet STIX 2.1 export, but indicators
   and raw feeds have no STIX representation at all.

## Decision Drivers

- **Zero cost** — all export formats must be produced from the existing read
  models with the Python standard library (`csv`, `json`); no new dependencies.
- **One query, grouped results** — search must stay a single HTTP round-trip,
  returning hits grouped by corpus so the UI can render one pane per corpus.
- **Filters follow the list endpoints** — export of a resource honours exactly
  the same filters the analyst can already apply in the UI (risk level, IoC
  type, category, unread-only, search), so "export what I'm looking at" is
  always true.
- **Standard shapes where STIX defines them** — sheets are STIX `vulnerability`
  objects, indicators are `indicator` objects with real patterns, raw feed
  items are `report` objects. Notifications have no STIX identity, so they are
  CSV/JSON only.

## Considered Options

### Option A: Rely on ClickHouse only (rejected)

Do global search with a single `UNION`/`FULL JOIN` and let analysts query
ClickHouse directly.

- Pro: no new code.
- Con: ClickHouse's natural-language search is limited (substring matching, no
  relevance ranking across tables), and requiring analysts to write SQL puts
  the data out of reach of the UI and the supervisor demo.

### Option B: Dedicated search + export routers over the existing read models (chosen)

Add `GET /api/v1/search` and `GET /api/v1/export`:

- Search runs three independent, parallelisable, `LIMIT`-bounded substring
  queries (`positionCaseInsensitive`) against `raw_threat_intel`,
  `processed_iocs` and `vulnerability_alerts`, grouped by corpus with counts.
- Export serializes a filtered dataset via `app/exporters.py`:
  - CSV — RFC-4180, Excel-safe quoting (nested objects flattened to JSON);
  - JSON — pretty array of the same flat records;
  - STIX 2.1 Bundle — `vulnerability` / `indicator` (with STIX patterns:
    `ipv4-addr`, `domain-name`, `file:hashes.*`, …) / `report` objects;
  - delivered as a streamed `StreamingResponse` with a dated
    `Content-Disposition` filename.

- Pro: zero new dependencies; search stays one round-trip; export is
  analyst/ISAC-ready; every format is derived from one flat record model so the
  code path is simple to audit.
- Con: substring search is not "semantic" — acceptable for an analyst lookup
  tool backed by a columnar store; add a dedicated search engine only if a
  later phase needs ranked/typo-tolerant search.

### Option C: Introduce an external search engine + export library (rejected)

Add Meilisearch/OpenSearch and a library like `stix2`.

- Pro: ranking, facets, fuzziness, spec-validated STIX.
- Con: new services to run and secure (violates the zero-cost, self-contained
  constraint), and a library dependency for output we can already generate with
  the stdlib. Per-request search over a few tens of thousands of rows is fine.

## Decision Outcome

Use **Option B**. `app/routers/search.py` (grouped global search),
`app/routers/export.py` (streamed bulk export with the shared filter set) and
`app/exporters.py` (pure CSV/JSON/STIX 2.1 serializers). The React app gains a
dedicated **Search & Export** view (`frontend/src/pages/SearchExport.jsx`):
one search box with a corpus filter on top, an export grid (one card per
resource with format buttons) below.

### Positive Consequences

- "What do we know about X?" is one query, one screen.
- Any filtered dataset leaves the platform as CSV, JSON or STIX 2.1 with a
  clean filename — no manual copy-paste, no SQL for analysts.
- Export reuses the existing filter grammar, so the hub can never show a filter
  the list endpoints don't understand.
- No new runtime dependencies or services.

### Negative Consequences

- STIX output is structurally valid but intentionally minimal (no SRO
  relationships, no TLP/confidence objects); downstream consumers that expect a
  fully related threat model will need to enrich it.
- Substring search scales with the table size; on very large corpora a
  dedicated search engine would be the natural successor (tracked as future
  work, not a Phase 6 requirement).
