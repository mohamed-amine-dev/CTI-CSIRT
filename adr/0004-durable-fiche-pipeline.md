# 0004: Durable AI fiche pipeline with honest status tracking

- Status: Accepted
- Deciders: CSIRT engineering team, security lead, platform architect
- Date: 2026-08-10

Technical Story: Fiches d'Alerte must not be silently dropped when the LLM rate
limit is hit or the process restarts mid-queue. The platform needs to track the
state of every fiche job, surface pending/failed CVEs honestly in the UI, and
retry failures without ever regenerating work that is already done.

## Context and Problem Statement

Phase 3 pushed every CVE-bearing record onto a plain `asyncio.Queue(maxsize=200)`
that fed a single AI worker. On a cold sync the KEV catalog alone yields ~1,600
CVEs; with Gemini free-tier throttling (~20 req/min) that backlog outlived the
queue, and the previous behaviour was:

1. **Silent drops** — a full queue logged `"AI queue full, dropping <cve>"` and
   the CVE was gone forever (until a later re-poll happened to re-find it).
2. **No retry policy** — a transient 429 / provider outage burned the CVE; the
   worker logged an error and moved on.
3. **No visibility** — analysts could not tell whether a missing fiche was
   pending, in-flight, failed, or simply never seen.
4. **Restart amnesia** — the dedup map (`_seen_cves`) lived only in memory, so a
   restart reprocessed already-done CVEs until the map was rebuilt.

## Decision Drivers

- **Honesty** — the UI must reflect the true pipeline state (pending / processing
  / done / failed), never imply every CVE has a fiche.
- **Zero data loss** — a full queue or a crash must not lose work.
- **Zero re-work** — already-generated fiches must not be regenerated after a
  restart (each one costs a rate-limited LLM call).
- **Operationality** — failed CVEs must recover by themselves (scheduler retry)
  and give analysts a manual retry lever.

## Considered Options

### Option A: Keep the in-memory queue, add a big maxsize (rejected)

Simply raise `maxsize` to, say, 10,000 so cold syncs fit.

- Pro: a one-line change.
- Con: still loses work on crash; still drops CVEs on a genuinely full queue; no
  retry policy; no analyst visibility; restart still reprocesses done CVEs.

### Option B: Durable job queue in ClickHouse + bounded in-memory queue (chosen)

Add a `fiche_pending` `ReplacingMergeTree` table (one row per CVE) as the source
of truth for every fiche job:

- **Persist before enqueue** — `_enqueue_fiche` writes `status=pending` first;
  only then is the CVE pushed to a bounded `asyncio.Queue`. A full queue leaves
  the row `pending` (nothing dropped); the scheduler drains it later.
- **Worker state machine** — `pending → processing → done | failed`. `failed`
  rows carry an `attempts` counter and `last_error`; after `ai_max_attempts`
  they stay failed, otherwise the scheduler re-enqueues them once `retry_at`
  (exponential backoff capped by `ai_retry_cooldown_minutes`) has passed.
- **Crash recovery** — on boot the dedup map is rehydrated from `vulnerability_alerts`
  (done) + `fiche_pending` (done/failed), and rows left `pending`/`processing`
  older than `ai_stale_processing_minutes` are re-enqueued.
- **Observability + control** — `GET /api/v1/ai/status` returns the honest counts
  (surfaced in the Vulnerabilities UI), and `POST /api/v1/ai/retry-failed` lets an
  analyst reset attempts and re-enqueue failures immediately.

- Pro: zero work loss, zero re-work after restart, honest UI, self-healing
  failures, cheap (one `ReplacingMergeTree` insert per CVE).
- Con: an extra table + a few writes per CVE; negligible vs. the seconds each
  LLM call takes.
- Con: replay ordering is approximate (scheduler pulls the oldest `pending` rows
  in batches of 200 per 60 s tick), which only matters during a cold-sync backlog
  and is acceptable for a free-tier platform.

## Decision Outcome

Use **Option B**. The fiche job lifecycle is owned by `fiche_pending` and driven
by `ThreatIntelPipeline` (`_enqueue_fiche`, `_ai_worker`, `_scheduler` +
`_requeue_stale_fiches`) with the free-tier rate limiter and cached Ollama probe
from `0003` protecting every generation call.

### Positive Consequences

- Fiches are never silently dropped; queue-full and failed CVEs are retried.
- Restarts are idempotent (dedup map rehydrated from ClickHouse).
- Analysts see live pending/processing/failed counts and can force a retry.
- The retry backoff (2, 4, … minutes capped by `ai_retry_cooldown_minutes`)
  rides out Gemini free-tier quota windows automatically.

### Negative Consequences

- Cold-sync backlogs drain at the rate limiter's pace (~20 fiches/min on the
  free tier); a few thousand CVEs take a couple of hours to process.
- The extra `fiche_pending` table must be included in any retention/backup story
  (`PARTITION BY toYYYYMM(updated_at)` makes monthly retention drops trivial).
