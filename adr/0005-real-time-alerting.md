# 0005: Real-time alerting with ClickHouse-backed notifications + Telegram push

- Status: Accepted
- Deciders: CSIRT engineering team, security lead, platform architect
- Date: 2026-08-10

Technical Story: A CSIRT must notice a new CRITICAL/HIGH vulnerability or a
newly catalogued known-exploited CVE within minutes, without watching the
dashboard. The platform needs an outbound notification channel (in-app + push)
that fires on genuinely new, high-priority findings and never risks the
ingestion pipeline.

## Context and Problem Statement

After Phase 4 the platform tracks every fiche job honestly, but nothing *tells*
the analyst about new findings:

1. **No push channel** — Telegram was only an *inbound* hook (the DarkWeb
   collector reads channel messages); there was no outbound alerting.
2. **Alert noise** — KEV re-syncs revisit ~1,700 CVEs every poll; alerting on
   every sighting would spam a channel. Alerts must fire only for **new** fiches
   that cross a risk threshold (or any KEV-sourced CVE, which is inherently
   urgent).
3. **Reliability budget** — alerting must be best-effort: a Telegram outage or a
   ClickHouse hiccup must never fail the fiche generation that triggered it.
4. **Read/ack lifecycle** — analysts need to see unread alerts in the UI and
   mark them read, which implies persistence + a small state machine.

## Decision Drivers

- **Zero cost** — reuse the existing Telegram Bot API (already configured for
  ingestion) as the only push channel; no SMS/email provider.
- **Timeliness** — the alert fires inline in the fiche worker at the moment a
  new high-risk fiche exists, so latency ≈ one LLM call.
- **Non-blocking** — the Telegram HTTP call is fire-and-forget (`asyncio.create_task`),
  never awaited by the worker.
- **Honest, ackable state** — notifications are rows in ClickHouse (auditable,
  partitionable for retention), with an unread count for the top-bar badge.

## Considered Options

### Option A: Webhooks/email to a third-party alerting service (rejected)

Push to a generic webhook (ntfy.sh, Slack) or SMTP.

- Pro: mature delivery + retries.
- Con: new external dependency + credentials; Slack/ntfy are not uniformly free;
  SMTP needs a relay and adds config surface. Telegram was already configured.

### Option B: ClickHouse notifications table + Telegram push (chosen)

Add a `notifications` `ReplacingMergeTree` (one row per alert, immutable except
the `read` flag, which is flipped by re-inserting the same `id` with a higher
`version`). The `NotificationService`:

- `notify()` persists the row, then schedules the Telegram push off the hot path;
- the fiche worker calls it only on the **generation** path
  (`isinstance(result, FicheAlerteModel)`) — deduplicated re-sightings (a dict
  from `_upsert_score`) never re-alert;
- thresholds: `risk >= ALERT_MIN_RISK` via a `RiskAssessment` enum order, OR
  `source` is `CISA-KEV`/`CISA-ADV` (with `ALERT_KEV_ALWAYS`);
- read lifecycle: `mark_read` / `mark_all_read` re-insert flipped rows;
  `GET /unread-count` powers the bell badge.

- Pro: zero new dependencies, uses the existing free Telegram bot, alerts are
  auditable + partitionable like every other table, unread state is simple.
- Pro: never blocks or fails the pipeline (persist errors are caught; push is
  fire-and-forget with a 15 s HTTP timeout).
- Con: Telegram `sendMessage` has no built-in retry — mitigated by logging the
  failure and by the in-app notification centre being the source of truth.

### Option C: In-memory event bus + browser notification (rejected)

Keep alerts only in the running process and use the Web Notifications API.

- Pro: simplest possible.
- Con: alerts are lost on restart, invisible to the analyst when the tab is
  closed, and unread state has no audit trail.

## Decision Outcome

Use **Option B**. `NotificationService` lives in `app/notifications.py`; the
fiche worker calls `_maybe_alert()` after each new fiche; the bell in the React
TopBar polls the unread count and renders the alert feed from
`/api/v1/notifications`.

### Positive Consequences

- New HIGH/CRITICAL or KEV CVEs reach the analyst in-app and on Telegram within
  minutes of discovery, automatically.
- Alerts are idempotent (dedup already guarantees one alert per new fiche) and
  ackable (read flag), with a zero-cost retention story (monthly partitions).
- `POST /api/v1/notifications/test` gives the supervisor a one-click demo.

### Negative Consequences

- Telegram delivery is best-effort (no retry queue); in-app feed is the source
  of truth, and failures are logged.
- Alert content is a summary, not the full fiche; analysts still open the fiche
  in the UI (future work: link the Telegram message to the fiche URL).
