# 0003: LLM engine selection with health-checked Ollama → Gemini failover

- Status: Accepted
- Deciders: CSIRT engineering team, security lead, platform architect
- Date: 2026-08-09

Technical Story: Fiche d'Alerte generation must never be silently fabricated when
the LLM backend is unavailable, and must keep working when the primary (local)
engine is down. The platform needs a deterministic, logged engine-selection rule
so an analyst can always tell which engine produced a given report.

## Context and Problem Statement

`0002` chose LangChain `with_structured_output` for the 4-point fiche contract
but left provider priority as "first configured cloud key (Groq → Gemini), else
local Ollama". That order fails the operational requirements of a zero-cost
CSIRT platform:

1. **Local-first economics** — Ollama is the only truly free, air-gapped engine;
   cloud keys burn a rate-limited free quota (Gemini free tier ~20 req/min).
2. **Silent-stall risk** — if the selected provider is down (Ollama not running,
   network blocked), generation fails without a fallback, and repeated syncs
   drop fiches with only a generic error line.
3. **No provenance** — there was no record of which engine produced which fiche,
   which matters when the security lead reviews AI-generated analysis.

## Decision Drivers

- **Zero cost** — prefer the local engine; only spend cloud quota when the local
  one is genuinely unavailable.
- **Honesty** — a fiche that cannot be generated must be left absent (and later,
  surfaced as pending in the UI), never filled with placeholder text.
- **Determinism** — the engine choice must be reproducible from logs.
- **Health probe cost** — the probe must be cheap (short timeout) because it runs
  before *every* fiche generation.

## Considered Options

### Option A: Static priority "cloud key first" (rejected)

Keep the original `active_provider` order (Groq → Gemini → Ollama).

- Pro: zero extra code.
- Con: burns cloud quota by default, stalls when the chosen cloud provider has a
  transient outage, and gives no engine provenance.

### Option B: Health-checked Ollama first, Gemini fallback (chosen)

In `auto` mode, `_engine_candidates()` runs a 2-second HTTP probe against
`{OLLAMA_BASE_URL}/api/tags` before every fiche generation:

- Ollama reachable → `[ollama, gemini]` (Gemini only retried if a key exists).
- Ollama unreachable → `[gemini]` when `GEMINI_API_KEY` is set, else `[ollama]`
  so the failure surfaces loudly rather than silently skipping.
- `LLM_PROVIDER=groq|gemini|ollama` still forces a single engine (no silent
  fallback) for deterministic deployments.

Each engine is retried 3× with 1.5s/3s backoff; on total failure the CVE is
simply left without a fiche (the UI will show an honest pending/absent state).
Every report logs `event=fiche_generated engine=<engine> cve=<cve>`.

- Pro: local-first (free), cloud quota spent only when needed, every fiche has
  engine provenance, and a dead engine can never stall the pipeline.
- Pro: the 2s health probe is negligible vs. multi-second generation calls.
- Con: one extra HTTP call per fiche; negligible in practice.

## Decision Outcome

Use **Option B**. `active_provider` now reports `ollama` for `auto` mode; the
runtime engine is resolved per-call via `_engine_candidates()` in
`app/ai_processor.py`, and each generated fiche is logged with its engine.

### Positive Consequences

- Free/local-first operation; cloud quota preserved for genuine failover.
- Analysts and the security lead can audit `event=fiche_generated engine=…`
  lines to know which engine produced each report.
- A down Ollama (or revoked Gemini key) degrades gracefully: retries → fallback →
  honest absence, never a fabricated report.

### Negative Consequences

- When neither engine is available, fiches are silently absent (mitigated in
  Phase 4 by storing a `pending`/`failed` status surfaced in the UI).
- Gemini free-tier rate limits still apply on failover; mitigated by the
  existing dedup rule (already-tracked CVEs never trigger an LLM call).
