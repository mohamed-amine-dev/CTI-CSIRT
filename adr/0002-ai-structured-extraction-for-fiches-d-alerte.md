# 0002: AI structured extraction for the Fiches d'Alerte

- Status: Accepted
- Deciders: CSIRT engineering team, security lead, platform architect
- Date: 2026-08-09

Technical Story: Every raw vulnerability mention ingested into the platform must
be turned into a "Fiche d'Alerte" that exactly matches the supervisor's 4-point
analyst template. We need the LLM output to be machine-verifiable, not free prose.

## Context and Problem Statement

A human analyst reading a CISA bulletin, a CERT-FR advisory or an NVD entry has to
produce a structured fiche containing:

1. **Environmental impact** — how to determine whether *our* environment is
   affected (affected versions / modules and the procedure to check).
2. **Risk assessment** — risk level, exploitation paths, and compromise impact.
3. **Exploitation status** — whether a public exploit/PoC exists and under what
   conditions it can be used.
4. **Remediation** — not just the vendor patch, but hardening, isolation and
   access-restriction measures.

Manually writing these fiches does not scale to the feed volume. Generating them
with an LLM *without constraints* is dangerous: the model will happily produce a
five-paragraph essay that a parser cannot validate and a dashboard cannot render.

## Decision Drivers

- **Enforceability** — the 4 sections are a hard contract from the supervisor;
  the extraction layer must guarantee they are present and typed.
- **Structured, not prose** — the fiche is stored in ClickHouse columns and
  rendered by the React frontend; nested fields (e.g. affected_versions as a
  list, `public_poc_available` as a boolean) must be parseable.
- **Hallucination containment** — `risk_level` and `public_poc_available` should
  be constrained enumerations/booleans, forcing the LLM to commit to a value and
  letting Pydantic reject anything else.
- **Zero cost** — free-tier Groq API (or local Ollama) must be usable.
- **Determinism and retryability** — a failed validation must be retryable
  without corrupting the database.

## Considered Options

### Option A: Free-form prompt + regex/post-processing (rejected)

Ask the LLM "write a fiche" and then parse the text with regex or heuristics.

- Pro: simplest possible implementation.
- Con: the model can skip a section, rename a heading, or emit
  `"HIGH RISK"` instead of `HIGH`. Every feed's raw text is different, so the
  regexes become an endless maintenance sink. No structural guarantee. This is
  exactly the kind of "works in demo, breaks in production" approach to avoid
  for a security-critical output.

### Option B: LangChain `with_structured_output(FicheAlerteModel)` (chosen)

A Pydantic model declares the exact schema; LangChain converts it to a strict
JSON schema, passes it to the provider (Groq/Ollama), and parses/validates the
response with Pydantic on the way back. `Literal` types and `bool` fields act as
an output contract enforced by the model provider itself.

- Pro: the LLM is steered to emit only fields we define; a wrong value raises a
  `ValidationError` at parse time (and we retry).
- Pro: provider-agnostic — the same model works with `ChatGroq` (free-tier API)
  or `ChatOllama` (local), so cost stays at zero.
- Pro: the same Pydantic class doubles as the ClickHouse row contract and the
  JSON contract for the React UI.

## Decision Outcome

Use **Pydantic v2 strict models** (`FicheAlerteModel` with nested
`EnvironmentalImpact`, `RiskAssessment`, `ExploitationStatus`, `RemediationPlan`)
combined with **LangChain `with_structured_output`** for every fiche generation.
Provider resolution: `ChatGroq` when a free key exists, `ChatOllama` otherwise.

Deduplication policy (decided here too):

- Before any LLM call, the CVE is extracted from the raw text via regex.
- If that CVE already exists in `vulnerability_alerts`, we do **not** call the
  LLM again (saves free-tier quota) — instead we re-insert the same CVE key with
  an incremented `threat_score`; `ReplacingMergeTree` merges it into one row.
- Only genuinely new CVEs trigger an LLM extraction call.

### Positive Consequences

- The 4-point supervisor template is enforced structurally, not stylistically.
- Any provider or model can be swapped without touching collectors or storage.
- Strict enums/booleans (risk_level, public_poc_available) make the fiche
  machine-queryable and dashboard-ready.
- Dedup before the LLM call protects both the free-tier quota and database size.

### Negative Consequences

- Structured output quality depends on model capability: small local models can
  occasionally return malformed JSON. Mitigated by validation + a single retry,
  and a degraded `LLM unavailable` error path that still stores the raw intel.
- `with_structured_output` requires tool-calling support from the provider
  (supported by Groq's chat models and Ollama's modern model families).
