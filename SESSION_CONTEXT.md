# Session Context — CTI Platform (`/actors` work)

Handoff notes for the next coding session. Read this first; it reconstructs the
full state of the Actors / Statistics / Assistant work on this project.

## Project layout (IMPORTANT — watch the paths)

- Real project root: `C:\Users\OUALLALI\Desktop\internship`
  - Subdirectories: `app/` (FastAPI backend), `frontend/` (Vite + React SPA),
    `docker-compose.yml`.
- There is a STALE OneDrive shadow at `C:\Users\OUALLALI\OneDrive\Desktop\internship`
  (near-empty). The bash tool's default cwd resolves there — ALWAYS pass the
  real path (or `workdir`) explicitly; do not rely on relative paths/`Get-Location`.
- Mirror/sync target: `C:\Users\OUALLALI\cti-build` (whole tree). After every
  source change we copy the touched files there. Keep it in sync; deletion is
  still pending user confirmation.
- The app container has NO bind mounts (immutable image rootfs) → every code
  change requires `docker compose up -d --build app`. Rebuild is ~60-90s.

## Current objective (4 user requests on `/actors`)

1. Rename Kill Chain → "TTP Covered" — DONE.
2. Malware drill-down page listing all actors using it — DONE (`/malware/:stixId`).
3. KB-grounded teaching chatbot on /actors Assistant tab — DONE + upgraded to
   local Ollama LLM (see below).
4. Readable Statistics tab — DONE (layout bug fixed + clickable lists).

## Containers / infra

- `cti-app` (FastAPI on :8000, wslrelay for Docker), `cti-clickhouse` (db `cti`),
  `cti-ollama` (local LLM), `cti-tor`. Port 8000 is Docker-mapped; no stale host
  process.
- ClickHouse 24.8. NOTE: `upperASCII()` does NOT exist — use `upperUTF8()`.
- KB numbers (verified live): 191 threat actors, 858 attack patterns, 733
  malware, 95 tools, stored in ClickHouse `cti` db.
- Ollama: server image `ollama:latest` (user has it), model `llama3.2:3b` pulled
  (2.0 GB) — do NOT pull another server image unless asked. Eval speed on this
  machine ≈ 7 t/s (slow CPU). Model is kept warm via `keep_alive: "30m"`.
- Important: the CVE alert-sheet AI pipeline (background scheduler) ALSO uses
  Ollama and has a ~26.5k-CVE backlog → it monopolizes the single model. See
  "assistant_busy" arbitration below.

## Statistics tab (frontend `ActorStats.jsx`)

- `/api/v1/actors/stats` payload keys: `kpis` (object: total_actors,
  actors_with_ttps, total_ttps, total_malware, total_tools), `tactic_coverage`,
  `top_techniques`, `top_malware`, `top_tools`, `top_actors`.
- `top_malware` / `top_tools` now include `stix_id` (added in
  `app/routers/actors.py` `top_entities()`). `top_actors` already had it.
- MiniList items are clickable Links (new tab):
  - malware/tools → `/malware/${encodeURIComponent(stix_id)}` (profile lists the
    groups that use them)
  - actors → `/actors?actor=${encodeURIComponent(stix_id)}` (`ThreatActors.jsx`
    reads `?actor=` via `useSearchParams` to select the profile)
- Old crash fixed: `Math.max(...tactics.reduce(...,1))` (spreading a number →
    "o.reduce is not iterable"). Now `reduce(...) || 1`.
- ErrorBoundary in `App.jsx:34` wraps the whole `/actors` route → a render crash
  in one tab kills all tabs. Per-tab `ErrorBoundary` wrappers were added around
  `ActorStats` and `AssistantChat` in `ThreatActors.jsx`.

## THE layout bug that looked like "AI not working" (fixed)

Root cause: in `frontend/src/components/ui/tabs.jsx`, `TabsContent` had Tailwind
`flex`, which overrides Radix's `[hidden]{display:none}` (author `display:flex`
beats the UA attribute selector). All three tab panels rendered stacked
(~520px each) → page grew to ~1648px, active content sat below the fold
(assistant input at viewport y=1696), stats looked blank until scrolling.
Fix: added `data-[state=inactive]:hidden` to `TabsContent` default className.
Verified: outer `main` scroll == client size (704px), inactive panels
`display:none`, stats scroll internally (1417px in 600px panel).

## Assistant (`app/assistant.py`) — deterministic KB + local Ollama

Endpoint: `POST /api/v1/actors/ask` `{query}` → `{answer, suggestions, entity,
engine}`. Frontend call `api.askActors` has `timeout: 120s`.

Flow in `KnowledgeAssistant.answer()`:
1. Technique regex `\bT\d{3,5}(\.\d{2,3})?\b` fast-path → `_answer_technique`.
   (Guard: technique result must NOT be overwritten by the later keyword branch —
   `result = None` pattern with `if result is None:` gate does this.)
2. `_resolve_entity()` — single matcher over actor names/aliases, malware/tool
   names, tactic labels: word-boundary regex, `_STOP` filler-word set, longest
   match wins, priority actor > malware > tactic. Fixes false positives
   ("cobalt"→actor Cobalt Group, "the"→The White Company inside "nothere").
3. Keyword fallback (`_answer_keyword`, multiSearchAnyCaseInsensitiveUTF8).
4. If result has `entity`: build a ~900-char facts block (KB summary + the
   deterministic answer as ground truth) → `_ollama_answer()` → Ollama
   `/api/chat` with hard anti-hallucination instructions (use ONLY the facts,
   ~40 words, same language), `num_predict: 160`, `keep_alive: "30m"`,
   `timeout: 115s`. On success: replace answer, add footer
   `_<model> · grounded on the local ATT&CK knowledge base._`, set
   `engine: "ollama"`. Any failure → deterministic answer returned unchanged
   (never breaks).

Verified answers (engine=ollama): "Who uses Cobalt Strike?" → correct actors
list; "What does APT28 use?" (45.3s); "What is T1055?" → technique Process
Injection / Stealth. Deterministic fallback + keyword path still work.

`suggestions` chips come from the answer builders; `entity` drives deep links.

## Shared-model arbitration (`app/assistant_busy.py`)

Problem: Ollama serializes per model; the background CVE alert-sheet generator
(~26.5k queued CVEs, one sheet ≈ 60-120s) monopolizes `llama3.2:3b`, so chat
requests queue behind it and hit timeouts → fallback.

Solution (process-wide, cooperative):
- `assistant.py` wraps its Ollama call with `await begin()` … `end()` (try/finally).
- Background jobs call `await yield_to_assistant(settings.ai_engine_timeout_seconds)`
  before each engine call (added in `_invoke_engine` in `app/ai_processor.py` and
  `_llm_structured` in `app/agent/graph.py`).
- `yield_to_assistant` waits while a chat is active AND for
  `RELEASE_BUFFER = 120s` after the last chat, so consecutive questions get the
  model. Capped by the caller's `max_wait` (120s), so the pipeline is never
  blocked forever — it defers to chats, then works through the backlog.

Observed behavior: first question after a sheet started ≈ 1-2 min (in-flight
sheet must finish), subsequent ≈ 35-45s. If Ollama unreachable → instant fallback.

## Debugging kit that works

- `docker exec cti-app python /tmp/x.py` for in-container runs; copy scripts via
  `docker cp`. Async client scripts need the app's DB conventions
  (clickhouse-connect async client) — see `app/db.py`.
- Headless browser CDP probing: Node v24.19.0 + Chrome at
  `C:\Program Files\Google\Chrome\Application\chrome.exe`. Flags:
  `--headless=new --remote-debugging-port=NNNN --user-data-dir=... --window-size=1600,900`.
  IMPORTANT: programmatic `.click()` does NOT switch Radix tabs — must send real
  `Input.dispatchMouseEvent` presses. `npx` is blocked by the execution policy.
- Check Ollama model presence: `docker exec cti-ollama ollama list`.
- Check the sheet backlog: query `cti.alert_sheet_pending` (columns: cve,
  status, attempts, last_error, retry_at, updated_at).
- Log greps: `docker logs cti-app --since 5m | Select-String OLLAMA|WARNING|sheet_generated`.

## Brief #4 — Phase 1: Threat Actor module (DONE, verified live)

Additive only. No fabricated data: ATT&CK intrusion-set descriptions carry NO
structured motivation/sectors/countries → profiles are deterministic keyword
extractions, always labelled `profile_source: "derived from the MITRE ATT&CK
intrusion-set description"`.

Backend:
- `app/actor_profile.py` (NEW): `profile_from_description()`, `detect_facet()`.
  - Copy in: `app/attack_importer.py` (12-col insert), `app/routers/actors.py`.
  - Matcher is hyphen/space-insensitive (`_token_re` normalizes `-`→space on
    BOTH token and text) + plural-tolerant (`_variants`: s/es/ies). Word-
    boundary lookarounds prevent substring false positives.
  - Origin vs target split: `_ORIGIN` = STRICT origin markers only (demonyms,
    "based in <country>", "government", "u.s. government", "fsb", "gru"…);
    `_ATTRIBUTION` = broad target-country map incl. bare country nouns. Bare
    "in the United States" ⇒ TARGET. `profile_from_description` removes the
    attribution country from `target_countries`.
  - TRAP: a tuple like `("Palestine", ("palestinian"))` is a bare STRING → the
    loop iterates characters (`token="a"` matched everything!). Always
    `("palestinian",)`. Fixed + verified.
  - Canonical labels: motivation ∈ {espionage, financial, hacktivism,
    destructive, unknown}; sectors ∈ 17 canonical; countries ∈ 42 canonical.
- `app/db_init.py`: `threat_actors` DDL + `_migrate()` ADD COLUMN IF NOT EXISTS:
  `motivation`, `attribution`, `target_sectors Array(String)`,
  `target_countries Array(String)`; `vulnerability_alerts.threat_actor_id`.
- `app/routers/actors.py`: `list_actors` filters `search`, `motivation`,
  `sector`, `country` (`has(target_sectors/countries, ...)`); `GET
  /actors/filters` (route MUST be declared before `/{stix_id}`); `get_actor`
  returns profile fields + `attributed_iocs` (`processed_iocs.threat_actor_id =
  stix_id`, empty → honest); `actor_stats` adds `most_referenced`
  (`attribution_coverage`, `actors` — 0/[] while no attributed IOC data).
- `app/assistant.py`: top-level `from app.actor_profile import detect_facet`;
  `_answer_target()` builds `[sector|country] {value}` answers from the KB via
  the facet classifier (NEW WHERE clause: `FROM {table} AS ta FINAL` — alias
  MUST precede `FINAL`, ClickHouse syntax error otherwise). Fast (~0.4s, no
  Ollama), grounded, honest ("origin: not stated").

Frontend:
- `services/api.js`: `getActors(search, filters)`, `getActorFilters()`.
- `pages/ThreatActors.jsx`: filter bar (Motivation / Sector / Target country
  dropdowns + Clear all), row chips (motivation + attribution badge), profile
  header badges, "Target Profile" section (sectors/countries chips + source
  note), "Attributed Indicators" honest empty-state block.
- `components/actors/ActorStats.jsx`: "Most-referenced actors" Card with honest
  "Not enough attributed data yet" when `attribution_coverage === 0`.

Verified live (after rebuild + db_init + sync):
- FIN7 → motivation financial, attribution "" (was a wrong "United States"),
  targets [Financial Services, Retail..., Healthcare, Shipping...] + United
  States. APT33 → Iran / Energy+Aviation / Saudi Arabia·US·South Korea.
- `?sector=Energy` → 6 actors (APT28, APT33, Fox Kitten, Kimsuky, Moses Staff,
  Sharpshooter). `?country=Russia` → 16 (target-country semantics).
- `/actors/filters` → 5 motivations, 17 sectors, 42 countries.
- `/actors/stats` `most_referenced` → `attribution_coverage: 0`, `actors: []`.
- `/actors/ask` "which actors target the energy sector" → 6 grounded actors,
  0.45s, engine=deterministic; "Who targets North Korea?" → 2 (0.36s).
- "tell me about APT33" → Ollama path, slow (~1-2min) when the CVE pipeline is
  mid-generation; still 200 eventually (arbitration works).

## Brief #4 — Phase 2: Detection Rule Generation (DONE, verified live)

Sigma rule generator — deterministic, ground-truth-grounded, additive, €0.
User confirmed deliverable: **Sigma rules + UI**.
Design choice: **compute-on-demand** (no new table / no pipeline) — rules are
built at request time from the KB, so they can never go stale and nothing new
needs syncing; the generator is pure Python.

Backend (new `app/detection_rules.py`):
- `TECHNIQUE_TO_SIGMA`: analyst-owned technique → Sigma template map, the same
  "explicit mapping table owned by the analysts" pattern as `app/tactics.py`
  and `actor_profile.py`. Current coverage: T1105, T1204.002, T1059.001,
  T1059.003, T1588.002, T1566.001, T1036.005, T1082, T1071.001, T1547.001,
  T1053.005, T1083, T1055, T1003, T1078, T1219, T1027. Extend the dict to grow
  coverage; more techniques → more generated rules with zero code elsewhere.
- Sub-technique fallback `_template_key()`: T1105.001 → T1105 template, but a
  bare parent (e.g. T1566) with only a sub-template is NOT covered (unmapped,
  honest). Fix an earlier bug where the parent-prefix set misfired → KeyError.
- YAML emitter is hand-rolled (dependency-free, no PyYAML in the image):
  `_scalar` quotes conservatively, multi-line description → literal block `|`
  scalar (single-quoted multi-line was broken YAML). Nested map/list support.
- `generate(actor, techniques, malware_names)` → `{generated, unmapped_count,
  unmapped[{x_mitre_id, name, tactic}], rules[], note}`. Each rule: deterministic
  `id` (uuid5), `title "Potential <actor> activity - <technique>"`, status
  experimental, author "Argus CTI - automated ATT&CK KB generator", date,
  references = real MITRE technique + actor URLs, tags attack.t* + attack.<tac>
  + actor.<slug>, logsource/detection/falsepositives/level from the template,
  sigma as a full YAML string. Description is composed ONLY from KB fields
  (technique summary snippet + actor motivation/attribution + KB malware names).
  ASCII only in generated strings (dropped the em-dash for portability).
- Route `GET /api/v1/actors/{stix_id}/rules` (in `routers/actors.py`): queries
  the actor, its observed techniques (attack_patterns via stix_relationships
  where source_ref = actor) and malware/tool names, calls `generate()`. 404 for
  unknown actor. No route-order conflict (two path segments).

Frontend:
- `services/api.js`: `getActorRules(stixId)`.
- `pages/ThreatActors.jsx`: new `rules` useApi keyed on selectedActorId, passed
  to ProfileView; new "Detection Rules" section renderer: loading skeletons,
  ErrorState retry, honest empty states ("no techniques in KB" vs "templates
  don't cover these techniques yet" + unmapped chips), rule cards with
  x_mitre_id badge + tactic + level badge, `CopyButton` for the YAML and a
  download-`.yml` button (Blob). Small `downloadRuleYaml` + `LevelBadge`
  helpers built with existing components only.

Verified live (after rebuild):
- APT33 → 14 rules generated / 17 unmapped (honest); first rule = Web Protocols
  T1071.001 with real MITRE URL, tags, logsource windows/net_connection,
  detection EventID 3 + dest 80/443, description with real technique summary +
  "attribution: Iran" + KB malware (NETWIRE, StoneDrill, NanoCore, ...).
- FIN7 → 4 rules; host-side probe: all emitted YAML parses (PyYAML check),
  deterministic ids, level/references/logsource/description round-trip.
- 404 for unknown actor; `/actors/stats` still healthy (191); new frontend
  bundle index-CWy6DRy8.js served.
- NOTE: host Python got PyYAML installed purely for YAML validation (temp tool,
  not a project dependency; container image unchanged in this regard).

## Brief #4 — Phase 3: Actor-IOC correlation / attribution (DONE, verified live)

User confirmed deliverable: **Actor-IOC correlation/attribution**. Real trusted
source = OTX pulse `adversary` field; plus an operator tagging workflow.

**KEY FINDING (honest): the `OTX_API_KEY` in `.env` returns 403 "Authentication
required"** → the OTX feed is INERT right now (collector returns 0 pulses, no
error logged). The attribution wiring is complete and proven with real data via
the analyst path; the moment a valid key is set, OTX pulses will auto-attribute.
Nothing is fabricated; attribution stays at 0 until a real source tags real IOCs.

Design:
- Attribution lives in a NEW table `ioc_actor_attribution` (db_init DDL §13),
  keyed (indicator, type), ReplacingMergeTree. DELIBERATE: re-inserting a
  `processed_iocs` row with fresh `ts` can cross a monthly partition → duplicate
  that FINAL never collapses. Dedicated additive table = always safe, every row
  carries provenance (source, attributed_by, ts).
- `source` LowCardinality: `otx` | `analyst` | `removed`. A `removed` row
  (threat_actor_id='') is a tombstone: newest version shadows prior rows and
  reads filter `threat_actor_id != ''`.
- New `app/actor_attribution.py`: `ActorAttribution` — lazy, hourly-refreshed
  index of name+aliases → stix_id (case/sep-insensitive `_norm`); `resolve()`
  returns '' when unmatched (never guessed); `attribute()` upserts. Verified:
  `resolve("Fancy Bear")` → APT28 id, "APT33"/"Turla"/"MuddyWater" → correct ids,
  "Unknown Group Xyz" → ''.
- Ingestion: `IntelRecord.threat_actor_name` (new optional field); OTX collector
  sets it from `pulse["adversary"]`. `BaseCollector._persist_attributions()` runs
  in `process()` (batched, one resolve per unique name) and `store_record()`;
  failures are logged and never break ingestion.
- Reads switched FROM `processed_iocs.threat_actor_id` (left empty; Phase 1
  column now vestigial) TO the new table:
  - profile `attributed_iocs`: LEFT JOIN processed_iocs for live severity;
    returns indicator/type/severity/source/attributed_by/ts.
  - stats `most_referenced`: count attributed (indicator,type) in 30d window,
    top actors with ioc_count; honest 0/[] until real tags exist.
- Analyst endpoints (have auth): `POST /actors/{stix_id}/attribute-ioc` {indicator,
  type, attributed_by?} → validates the IOC exists in processed_iocs (else 404)
  and the actor exists; `DELETE /actors/{stix_id}/attribute-ioc` → tombstone.
  Rendered in ThreatActors.jsx Attributed Indicators: source badges (otx/analyst),
  x remove button for analyst rows, an "Attribute to this actor" form (type select
  + indicator input) with inline success/error; onAttributed reloads detail+stats.
  api.js: `attributeIoc` / `unattributeIoc`.

Verified live (real corpus data only; test attribution removed afterwards):
- RESOLVE correct ids; POST → 200, profile shows real IOC `172.70.206.0/23`
  (severity 6.0 from live corpus, source analyst); stats → coverage 1, APT33 top;
  DELETE → back to 0; unknown actor / non-corpus IOC → 404.
- Frontend build passed (vite); new SPA baked into image.

## Brief #4 — Phase 4: RBAC + Login, TLP marking, audit logging (SCOPE — agreed)

Agreed scope (transcribed verbatim from the supervisor on 2026-09-19, written to
this file BEFORE building so it cannot drift):

1. **Real authentication**: username/password hashed with bcrypt or argon2, plus
   optional free TOTP-based 2FA.
2. **Authorization = two independent dimensions** (not one flat role):
   - (a) workspace tags per user (TI / CERT / DFIR, one or more each) controlling
     the default nav/dashboard;
   - (b) an individual TLP clearance tier per user, **enforced server-side on
     every single endpoint** — not just hidden in the UI. A low-clearance user
     must get a real 403 from the API on a RED-marked item.
3. **Nullable `tlp` column** (RED / AMBER+STRICT / AMBER / GREEN / CLEAR) on every
   relevant table, INCLUDING the Phase 1 Threat Actor tables. Enforced on display
   and on export — any STIX/MISP export must exclude RED items by default.
4. **Append-only audit log table** (who viewed/exported/modified what, when) with
   a simple searchable view for admins.
5. **Workspaces without real features yet** (e.g. CERT case tracking) get an
   honest "not yet available" state — never a placeholder pretending to be real.
6. **Verify before reporting done**: (a) a real low-clearance test user is
   actually blocked server-side (not just UI-hidden); (b) export really excludes
   RED items; (c) a real audit entry gets written.

Same rules as every phase: no fabricated data, ask before assuming any credential
or design decision, do not touch/refactor existing working modules, run and
verify before reporting done.

### PENDING DECISIONS (asking user before building; will be resolved here)
- User provisioning + initial credentials mechanism.
- Password hashing library (bcrypt vs argon2) & whether adding a pip dep is OK.
- TLP semantics for null rows + how RED items get created (analyst/admin set-TLP?).
- Audit-log capture scope (which endpoints count as "viewed/modified/exported").
- Workspace nav/dashboard surfacing (switcher defaulting to user's tags?).

## Notes / open items

- Some CVE sheet generations fail with an EMPTY error after ~120s (seems
  pre-existing, slow model on long raw texts; scheduler retries). Not addressed —
  pipeline was already churning like this before our changes.
- OTX feed currently dead (botched API key → 403). Feed attribution activates
  automatically once the key in `.env` is valid; no code change needed. Until
  then `most_referenced.attribution_coverage` stays honestly at 0.
- `cti-build` mirror deletion still pending user confirmation.
- Temp debug/probe scripts: keep them in
  `%LOCALAPPDATA%\Temp\opencode\` and clean up after.
- Never fabricate data; keep the platform at €0 (Ollama/Gemini are the free
  providers; `LLM_PROVIDER=auto` resolves to ollama). Do NOT print or commit
  `.env` secrets (a Gemini API key exists there).