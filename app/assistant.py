from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from app.actor_profile import detect_facet

logger = logging.getLogger(__name__)

# Ingest uses 1970-01-01 as the "unknown activity window" marker — never
# present a fabricated year, only data recorded in the ATT&CK knowledge base.
_MIN_YEAR = 1971

_TECH_RE = re.compile(r"\bT\d{3,5}(?:\.\d{2,3})?\b", re.IGNORECASE)

# Generic filler words that must never be treated as entity names (e.g. the
# first word of an actor like "The White Company" must not match "the" in a
# sentence).
_STOP = {
    "the", "and", "for", "who", "what", "which", "how", "when", "where",
    "are", "was", "were", "is", "do", "does", "did", "of", "on", "in",
    "with", "by", "to", "at", "a", "an", "used", "uses", "using", "about",
    "from", "that", "this", "these", "those", "they", "their", "them",
    "you", "your", "tell", "me", "name", "list", "show", "all", "most",
    "what", "why", "get", "its", "it's", "has", "have", "can", "could", "any",
    "actor", "actors", "apt", "group", "groups", "malware", "tool", "tools",
    "tactic", "tactics", "technique", "techniques", "attack", "att&ck",
}

DEFAULT_CHIPS = [
    "Tell me about APT28",
    "Who uses Cobalt Strike?",
    "What is T1055?",
    "Which actors target the government sector?",
    "Explain the Initial Access tactic",
    "What does Kimsuky cover?",
]


def _year(iso: Any) -> str | None:
    if not iso:
        return None
    try:
        y = int(str(iso)[:4])
    except (TypeError, ValueError):
        return None
    return str(y) if y >= _MIN_YEAR else None


def _window(first_seen: Any, last_seen: Any) -> str:
    lo = _year(first_seen)
    hi = _year(last_seen)
    if lo and hi and lo != hi:
        return f"{lo}–{hi}"
    if lo:
        return f"since {lo}"
    return "not recorded in the ATT&CK knowledge base"


def _excerpt(text: Any, limit: int = 420) -> str | None:
    if not text:
        return None
    t = " ".join(str(text).split())
    if len(t) <= limit:
        return t
    cut = t[: limit - 1]
    return cut.rsplit(" ", 1)[0] + "…"


def _tactic_label(tactic: str | None) -> str:
    if not tactic or tactic.lower() in {"unknown", "unmapped", "null", ""}:
        return "Unmapped"
    return " ".join(w.capitalize() for w in tactic.replace("_", " ").split())


class KnowledgeAssistant:
    """Deterministic question-answering over the ATT&CK knowledge base.

    Every answer is assembled from values stored in ClickHouse (names,
    aliases, descriptions, relationships and counts). No LLM is involved,
    so nothing is invented and the endpoint can never "fail to generate".
    """

    def __init__(self, db: Any, db_name: str) -> None:
        self.db = db
        self.l = db_name
        self.ACTORS = f"{db_name}.threat_actors"
        self.RELS = f"{db_name}.stix_relationships"
        self.PATTERNS = f"{db_name}.attack_patterns"
        self.MT = f"{db_name}.malware_tools"

    async def _q(self, sql: str, params: dict[str, Any] | None = None) -> list[list[Any]]:
        rows = await self.db.query(sql, parameters=params or {})
        return rows.result_rows

    # --- entity resolution ----------------------------------------------------

    async def _actor_index(self) -> list[tuple[str, str, list[str] | None]]:
        rows = await self._q(
            f"SELECT stix_id, name, aliases FROM {self.ACTORS} FINAL ORDER BY name"
        )
        return [(r[0], r[1], r[2]) for r in rows]

    async def _playbook_index(self) -> list[tuple[str, str, str]]:
        rows = await self._q(
            f"SELECT stix_id, name, type FROM {self.MT} FINAL ORDER BY name"
        )
        return [(r[0], r[1], r[2]) for r in rows]

    async def _tactic_index(self) -> list[str]:
        rows = await self._q(
            f"SELECT DISTINCT tactic FROM {self.PATTERNS} FINAL WHERE tactic != ''"
        )
        return [str(r[0]) for r in rows]

    def _boundary(self, candidate: str) -> re.Pattern[str]:
        return re.compile(rf"\b{re.escape(candidate)}\b", re.IGNORECASE)

    async def _resolve_entity(self, query: str):
        """Find the single best entity the query mentions.

        Candidates come from actor names/aliases, malware & tool names and
        tactic labels. Matches must sit on word boundaries (so "the" inside
        "there" or "nothere" never fires) and filler words are excluded.
        The longest match wins; equality is broken by priority actor > malware
        > tactic. Returns (kind, payload) or None.
        """
        q = query.lower().strip()
        best: tuple[int, int, str, object] | None = None

        def consider(kind: str, priority: int, matched: str, payload: object) -> None:
            nonlocal best
            if best is None or len(matched) > best[0] or (
                len(matched) == best[0] and priority < best[1]
            ):
                best = (len(matched), priority, kind, payload)

        for stix_id, name, aliases in await self._actor_index():
            cands: list[str] = [str(name)]
            cands += [str(a) for a in (aliases or [])]
            parts = str(name).strip().split()
            first = parts[0] if parts else ""
            if len(parts) > 1 and len(first) >= 4 and first.lower() not in _STOP:
                cands.append(first)
            for cand in cands:
                c = cand.lower().strip()
                if len(c) < 2:
                    continue
                if self._boundary(c).search(q):
                    consider("actor", 0, c, (stix_id, cand))

        for stix_id, mname, mtype in await self._playbook_index():
            c = str(mname).strip().lower()
            if len(c) < 3:
                continue
            if self._boundary(c).search(q):
                consider("malware", 1, c, (stix_id, str(mname), str(mtype)))

        for tactic in await self._tactic_index():
            t = str(tactic).strip().lower()
            if len(t) < 5 or t in _STOP:
                continue
            if self._boundary(t).search(q):
                consider("tactic", 2, t, str(tactic))

        if best is None:
            return None
        return best[2], best[3]

    async def _technique(self, mitre_id: str) -> list[Any] | None:
        rows = await self._q(
            f"""
            SELECT stix_id, x_mitre_id, tactic, name, description, url
            FROM {self.PATTERNS} FINAL
            WHERE upperUTF8(x_mitre_id) = {{id:String}}
            LIMIT 1
            """,
            {"id": mitre_id.upper()},
        )
        return rows[0] if rows else None

    # --- data queries ---------------------------------------------------------

    async def _actor_kit(self, stix_id: str) -> dict[str, Any]:
        rows = await self._q(
            f"""
            SELECT name, description, aliases, first_seen, last_seen, url
            FROM {self.ACTORS} FINAL WHERE stix_id = {{id:String}}
            """,
            {"id": stix_id},
        )
        if not rows:
            return {}
        r = rows[0]
        rels = await self._q(
            f"""
            SELECT target_ref, relationship_type FROM {self.RELS} FINAL
            WHERE source_ref = {{id:String}}
            """,
            {"id": stix_id},
        )
        targets = [row[0] for row in rels]
        ttp_rows, mt_rows = [], []
        if targets:
            ttp_rows = await self._q(
                f"""
                SELECT x_mitre_id, name, tactic FROM {self.PATTERNS} FINAL
                WHERE has({{targets:Array(String)}}, stix_id)
                ORDER BY tactic, name
                """,
                {"targets": targets},
            )
            mt_rows = await self._q(
                f"""
                SELECT name, type FROM {self.MT} FINAL
                WHERE has({{targets:Array(String)}}, stix_id)
                ORDER BY type, name
                """,
                {"targets": targets},
            )
        return {
            "name": r[0],
            "description": r[1],
            "aliases": r[2],
            "first_seen": r[3],
            "last_seen": r[4],
            "url": r[5],
            "ttps": ttp_rows,
            "tools": mt_rows,
        }

    async def _actors_for_target(self, target_ref: str) -> tuple[int, list[dict[str, str]]]:
        rows = await self._q(
            f"""
            SELECT ta.name, ta.stix_id
            FROM {self.RELS} AS r FINAL
            INNER JOIN (SELECT stix_id, name FROM {self.ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            WHERE r.target_ref = {{id:String}}
            GROUP BY ta.name, ta.stix_id
            ORDER BY ta.name
            """,
            {"id": target_ref},
        )
        total = await self._q(
            f"""
            SELECT uniqExact(r.source_ref)
            FROM {self.RELS} AS r FINAL
            INNER JOIN (SELECT stix_id FROM {self.ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            WHERE r.target_ref = {{id:String}}
            """,
            {"id": target_ref},
        )
        count = total[0][0] if total else 0
        return count, [{"name": row[0], "stix_id": row[1]} for row in rows]

    async def _technique_usage(self, pattern_stix_id: str) -> tuple[int, list[tuple[str, str]]]:
        return await self._actors_for_target(pattern_stix_id)

    async def _tactic_kit(self, tactic: str) -> dict[str, Any]:
        tt = await self._q(
            f"""
            SELECT stix_id, x_mitre_id, name
            FROM {self.PATTERNS} FINAL WHERE tactic = {{t:String}}
            ORDER BY name
            """,
            {"t": tactic},
        )
        coverage = await self._q(
            f"""
            SELECT ap.x_mitre_id, ap.name, uniqExact(r.source_ref) AS c
            FROM {self.RELS} AS r FINAL
            INNER JOIN (SELECT stix_id FROM {self.ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            INNER JOIN (SELECT stix_id, x_mitre_id, name, tactic FROM {self.PATTERNS} FINAL) AS ap ON r.target_ref = ap.stix_id
            WHERE ap.tactic = {{t:String}}
            GROUP BY ap.x_mitre_id, ap.name
            ORDER BY c DESC, ap.name
            LIMIT 7
            """,
            {"t": tactic},
        )
        top_actors = await self._q(
            f"""
            SELECT ta.name, uniqExact(r.target_ref) AS c
            FROM {self.RELS} AS r FINAL
            INNER JOIN (SELECT stix_id, name FROM {self.ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            INNER JOIN (SELECT stix_id, tactic FROM {self.PATTERNS} FINAL) AS ap ON r.target_ref = ap.stix_id
            WHERE ap.tactic = {{t:String}}
            GROUP BY ta.name
            ORDER BY c DESC, ta.name
            LIMIT 6
            """,
            {"t": tactic},
        )
        return {"techniques": tt, "coverage": coverage, "top_actors": top_actors}

    # --- local LLM grounding --------------------------------------------------

    async def _kb_summary(self) -> str:
        rows = await self._q(
            f"""
            SELECT (SELECT count() FROM {self.ACTORS} FINAL),
                   (SELECT count() FROM {self.PATTERNS} FINAL),
                   (SELECT count() FROM {self.MT} FINAL WHERE type = 'malware'),
                   (SELECT count() FROM {self.MT} FINAL WHERE type = 'tool')
            """
        )
        if not rows:
            return "knowledge base: 0 actors, 0 techniques, 0 malware, 0 tools"
        r = rows[0]
        return f"knowledge base: {r[0]} threat actors, {r[1]} ATT&CK techniques, {r[2]} malware, {r[3]} tools"

    async def _ollama_tags(self, base_url: str, timeout: float = 3.0) -> list[str]:
        """List locally installed models; empty on any failure."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(f"{base_url.rstrip('/')}/api/tags")
            if resp.status_code != 200:
                return []
            return [m.get("name", "") for m in resp.json().get("models", [])]
        except Exception:
            return []

    async def _ollama_answer(self, question: str, facts: str) -> str | None:
        """Raise the shared-model flag for the duration of the call so the
        background CVE sheet generator yields the model to the interactive
        answer; then run the actual request (see _ollama_answer_inner)."""
        from app.assistant_busy import begin, end

        await begin()
        try:
            return await self._ollama_answer_inner(question, facts)
        finally:
            end()

    async def _ollama_answer_inner(self, question: str, facts: str) -> str | None:
        """Ask the LOCAL Ollama model to synthesise an answer strictly from the
        retrieved KB facts. Any failure returns None so the deterministic answer
        (already assembled from ClickHouse) always remains as fallback — the
        endpoint never errors and never invents data."""
        from app.config import get_settings

        settings = get_settings()
        base = settings.ollama_base_url.rstrip("/")
        model = settings.ollama_model
        tag = await self._ollama_tags(base)
        if not any(t == model or t.split(":")[0] == model.split(":")[0] for t in tag):
            logger.warning("Ollama model %s not installed locally (%s)", model, ", ".join(tag) or "none")
            return None
        summary = await self._kb_summary()
        system = (
            "You are a threat-intelligence assistant answering questions exclusively from a local "
            "MITRE ATT&CK knowledge base.\n"
            "A retrieval step already searched that knowledge base; every fact you need is in the "
            "FACTS block below, plus global KB statistics.\n"
            "Hard rules:\n"
            "- Use ONLY the provided facts. Never invent names, numbers, aliases, techniques, tools, "
            "dates or relationships.\n"
            "- If the facts do not answer the question, say what is missing and what the user could ask instead.\n"
            "- Be very concise: about 40 words, Markdown, short bullets, bold key entities.\n"
            "- Answer in the same language as the user's question.\n"
            f"KB STATISTICS:\n{summary}\n\n"
            f"FACTS FROM SEARCH (ground truth):\n{facts}"
        )
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": question},
            ],
            "stream": False,
            "keep_alive": "30m",
            "options": {"temperature": 0.2, "top_p": 0.9, "num_predict": 160},
        }
        try:
            async with httpx.AsyncClient(timeout=115.0) as client:
                resp = await client.post(f"{base}/api/chat", json=payload)
            if resp.status_code != 200:
                logger.warning("Ollama chat HTTP %s", resp.status_code)
                return None
            content = resp.json().get("message", {}).get("content", "").strip()
            return content or None
        except Exception as exc:
            logger.warning("Ollama chat failed (%s): %s", type(exc).__name__, exc)
            return None

    # --- public answering -----------------------------------------------------

    async def answer(self, query: str) -> dict[str, Any]:
        q = query.strip()
        if not q:
            return {
                "answer": "Ask me anything about the ATT&CK knowledge base: threat actors, techniques, tactics, malware and tools.",
                "suggestions": DEFAULT_CHIPS,
            }

        result: dict[str, Any] | None = None
        m = _TECH_RE.search(q)
        if m:
            row = await self._technique(m.group(0))
            if row:
                result = await self._answer_technique(q, row)
            else:
                return {
                    "answer": f"No technique `{m.group(0).upper()}` exists in the ATT&CK knowledge base. Try a different ID.",
                    "suggestions": DEFAULT_CHIPS,
                }

        if result is None:
            entity = await self._resolve_entity(q)
            if entity:
                kind, payload = entity
                if kind == "actor":
                    kit = await self._actor_kit(payload[0])
                    if kit:
                        result = await self._answer_actor(q, (payload[0], payload[1]), kit)
                    else:
                        result = {
                            "answer": f"I found **{payload[1]}** in the knowledge base but there is no mapped profile yet. Ask after the next ATT&CK sync.",
                            "suggestions": DEFAULT_CHIPS,
                        }
                elif kind == "malware":
                    result = await self._answer_malware(q, payload)
                else:
                    result = await self._answer_tactic(q, payload)
            else:
                facet = detect_facet(q)
                if facet and facet[0] in ("sector", "country"):
                    result = await self._answer_target(q, facet)
                if result is None:
                    result = await self._answer_keyword(q)

        # Local LLM synthesis — only when the retrieval step landed on a concrete
        # entity. The retrieved facts ARE the ground truth passed to the model, so
        # the deterministic answer above stays as an instant fallback.
        if result.get("entity"):
            facts = (
                f'Resolved entity: {result["entity"]["kind"]} “{result["entity"]["name"]}”.\n'
                f"DETERMINISTIC KB ANSWER (ground truth):\n{result['answer']}"
            )
            if len(facts) > 900:
                facts = facts[:900].rsplit(" ", 1)[0] + " …"
            llm = await self._ollama_answer(q, facts)
            if llm:
                from app.config import get_settings

                model = get_settings().ollama_model
                result["answer"] = f"{llm.rstrip()}\n\n_{model} · grounded on the local ATT&CK knowledge base._"
                result["engine"] = "ollama"
        return result

    # --- answer builders ------------------------------------------------------

    async def _answer_actor(self, query: str, actor: tuple[str, str], kit: dict[str, Any]) -> dict[str, Any]:
        stix_id, name = actor
        alias_str = ", ".join(a for a in (kit["aliases"] or []) if str(a).lower().strip() != name.lower()) if kit["aliases"] else None
        ttp_bullets = "\n".join(f"- {r[1]} ({_tactic_label(r[2])})" for r in kit["ttps"][:10])
        if len(kit["ttps"]) > 10:
            ttp_bullets += f"\n- … plus {len(kit['ttps']) - 10} more"
        mt_bullets = "\n".join(f"- {r[0]} ({r[1]})" for r in kit["tools"][:10])
        if len(kit["tools"]) > 10:
            mt_bullets += f"\n- … plus {len(kit['tools']) - 10} more"
        link = f"\n\n[View on MITRE ATT&CK]({kit['url']})" if kit.get("url") else ""

        lines = [
            f"**{name}** is a threat actor (APT) in the MITRE ATT&CK knowledge base.",
            f"- **Active window:** {_window(kit['first_seen'], kit['last_seen'])}.",  # type: ignore[arg-type]
        ]
        if alias_str:
            lines.append(f"- **Also known as:** {alias_str}.")
        lines.append(f"- **Technique coverage:** {len(kit['ttps'])} ATT&CK technique(s).")
        if ttp_bullets:
            lines.append(f"- **Sample techniques:**\n{ttp_bullets}")
        if mt_bullets:
            lines.append(f"- **Associated malware / tools:**\n{mt_bullets}")
        desc = _excerpt(kit.get("description"))
        if desc:
            lines.append(f"- **In short:** {desc}")
        answer = "\n".join(lines) + link
        return {
            "answer": answer,
            "suggestions": [f"Which actors use the same techniques as {name}?", f"What tactics does {name} cover?", "Who uses Cobalt Strike?"],
            "entity": {"kind": "actor", "name": name, "id": stix_id},
        }

    async def _answer_technique(self, query: str, row: list[Any]) -> dict[str, Any]:
        stix_id, mitre_id, tactic, name, desc, url = row
        total, users = await self._technique_usage(stix_id)
        user_names = ", ".join(u["name"] for u in users[:12])
        if len(users) > 12:
            user_names += f" and {len(users) - 12} more"
        link = f"\n\n[View on MITRE ATT&CK]({url})" if url else ""
        what = _excerpt(desc)
        answer = "\n".join([
            f"**{name}** ({mitre_id}) is an ATT&CK technique under **{_tactic_label(tactic)}**.",
            f"- **Recorded usage:** {total} threat actor(s) in this knowledge base.",
            f"- **What it is:** {what}" if what else f"- **What it is:** no description in the knowledge base.",
            f"- **Notable actors that use it:** {user_names or '(none mapped)'}",
        ]) + link
        return {
            "answer": answer,
            "suggestions": [f"Explain the {_tactic_label(tactic)} tactic", f"List techniques used by {user_names.split(', ')[0] if user_names else 'APT28'}", "Who uses Cobalt Strike?"],
            "entity": {"kind": "technique", "name": f"{mitre_id} {name}", "id": stix_id},
        }

    async def _answer_tactic(self, query: str, tactic: str) -> dict[str, Any]:
        kit = await self._tactic_kit(tactic)
        label = _tactic_label(tactic)
        tech_str = ", ".join(f"{r[1]} ({r[2]})" for r in kit["coverage"][:6])
        actors_str = ", ".join(f"{r[0]} ({r[1]} TTPs)" for r in kit["top_actors"][:6])
        answer = "\n".join([
            f"**{label}** is a MITRE ATT&CK tactic (kill-chain phase).",
            f"- **Scale in this knowledge base:** {len(kit['techniques'])} technique(s) tagged `{tactic}`.",
            f"- **Most-cited techniques here:** {tech_str or '(none mapped)'}.",
            f"- **Actors with the deepest coverage here:** {actors_str or '(none mapped)'}.",
            f"- Tactic labels come from the ATT&CK data we ingest — for example the modern 'Stealth' phase groups techniques that previously sat under Defense Evasion.",
        ])
        return {
            "answer": answer,
            "suggestions": DEFAULT_CHIPS,
            "entity": {"kind": "tactic", "name": label, "id": tactic},
        }

    async def _answer_malware(self, query: str, malware: tuple[str, str, str]) -> dict[str, Any]:
        stix_id, name, mtype = malware
        rows = await self._q(
            f"SELECT name, description, url FROM {self.MT} FINAL WHERE stix_id = {{id:String}} LIMIT 1",
            {"id": stix_id},
        )
        desc, url = None, None
        if rows:
            desc = rows[0][1] if len(rows[0]) > 1 else None
            url = rows[0][2] if len(rows[0]) > 2 else None
        total, users = await self._actors_for_target(stix_id)
        user_lines = "\n".join(f"- {u['name']}" for u in users[:12])
        if len(users) > 12:
            user_lines += f"\n- … plus {len(users) - 12} more"
        link = f"\n\n[View on MITRE ATT&CK]({url})" if url else ""
        what = _excerpt(desc)
        answer = "\n".join([
            f"**{name}** is a {mtype} associated with **{total}** threat actor(s) in the ATT&CK knowledge base.",
            f"- **What it is:** {what}" if what else f"- **What it is:** no description in the knowledge base.",
            f"- **Threat actors that use it:**\n{user_lines or '- (none mapped)'}",
        ]) + link
        return {
            "answer": answer,
            "suggestions": DEFAULT_CHIPS,
            "entity": {"kind": mtype, "name": name, "id": stix_id},
        }

    async def _answer_target(self, query: str, facet: tuple[str, str]) -> dict[str, Any]:
        """Answer "which actors target <sector/country>?" strictly from the
        structured `target_sectors` / `target_countries` columns stored by the
        Phase 1 importer — real data, never speculation. Deterministic (no
        entity payload, so the Ollama synthesis step is skipped)."""
        kind, value = facet
        column = "target_sectors" if kind == "sector" else "target_countries"
        rows = await self._q(
            f"""
            SELECT ta.name, ta.stix_id, ta.motivation, ta.attribution
            FROM {self.ACTORS} AS ta FINAL
            WHERE has(ta.{column}, {{s:String}})
            ORDER BY ta.name
            """,
            {"s": value},
        )
        if not rows:
            return {
                "answer": (
                    f"No threat actor in the ATT&CK knowledge base is recorded as targeting the "
                    f"**{value}** {kind} yet. Ask about an actor, technique, tactic or malware name."
                ),
                "suggestions": DEFAULT_CHIPS,
            }
        bullets = "\n".join(
            f"- **{r[0]}** — motivation: {r[2]}, origin: {r[3] or 'not stated'}"
            for r in rows[:12]
        )
        if len(rows) > 12:
            bullets += f"\n- … plus {len(rows) - 12} more"
        return {
            "answer": (
                f"Per the ATT&CK knowledge base, **{len(rows)}** threat actor(s) are recorded as "
                f"targeting the **{value}** {kind}:\n{bullets}\n\n"
                "_Profiles are derived strictly from the MITRE ATT&CK intrusion-set descriptions._"
            ),
            "suggestions": DEFAULT_CHIPS,
        }

    async def _answer_keyword(self, query: str) -> dict[str, Any]:
        q = query.strip().lower()
        # Normalise apostrophes/quotes so "who's" still matches "who s" patterns.
        words = [w for w in re.split(r"[^a-z0-9]+", re.sub(r"[’']", " ", q)) if len(w) >= 3 and w not in _STOP]
        if not words:
            return {
                "answer": "I need a little more to go on. Try mentioning an APT name, technique ID (e.g. T1055), tactic, or malware name.",
                "suggestions": DEFAULT_CHIPS,
            }
        params = {"words": words}
        actor_hits = await self._q(
            f"""
            SELECT name, description, aliases
            FROM {self.ACTORS} FINAL
            WHERE multiSearchAnyCaseInsensitiveUTF8(description, {{words:Array(String)}})
               OR multiSearchAnyCaseInsensitiveUTF8(name, {{words:Array(String)}})
               OR multiSearchAnyCaseInsensitiveUTF8(toString(aliases), {{words:Array(String)}})
            ORDER BY name
            """,
            params,
        )
        tech_hits = await self._q(
            f"""
            SELECT x_mitre_id, name, tactic
            FROM {self.PATTERNS} FINAL
            WHERE multiSearchAnyCaseInsensitiveUTF8(description, {{words:Array(String)}})
               OR multiSearchAnyCaseInsensitiveUTF8(name, {{words:Array(String)}})
            ORDER BY name
            LIMIT 6
            """,
            params,
        )
        mt_hits = await self._q(
            f"""
            SELECT name, type
            FROM {self.MT} FINAL
            WHERE multiSearchAnyCaseInsensitiveUTF8(name, {{words:Array(String)}})
               OR multiSearchAnyCaseInsensitiveUTF8(description, {{words:Array(String)}})
            ORDER BY name
            LIMIT 6
            """,
            params,
        )

        if not actor_hits and not tech_hits and not mt_hits:
            return {
                "answer": (
                    f"I couldn't find anything in the ATT&CK knowledge base matching “{query.strip()}”.\n\n"
                    "You can ask me about threat actors, techniques, tactics, malware and tools — for example:"
                ),
                "suggestions": DEFAULT_CHIPS,
            }

        lines = [f"Here is what the ATT&CK knowledge base says about “{query.strip()}” — all numbers are read live from our data:"]
        if actor_hits:
            lines.append(f"- **Threat actors ({len(actor_hits)} match):**")
            for r in actor_hits[:5]:
                lines.append(f"  - {r[0]}: {_excerpt(r[1], 180)}")
        if tech_hits:
            lines.append(f"- **Techniques ({len(tech_hits)} match):**")
            for r in tech_hits[:5]:
                lines.append(f"  - {r[0]} {r[1]} ({_tactic_label(r[2])})")
        if mt_hits:
            lines.append(f"- **Malware / tools ({len(mt_hits)} match):**")
            for r in mt_hits[:5]:
                lines.append(f"  - {r[0]} ({r[1]})")
        return {"answer": "\n".join(lines), "suggestions": DEFAULT_CHIPS}