from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.actor_attribution import SOURCE_ANALYST, SOURCE_REMOVED, ActorAttribution
from app.assistant import KnowledgeAssistant
from app.attack_importer import AttackImporter
from app.auth import allowed_tlp_values, assert_tlp_allowed, requester_policy
from app.detection_rules import generate as generate_detection_rules

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/actors", tags=["actors"])

_bearer = HTTPBearer(auto_error=False)


def _require_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Reject state-changing calls that do not carry the configured token."""
    expected = request.app.state.settings.api_access_token
    if creds is None or creds.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing access token")

def _db(request: Request) -> Any:
    return request.app.state.db

def _database(request: Request) -> str:
    return request.app.state.settings.clickhouse_database


def _tlp_where(request: Request) -> tuple[str, dict[str, Any]]:
    """Server-side TLP visibility for the requester's clearance (Phase 4).

    RED rows are only reachable by RED-clearance (or privileged-ops) callers;
    lower clearance reads everything else. Returns an SQL predicate + params
    unconditionally so content list queries stay single-source-of-truth.
    """
    policy = requester_policy(request)
    allowed = allowed_tlp_values(policy.get("tier", 0))
    return (
        "(empty(tlp) OR tlp IN {allowed_tlp:Array(String)})",
        {"allowed_tlp": allowed},
    )

@router.get("")
async def list_actors(
    request: Request,
    search: str = "",
    motivation: str = "",
    sector: str = "",
    country: str = "",
) -> dict[str, Any]:
    """List threat actors, optionally filtered by name/alias, motivation,
    target sector or target country (Brief #4 Phase 1 additive filters)."""
    query = f"""
        SELECT stix_id, name, description, aliases, first_seen, last_seen, url,
               motivation, attribution, target_sectors, target_countries
        FROM {_database(request)}.threat_actors FINAL
    """
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if search:
        clauses.append(
            "positionCaseInsensitive(name, {s:String}) > 0"
            " OR positionCaseInsensitive(description, {s:String}) > 0"
            " OR positionCaseInsensitive(toString(aliases), {s:String}) > 0"
        )
        params["s"] = search
    if motivation:
        clauses.append("motivation = {mo:String}")
        params["mo"] = motivation
    if sector:
        clauses.append("has(target_sectors, {sec:String})")
        params["sec"] = sector
    if country:
        clauses.append("has(target_countries, {ct:String})")
        params["ct"] = country
    tlp_sql, tlp_params = _tlp_where(request)
    clauses.append(f"({tlp_sql})")
    params.update(tlp_params)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY name"

    rows = await _db(request).query(query, parameters=params)

    actors = []
    for r in rows.result_rows:
        actors.append({
            "stix_id": r[0],
            "name": r[1],
            "description": r[2],
            "aliases": r[3],
            "first_seen": r[4].isoformat() if r[4] else None,
            "last_seen": r[5].isoformat() if r[5] else None,
            "url": r[6],
            "motivation": r[7] or "unknown",
            "attribution": r[8] or "",
            "target_sectors": r[9] or [],
            "target_countries": r[10] or [],
            "ttp_count": 0,
            "malware_count": 0,
            "tool_count": 0,
        })

    # Enrich every actor with relationship counts (observed TTPs, malware,
    # tools) so the list can show analyst signals without N+1 GETs.
    if actors:
        db_name = _database(request)
        ids = [a["stix_id"] for a in actors]

        ttp_rows = await _db(request).query(
            f"""
            SELECT r.source_ref, count()
            FROM {db_name}.stix_relationships AS r FINAL
            WHERE r.source_ref IN {{sources:Array(String)}}
              AND r.target_ref IN (SELECT stix_id FROM {db_name}.attack_patterns FINAL)
            GROUP BY r.source_ref
            """,
            parameters={"sources": ids},
        )
        ttp_counts = {row[0]: row[1] for row in ttp_rows.result_rows}

        mt_rows = await _db(request).query(
            f"""
            SELECT r.source_ref, mt.type, count()
            FROM {db_name}.stix_relationships AS r FINAL
            INNER JOIN (
                SELECT stix_id, type FROM {db_name}.malware_tools FINAL
            ) AS mt ON r.target_ref = mt.stix_id
            WHERE r.source_ref IN {{sources:Array(String)}}
            GROUP BY r.source_ref, mt.type
            """,
            parameters={"sources": ids},
        )
        malware_counts = {}
        tool_counts = {}
        for row in mt_rows.result_rows:
            if row[1] == "tool":
                tool_counts[row[0]] = row[2]
            else:
                malware_counts[row[0]] = row[2]

        for a in actors:
            a["ttp_count"] = ttp_counts.get(a["stix_id"], 0)
            a["malware_count"] = malware_counts.get(a["stix_id"], 0)
            a["tool_count"] = tool_counts.get(a["stix_id"], 0)

    return {"actors": actors}


@router.get("/stats")
async def actor_stats(request: Request) -> dict[str, Any]:
    """Knowledge-base-wide statistics for the OpenCTI-style Statistics view.

    Everything is scoped to *threat actors* (intrusion sets): a technique,
    malware or tool only counts when a relationship ties it to an actor.
    """
    db = _db(request)
    db_name = _database(request)

    ACTORS = f"{db_name}.threat_actors"
    RELS = f"{db_name}.stix_relationships"
    PATTERNS = f"{db_name}.attack_patterns"
    MT = f"{db_name}.malware_tools"

    async def scalar(sql: str, params: dict[str, Any] | None = None) -> int:
        rows = await db.query(sql, parameters=params or {})
        return rows.result_rows[0][0] if rows.result_rows else 0

    kpis = {
        "total_actors": await scalar(f"SELECT count() FROM {ACTORS} FINAL"),
        "total_ttps": await scalar(f"SELECT count() FROM {PATTERNS} FINAL"),
        "total_malware": await scalar(f"SELECT count() FROM {MT} FINAL WHERE type = 'malware'"),
        "total_tools": await scalar(f"SELECT count() FROM {MT} FINAL WHERE type = 'tool'"),
        "actors_with_ttps": await scalar(
            f"""
            SELECT uniqExact(r.source_ref)
            FROM {RELS} AS r FINAL
            INNER JOIN (SELECT stix_id FROM {ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            INNER JOIN (SELECT stix_id FROM {PATTERNS} FINAL) AS ap ON r.target_ref = ap.stix_id
            """
        ),
    }

    # Tactic coverage: how many actors / techniques map to each kill-chain phase.
    tac_rows = await db.query(
        f"""
        SELECT ap.tactic AS tactic,
               uniqExact(r.source_ref) AS actor_count,
               uniqExact(r.target_ref) AS technique_count
        FROM {RELS} AS r FINAL
        INNER JOIN (SELECT stix_id FROM {ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
        INNER JOIN (SELECT stix_id, tactic FROM {PATTERNS} FINAL) AS ap ON r.target_ref = ap.stix_id
        GROUP BY ap.tactic
        ORDER BY actor_count DESC, technique_count DESC
        """
    )
    tactic_coverage = [
        {"tactic": row[0], "actor_count": row[1], "technique_count": row[2]}
        for row in tac_rows.result_rows
    ]

    # Most-cited techniques across actors.
    tech_rows = await db.query(
        f"""
        SELECT ap.x_mitre_id, ap.name, ap.tactic, uniqExact(r.source_ref) AS actor_count
        FROM {RELS} AS r FINAL
        INNER JOIN (SELECT stix_id FROM {ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
        INNER JOIN (SELECT stix_id, x_mitre_id, name, tactic FROM {PATTERNS} FINAL)
            AS ap ON r.target_ref = ap.stix_id
        GROUP BY ap.x_mitre_id, ap.name, ap.tactic
        ORDER BY actor_count DESC
        LIMIT 12
        """
    )
    top_techniques = [
        {"x_mitre_id": row[0], "name": row[1], "tactic": row[2], "actor_count": row[3]}
        for row in tech_rows.result_rows
    ]

    async def top_entities(entity_kind: str, limit: int = 8) -> list[dict[str, Any]]:
        rows = await db.query(
            f"""
            SELECT mt.stix_id, mt.name, uniqExact(r.source_ref) AS actor_count
            FROM {RELS} AS r FINAL
            INNER JOIN (SELECT stix_id FROM {ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
            INNER JOIN (SELECT stix_id, name FROM {MT} FINAL WHERE type = {{kind:String}})
                AS mt ON r.target_ref = mt.stix_id
            GROUP BY mt.stix_id, mt.name
            ORDER BY actor_count DESC
            LIMIT {int(limit)}
            """,
            parameters={"kind": entity_kind},
        )
        return [{"stix_id": row[0], "name": row[1], "actor_count": row[2]} for row in rows.result_rows]

    top_malware = await top_entities("malware")
    top_tools = await top_entities("tool")

    # Actors with the richest technique coverage.
    actor_rows = await db.query(
        f"""
        SELECT ta.stix_id, ta.name, uniqExact(r.target_ref) AS ttp_count
        FROM {RELS} AS r FINAL
        INNER JOIN (SELECT stix_id, name FROM {ACTORS} FINAL) AS ta ON r.source_ref = ta.stix_id
        INNER JOIN (SELECT stix_id FROM {PATTERNS} FINAL) AS ap ON r.target_ref = ap.stix_id
        GROUP BY ta.stix_id, ta.name
        ORDER BY ttp_count DESC
        LIMIT 10
        """
    )
    top_actors = [
        {"stix_id": row[0], "name": row[1], "ttp_count": row[2]}
        for row in actor_rows.result_rows
    ]

    # Most-referenced actors by attributed IOC volume (Brief #4 Phase 3).
    # Reads the dedicated `ioc_actor_attribution` table: feed attribution
    # (OTX pulse `adversary`) plus operator tags, with removal tombstones
    # filtered out (threat_actor_id != ''). Honest empty state: no IOC is
    # attributed until a trusted source or an analyst tags one.
    mr_rows = await db.query(
        f"""
        SELECT ta.stix_id, ta.name, count() AS c
        FROM {db_name}.ioc_actor_attribution AS a FINAL
        INNER JOIN (SELECT stix_id, name FROM {db_name}.threat_actors FINAL)
            AS ta ON a.threat_actor_id = ta.stix_id
        WHERE a.threat_actor_id != ''
          AND a.ts >= now() - INTERVAL {{days:UInt32}} DAY
        GROUP BY ta.stix_id, ta.name
        ORDER BY c DESC
        LIMIT 10
        """,
        parameters={"days": 30},
    )
    attributed_rows = await db.query(
        f"""
        SELECT count()
        FROM {db_name}.ioc_actor_attribution FINAL
        WHERE threat_actor_id != ''
          AND ts >= now() - INTERVAL {{days:UInt32}} DAY
        """,
        parameters={"days": 30},
    )
    attributed_total = attributed_rows.result_rows[0][0] if attributed_rows.result_rows else 0
    most_referenced = {
        "window_days": 30,
        "attribution_coverage": attributed_total,
        "actors": [
            {"stix_id": row[0], "name": row[1], "ioc_count": row[2]}
            for row in mr_rows.result_rows
        ],
    }

    return {
        "kpis": kpis,
        "tactic_coverage": tactic_coverage,
        "top_techniques": top_techniques,
        "top_malware": top_malware,
        "top_tools": top_tools,
        "top_actors": top_actors,
        "most_referenced": most_referenced,
    }


@router.get("/filters")
async def actor_filters(request: Request) -> dict[str, Any]:
    """Distinct values for the browse filters (motivation, target sector,
    target country) as stored in the knowledge base. Adds the pseudo-option
    "unknown" for motivation so analysts can explicitly show unclassified
    actors."""
    db_name = _database(request)
    mot_rows = await _db(request).query(
        f"SELECT DISTINCT motivation FROM {db_name}.threat_actors FINAL ORDER BY motivation"
    )
    sec_rows = await _db(request).query(
        f"""
        SELECT DISTINCT s
        FROM {db_name}.threat_actors FINAL
        ARRAY JOIN target_sectors AS s
        WHERE s != ''
        ORDER BY s
        """
    )
    ctr_rows = await _db(request).query(
        f"""
        SELECT DISTINCT c
        FROM {db_name}.threat_actors FINAL
        ARRAY JOIN target_countries AS c
        WHERE c != ''
        ORDER BY c
        """
    )
    motivations = [str(r[0]) for r in mot_rows.result_rows]
    if "unknown" not in motivations:
        motivations.append("unknown")
    return {
        "motivations": motivations,
        "sectors": [str(r[0]) for r in sec_rows.result_rows],
        "countries": [str(r[0]) for r in ctr_rows.result_rows],
    }


@router.get("/{stix_id}")
async def get_actor(request: Request, stix_id: str) -> dict[str, Any]:
    """Get detailed actor profile including TTPs and Malware/Tools."""
    db = _db(request)
    db_name = _database(request)
    
    # 1. Get Actor
    actor_rows = await db.query(
        f"""
        SELECT name, description, aliases, first_seen, last_seen, url,
               motivation, attribution, target_sectors, target_countries, tlp
        FROM {db_name}.threat_actors FINAL
        WHERE stix_id = {{id:String}}
        """,
        parameters={"id": stix_id}
    )
    if not actor_rows.result_rows:
        raise HTTPException(status_code=404, detail="Actor not found")

    r = actor_rows.result_rows[0]
    policy = requester_policy(request)
    assert_tlp_allowed((r[10] or "").upper() or None, policy.get("tier", 0))
    actor = {
        "stix_id": stix_id,
        "name": r[0],
        "description": r[1],
        "aliases": r[2],
        "first_seen": r[3].isoformat() if r[3] else None,
        "last_seen": r[4].isoformat() if r[4] else None,
        "url": r[5],
        "motivation": r[6] or "unknown",
        "attribution": r[7] or "",
        "target_sectors": r[8] or [],
        "target_countries": r[9] or [],
        "profile_source": "derived from the MITRE ATT&CK intrusion-set description",
    }
    
    # 2. Get Relationships (what does this actor use?)
    rels = await db.query(
        f"""
        SELECT target_ref, relationship_type
        FROM {db_name}.stix_relationships FINAL
        WHERE source_ref = {{id:String}}
        """,
        parameters={"id": stix_id}
    )
    
    malware_tools = []
    ttps = []
    
    target_refs = [row[0] for row in rels.result_rows]
    if target_refs:
        # Fetch Malware/Tools
        mt_rows = await db.query(
            f"""
            SELECT stix_id, name, type, description, url
            FROM {db_name}.malware_tools FINAL
            WHERE has({{targets:Array(String)}}, stix_id)
            """,
            parameters={"targets": target_refs}
        )
        for mr in mt_rows.result_rows:
            malware_tools.append({
                "stix_id": mr[0],
                "name": mr[1],
                "type": mr[2],
                "description": mr[3],
                "url": mr[4]
            })
            
        # Fetch TTPs
        ttp_rows = await db.query(
            f"""
            SELECT stix_id, x_mitre_id, tactic, name, description, url
            FROM {db_name}.attack_patterns FINAL
            WHERE has({{targets:Array(String)}}, stix_id)
            """,
            parameters={"targets": target_refs}
        )
        for tr in ttp_rows.result_rows:
            ttps.append({
                "stix_id": tr[0],
                "x_mitre_id": tr[1],
                "tactic": tr[2],
                "name": tr[3],
                "description": tr[4],
                "url": tr[5]
            })
            
    actor["malware_tools"] = malware_tools
    actor["ttps"] = ttps

    # 4. Attributed indicators (Brief #4 Phase 3): IOCs a trusted source
    # (OTX pulse `adversary`) or an analyst tagged with this actor. Severity is
    # pulled from the live IOC corpus; provenance rides on every row.
    attr_rows = await db.query(
        f"""
        SELECT a.indicator, a.type, p.severity, a.source, a.attributed_by, a.ts
        FROM {db_name}.ioc_actor_attribution AS a FINAL
        LEFT JOIN (
            SELECT indicator, type, severity
            FROM {db_name}.processed_iocs FINAL
        ) AS p ON a.type = p.type AND a.indicator = p.indicator
        WHERE a.threat_actor_id = {{id:String}}
        ORDER BY a.ts DESC
        LIMIT 100
        """,
        parameters={"id": stix_id},
    )
    iocs = [
        {
            "indicator": row[0],
            "type": row[1],
            "severity": row[2],
            "source": row[3],
            "attributed_by": row[4],
            "ts": row[5].isoformat() if row[5] else None,
        }
        for row in attr_rows.result_rows
    ]
    actor["attributed_iocs"] = iocs
    actor["attributed_ioc_count"] = len(iocs)
    return actor


@router.get("/{stix_id}/attack-matrix")
async def get_actor_attack_matrix(request: Request, stix_id: str) -> dict[str, Any]:
    """Per-actor ATT&CK matrix (ATT&CK Matrix per Threat Actor brief).

    Returns the *whole* imported technique landscape grouped by tactic so the
    UI can dim techniques the actor is not known to use. `used` is only ever
    true for techniques the actor<->technique STIX relationship data actually
    records (source_ref = this actor, target_ref = an attack-pattern);
    highlights are never guessed.
    """
    db = _db(request)
    db_name = _database(request)

    actor_rows = await db.query(
        f"""
        SELECT name FROM {db_name}.threat_actors FINAL
        WHERE stix_id = {{id:String}}
        """,
        parameters={"id": stix_id},
    )
    if not actor_rows.result_rows:
        raise HTTPException(status_code=404, detail="Actor not found")
    actor_name = actor_rows.result_rows[0][0]

    rel_rows = await db.query(
        f"""
        SELECT target_ref
        FROM {db_name}.stix_relationships FINAL
        WHERE source_ref = {{id:String}}
          AND target_ref IN (SELECT stix_id FROM {db_name}.attack_patterns FINAL)
        """,
        parameters={"id": stix_id},
    )
    used_ids = {r[0] for r in rel_rows.result_rows}

    tlp_where, tlp_params = _tlp_where(request)
    pat_rows = await db.query(
        f"""
        SELECT stix_id, x_mitre_id, tactic, name, description, url
        FROM {db_name}.attack_patterns FINAL
        WHERE {tlp_where}
        ORDER BY x_mitre_id
        """,
        parameters=tlp_params,
    )

    from app.tactics import TACTIC_ORDER  # 14 canonical tactics, MITRE order

    canonical = [t for t in TACTIC_ORDER if t != "Unclassified"]
    ordering = {t: i for i, t in enumerate(canonical)}
    # Tactics outside the canonical 14 (newer additions, fallback labels) are
    # ordered after the canonical ones by name, deterministically — never guessed.
    def tactic_key(t: str) -> tuple[int, str]:
        return (ordering.get(t, len(canonical)), "" if t == "unknown" else t)

    techniques = [
        {
            "stix_id": r[0],
            "x_mitre_id": r[1],
            "tactic": r[2] or "unknown",
            "name": r[3],
            "description": r[4],
            "url": r[5],
            "used": r[0] in used_ids,
        }
        for r in pat_rows.result_rows
    ]

    seen: dict[str, None] = {}
    for t in techniques:
        seen[t["tactic"]] = None
    tactics = sorted(seen, key=tactic_key)

    return {
        "actor": {"stix_id": stix_id, "name": actor_name},
        "tactics": tactics,
        "techniques": techniques,
        "highlights": {
            "used": len(used_ids),
            "total": len(techniques),
        },
    }


@router.get("/{stix_id}/rules")
async def get_actor_rules(request: Request, stix_id: str) -> dict[str, Any]:
    """Generate Sigma detection rules for one actor (Brief #4 Phase 2).

    Fully deterministic and ground-truth-grounded: a rule is produced only for
    techniques the KB records the actor using AND that have an analyst-owned
    Sigma template; the rest are reported as `unmapped`. Neither this generator
    nor its templates invent techniques or fields.
    """
    db = _db(request)
    db_name = _database(request)

    actor_rows = await db.query(
        f"""
        SELECT name, motivation, attribution, url
        FROM {db_name}.threat_actors FINAL
        WHERE stix_id = {{id:String}}
        """,
        parameters={"id": stix_id},
    )
    if not actor_rows.result_rows:
        raise HTTPException(status_code=404, detail="Actor not found")
    a = actor_rows.result_rows[0]
    actor = {
        "stix_id": stix_id,
        "name": a[0],
        "motivation": a[1] or "unknown",
        "attribution": a[2] or "",
        "url": a[3] or "",
    }

    rels = await db.query(
        f"""
        SELECT target_ref
        FROM {db_name}.stix_relationships FINAL
        WHERE source_ref = {{id:String}}
        """,
        parameters={"id": stix_id},
    )
    target_refs = [r[0] for r in rels.result_rows]
    if not target_refs:
        generated = generate_detection_rules(actor, [], [])
        generated["actor"] = actor
        return generated

    # Techniques the KB records the actor using (observed relations).
    ttp_rows = await db.query(
        f"""
        SELECT stix_id, x_mitre_id, tactic, name, description, url
        FROM {db_name}.attack_patterns FINAL
        WHERE has({{targets:Array(String)}}, stix_id)
        """,
        parameters={"targets": target_refs},
    )
    techniques = [
        {
            "stix_id": row[0],
            "x_mitre_id": row[1] or "",
            "tactic": row[2] or "unknown",
            "name": row[3],
            "description": row[4],
            "url": row[5] or "",
        }
        for row in ttp_rows.result_rows
    ]

    # Malware/tool names of this actor (real KB names, for rule context only).
    mt_rows = await db.query(
        f"""
        SELECT name
        FROM {db_name}.malware_tools FINAL
        WHERE has({{targets:Array(String)}}, stix_id)
        """,
        parameters={"targets": target_refs},
    )
    malware_names = [row[0] for row in mt_rows.result_rows]

    generated = generate_detection_rules(actor, techniques, malware_names)
    generated["actor"] = actor
    return generated


class AttributeIocRequest(BaseModel):
    indicator: str
    type: str
    attributed_by: str = ""


@router.post("/{stix_id}/attribute-ioc")
async def attribute_ioc(
    request: Request,
    stix_id: str,
    body: AttributeIocRequest,
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Operator-tagged attribution (Brief #4 Phase 3): link a real IOC from the
    corpus to this actor. Only indicators already present in `processed_iocs`
    can be attributed — never fabricated. Written as an `analyst` row in
    `ioc_actor_attribution` with provenance; DELETE reverses it."""
    indicator = body.indicator.strip()
    ioc_type = body.type.strip().lower()
    if not indicator or not ioc_type:
        raise HTTPException(status_code=422, detail="indicator and type are required")

    db = _db(request)
    db_name = _database(request)

    actor_rows = await db.query(
        f"SELECT name FROM {db_name}.threat_actors FINAL WHERE stix_id = {{id:String}}",
        parameters={"id": stix_id},
    )
    if not actor_rows.result_rows:
        raise HTTPException(status_code=404, detail="Actor not found")
    actor_name = actor_rows.result_rows[0][0]

    exists = await db.query(
        f"""
        SELECT count()
        FROM {db_name}.processed_iocs FINAL
        WHERE type = {{t:String}} AND indicator = {{i:String}}
        """,
        parameters={"t": ioc_type, "i": indicator},
    )
    in_corpus = exists.result_rows[0][0] > 0 if exists.result_rows else False
    if not in_corpus:
        raise HTTPException(
            status_code=404,
            detail=f"No '{ioc_type}' indicator '{indicator}' exists in the IOC corpus",
        )

    try:
        attr = ActorAttribution(db, db_name)
        await attr.attribute(
            indicator,
            ioc_type,
            stix_id,
            SOURCE_ANALYST,
            (body.attributed_by or "").strip()[:48],
        )
    except Exception as exc:  # noqa: BLE001 - surface as a clean 502
        logger.error("attribute-ioc persist failed: %s", exc)
        raise HTTPException(status_code=502, detail="Could not persist attribution") from exc

    return {
        "status": "ok",
        "actor": {"stix_id": stix_id, "name": actor_name},
        "indicator": indicator,
        "type": ioc_type,
        "source": SOURCE_ANALYST,
    }


@router.delete("/{stix_id}/attribute-ioc")
async def unattribute_ioc(
    request: Request,
    stix_id: str,
    indicator: str = "",
    type: str = "",
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Remove analyst attribution by writing a `removed` tombstone: the empty
    threat_actor_id row carries the newest version and shadows the prior row
    for every reader (which filters `threat_actor_id != ''`)."""
    indicator = indicator.strip()
    ioc_type = type.strip().lower()
    if not indicator or not ioc_type:
        raise HTTPException(status_code=422, detail="indicator and type are required")

    try:
        attr = ActorAttribution(_db(request), _database(request))
        await attr.attribute(indicator, ioc_type, "", SOURCE_REMOVED, "")
    except Exception as exc:  # noqa: BLE001 - surface as a clean 502
        logger.error("unattribute-ioc persist failed: %s", exc)
        raise HTTPException(status_code=502, detail="Could not persist removal") from exc

    return {"status": "ok", "indicator": indicator, "type": ioc_type, "removed": True}


@router.post("/sync")
async def sync_attack(request: Request) -> dict[str, Any]:
    """Trigger ATT&CK STIX 2.1 ingest."""
    importer = AttackImporter(_db(request))
    stats = await importer.sync()
    return {"status": "ok", "stats": stats}


class AskQuery(BaseModel):
    query: str

@router.post("/ask")
async def ask_actors(request: Request, body: AskQuery) -> dict[str, Any]:
    """Knowledge-base-grounded assistant over actors, TTPs, tactics & malware.

    Answers are assembled deterministically from data stored in ClickHouse
    (names, aliases, descriptions and relationships) — no external LLM is
    involved, so the answer is always grounded in our data.
    """
    try:
        assistant = KnowledgeAssistant(_db(request), _database(request))
        return await assistant.answer(body.query or "")
    except Exception as e:  # pragma: no cover - defensive
        logger.error("assistant failed: %s", e)
        raise HTTPException(status_code=500, detail="Assistant failed to build an answer from the knowledge base") from e
