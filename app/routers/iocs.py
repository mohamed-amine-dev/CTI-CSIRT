# =============================================================================
# CTI Platform - /api/v1/iocs routes (processed indicators)
# -----------------------------------------------------------------------------
# Read-only endpoints over processed_iocs (the normalised indicator corpus).
# Analysts can look up a single indicator ("is this IP known?") and the
# frontend can render type distribution. FINAL applies dedup on read.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.ingestion_engine import IOC_TYPES

router = APIRouter(prefix="/api/v1/iocs", tags=["iocs"])


@router.get("")
async def list_iocs(
    request: Request,
    type: str | None = Query(default=None, description="Filter by IOC type"),
    indicator: str | None = Query(default=None, description="Exact indicator lookup"),
    search: str | None = Query(default=None, description="Case-insensitive substring search on the indicator"),
    country: str | None = Query(default=None, description="Filter IP indicators by geolocated country code (e.g. US)"),
    days: int = Query(default=0, ge=0, le=365, description="Only indicators seen in the last N days (0 = no window)"),
    min_severity: float = Query(default=0.0, ge=0.0, le=10.0),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Paginated IOC list, highest severity first.

    Always returns 200 with an empty `items` array when nothing matches —
    never a 500. `search` uses `positionCaseInsensitive` (robust Unicode-aware
    substring match that also treats `%` / `_` literally). `country` restricts
    to IPs the GeoEnricher resolved to that country (choropleth click-through).
    """
    db = request.app.state.db
    where, params = ["severity >= {ms:Float32}"], {"ms": min_severity}
    if type:
        if type not in IOC_TYPES:
            raise HTTPException(status_code=422, detail=f"type must be one of {IOC_TYPES}")
        where.append("type = {t:String}")
        params["t"] = type
    if search and search.strip():
        where.append("positionCaseInsensitive(indicator, {s:String}) > 0")
        params["s"] = search.strip()
    if indicator:
        where.append("indicator = {ind:String}")
        params["ind"] = indicator.lower()
    if country:
        where.append("type IN ('ipv4', 'ipv6')")
        where.append(
            "indicator IN (SELECT ip FROM {db:Identifier}.ip_geo_cache FINAL "
            "WHERE status = 'ok' AND country_code = {cc:String})"
        )
        params["cc"] = country.strip().upper()
    if days:
        where.append("ts >= toDate(now()) - INTERVAL {d:UInt32} DAY")
        params["d"] = days

    rows = await db.query(
        f"""
        SELECT indicator, type, severity, ts
        FROM {{db:Identifier}}.processed_iocs FINAL
        WHERE {' AND '.join(where)}
        ORDER BY severity DESC, ts DESC
        LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}
        """,
        parameters={**params, "db": request.app.state.settings.clickhouse_database,
                    "lim": limit, "off": offset},
    )
    return {
        "items": [
            {"indicator": r[0], "type": r[1], "severity": r[2],
             "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3])}
            for r in rows.result_rows
        ],
        "total": len(rows.result_rows),
    }


@router.get("/stats")
async def ioc_stats(request: Request) -> dict[str, Any]:
    """Count of indicators by type (dashboard widget)."""
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT type, count()
        FROM {db:Identifier}.processed_iocs FINAL
        GROUP BY type ORDER BY count() DESC
        """,
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    return {"by_type": {r[0]: r[1] for r in rows.result_rows}}


@router.get("/recent")
async def recent_iocs(
    request: Request,
    limit: int = Query(default=10, ge=1, le=30),
    days: int = Query(default=7, ge=1, le=90),
    per_type: int = Query(default=3, ge=1, le=5),
) -> dict[str, Any]:
    """Recently tracked indicators, ordered by actual recency and mixed across
    IOC types.

    The generic `list_iocs` sorts `severity DESC, ts DESC`, so the thousands of
    severity-10 CVEs always edge out newer IPs/domains/hashes — a panel fed by it
    looks CVE-only even though recent ingestion is genuinely mixed. This endpoint
    instead keeps the most recent `per_type` rows per indicator type inside the
    last `days` and sorts by `ts DESC`, giving a truthful cross-type cross-section
    of whatever was actually tracked recently.
    """
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT indicator, type, severity, ts
        FROM (
            SELECT indicator, type, severity, ts,
                   row_number() OVER (PARTITION BY type ORDER BY ts DESC) AS rn
            FROM {db:Identifier}.processed_iocs FINAL
            WHERE ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        )
        WHERE rn <= {pt:UInt32}
        ORDER BY ts DESC
        LIMIT {lim:UInt32}
        """,
        parameters={"db": request.app.state.settings.clickhouse_database,
                    "d": days, "pt": per_type, "lim": limit},
    )
    return {
        "items": [
            {"indicator": r[0], "type": r[1], "severity": r[2],
             "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3])}
            for r in rows.result_rows
        ],
        "total": len(rows.result_rows),
    }


@router.get("/{indicator}")
async def get_ioc(indicator: str, request: Request) -> dict[str, Any]:
    """Exact indicator lookup — answers 'do we already know this IP/hash?'.

    Bundles the platform's own cross-references when the indicator has known
    associations: a threat actor (via `ioc_actor_attribution`) and/or a malware
    / tool family (via `processed_iocs.malware_id -> malware_tools`). Read-only;
    association data is whatever the ingestion + operator attribution recorded.
    """
    db = request.app.state.db
    db_name = request.app.state.settings.clickhouse_database
    rows = await db.query(
        """
        SELECT indicator, type, severity, ts, malware_id
        FROM {db:Identifier}.processed_iocs FINAL
        WHERE indicator = {ind:String}
        ORDER BY severity DESC LIMIT 1
        """,
        parameters={"db": db_name, "ind": indicator.lower()},
    )
    if not rows.result_rows:
        raise HTTPException(status_code=404, detail=f"Unknown indicator: {indicator}")
    r = rows.result_rows[0]
    result: dict[str, Any] = {
        "indicator": r[0], "type": r[1], "severity": r[2],
        "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
        "malware": None,
        "actors": [],
    }

    malware_id = r[4]
    if malware_id:
        mrows = await db.query(
            """
            SELECT stix_id, name
            FROM {db:Identifier}.malware_tools FINAL
            WHERE stix_id = {mid:String}
            LIMIT 1
            """,
            parameters={"db": db_name, "mid": malware_id},
        )
        if mrows.result_rows:
            result["malware"] = {"stix_id": mrows.result_rows[0][0],
                                 "name": mrows.result_rows[0][1]}

    arows = await db.query(
        """
        SELECT t.stix_id, t.name
        FROM {db:Identifier}.ioc_actor_attribution AS a FINAL
        INNER JOIN {db:Identifier}.threat_actors AS t
            ON a.threat_actor_id = t.stix_id
        WHERE a.indicator = {ind:String} AND a.type = {typ:String}
          AND a.threat_actor_id != ''
        ORDER BY a.ts DESC LIMIT 5
        """,
        parameters={"db": db_name, "ind": indicator.lower(), "typ": r[1]},
    )
    result["actors"] = [{"stix_id": x[0], "name": x[1]} for x in arows.result_rows]

    return result
