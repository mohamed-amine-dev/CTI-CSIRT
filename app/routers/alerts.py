# =============================================================================
# CTI Platform - /api/v1/alerts routes (Alert Sheets)
# -----------------------------------------------------------------------------
# Read-only endpoints serving the vulnerability_alerts table. Designed as the
# JSON contract for the future React (Vite) + Tailwind frontend: list, detail,
# and risk-level stats. Every query uses FINAL so ReplacingMergeTree dedup is
# applied on read (one row per CVE, latest score).
# =============================================================================

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

VALID_RISK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@router.get("")
async def list_alerts(
    request: Request,
    risk_level: str | None = Query(default=None, description="Filter by risk level"),
    search: str | None = Query(default=None, description="Substring search on CVE / summary"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Paginated list of Alert Sheets, newest first."""
    db = request.app.state.db
    where, params = ["1=1"], {}
    if risk_level:
        if risk_level.upper() not in VALID_RISK:
            raise HTTPException(status_code=422, detail=f"risk_level must be one of {sorted(VALID_RISK)}")
        # risk_level is a JSON column; extract the scalar for filtering.
        where.append("JSONExtractString(risk_level, 'risk_level') = {rl:String}")
        params["rl"] = risk_level.upper()
    if search and search.strip():
        where.append("(positionCaseInsensitive(vuln_cve, {s:String}) > 0 OR positionCaseInsensitive(ai_summary, {s2:String}) > 0)")
        params["s"], params["s2"] = search.strip(), search.strip()

    clauses = " AND ".join(where)
    rows = await db.query(
        f"""
        SELECT vuln_cve, risk_level, exploitation_status, threat_score, ts,
               environmental_impact, remediation_solutions, ai_summary
        FROM {{db:Identifier}}.vulnerability_alerts FINAL
        WHERE {clauses}
        ORDER BY ts DESC
        LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}
        """,
        parameters={**params, "db": request.app.state.settings.clickhouse_database,
                    "lim": limit, "off": offset},
    )
    return {"items": [_row(r) for r in rows.result_rows], "total": len(rows.result_rows), "limit": limit, "offset": offset}


@router.get("/stats")
async def alert_stats(request: Request) -> dict[str, Any]:
    """Count of sheets grouped by risk level (dashboard widget)."""
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT JSONExtractString(risk_level, 'risk_level') AS rl, count()
        FROM {db:Identifier}.vulnerability_alerts FINAL
        GROUP BY rl ORDER BY rl
        """,
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    return {"by_risk_level": {r[0]: r[1] for r in rows.result_rows}}


@router.get("/{cve}")
async def get_alert(cve: str, request: Request) -> dict[str, Any]:
    """Fetch a single Alert Sheet by its CVE identifier."""
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT vuln_cve, risk_level, exploitation_status, threat_score, ts,
               environmental_impact, remediation_solutions, ai_summary
        FROM {db:Identifier}.vulnerability_alerts FINAL
        WHERE vuln_cve = {cve:String}
        LIMIT 1
        """,
        parameters={"db": request.app.state.settings.clickhouse_database, "cve": cve.upper()},
    )
    if not rows.result_rows:
        raise HTTPException(status_code=404, detail=f"No sheet found for {cve}")
    return _row(rows.result_rows[0])


def _row(r: list[Any]) -> dict[str, Any]:
    """Map a raw ClickHouse row to the JSON contract for the React frontend.

    The JSON-string columns (environmental_impact, risk_level,
    exploitation_status, remediation_solutions) are parsed back into objects so
    the frontend receives nested, typed data. `risk_level_label` is the scalar
    enum extracted from the JSON for quick badges/chips.
    """
    risk = _safe_json(r[1])
    return {
        "vuln_cve": r[0],
        "risk_level": risk,
        "risk_level_label": (risk.get("risk_level") if isinstance(risk, dict) else r[1]),
        "exploitation_status": _safe_json(r[2]),
        "threat_score": r[3],
        "ts": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
        "environmental_impact": _safe_json(r[5]),
        "remediation_solutions": _safe_json(r[6]),
        "ai_summary": r[7],
    }


def _safe_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw
