# =============================================================================
# CTI Platform - /api/v1/export routes (analyst export hub)
# -----------------------------------------------------------------------------
# Bulk, analyst-ready download of any read model in the platform. The frontend
# Search & Export hub calls this with a resource + format + the same filters
# the list endpoints accept, and gets a streamed file back:
#
#   GET /api/v1/export?resource=alerts|iocs|feeds|notifications
#                       &format=csv|json|stix&<resource filters>
#
# Formats:
#   csv  -> RFC-4180 flat rows (one line per record)
#   json -> pretty array of the same flat records
#   stix -> STIX 2.1 Bundle (alerts -> vulnerability, iocs -> indicator,
#           feeds -> report; notifications are not STIX-expressible -> 422)
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app import exporters
from app.routers.alerts import VALID_RISK, _safe_json
from app.routers.feeds import _CATEGORY_SQL

router = APIRouter(prefix="/api/v1/export", tags=["export"])

VALID_RESOURCES = ("alerts", "iocs", "feeds", "notifications")
VALID_FORMATS = ("csv", "json", "stix")

_CSV_FIELDS: dict[str, list[str]] = {
    "alerts": ["vuln_cve", "risk_level", "threat_score", "exploitation_status", "ts", "ai_summary"],
    "iocs": ["indicator", "type", "severity", "ts"],
    "feeds": ["source", "category", "url", "raw_text", "ts"],
    "notifications": ["id", "category", "severity", "title", "body", "cve", "source", "read", "created_at"],
}

_STIX_CSV_FIELDS: dict[str, list[str]] = {
    "alerts": ["vuln_cve", "risk_level", "threat_score", "exploitation_status", "ts", "ai_summary"],
    "iocs": ["indicator", "type", "severity", "ts"],
    "feeds": ["source", "category", "url", "raw_text", "ts"],
}


def _iso(v: Any) -> str:
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


@router.get("")
async def export_data(
    request: Request,
    resource: str = Query(description=f"One of {VALID_RESOURCES}"),
    format: str = Query(default="csv", description=f"One of {VALID_FORMATS}"),
    search: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    type: str | None = Query(default=None),
    min_severity: float = Query(default=0.0, ge=0.0, le=10.0),
    source: str | None = Query(default=None),
    category: str | None = Query(default=None),
    unread_only: bool = Query(default=False),
    severity: str | None = Query(default=None),
    limit: int = Query(default=10000, ge=1, le=50000),
) -> StreamingResponse:
    """Stream an analyst export of one resource in the requested format."""
    if resource not in VALID_RESOURCES:
        raise HTTPException(status_code=422, detail=f"resource must be one of {VALID_RESOURCES}")
    if format not in VALID_FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of {VALID_FORMATS}")
    if format == "stix" and resource == "notifications":
        raise HTTPException(status_code=422, detail="notifications have no STIX representation; use csv/json")

    db = request.app.state.db
    database = request.app.state.settings.clickhouse_database

    if resource == "alerts":
        where, params = ["1=1"], {}
        if risk_level:
            if risk_level.upper() not in VALID_RISK:
                raise HTTPException(status_code=422, detail=f"risk_level must be one of {sorted(VALID_RISK)}")
            where.append("JSONExtractString(risk_level, 'risk_level') = {rl:String}")
            params["rl"] = risk_level.upper()
        if search and search.strip():
            where.append("(positionCaseInsensitive(vuln_cve, {s:String}) > 0 OR positionCaseInsensitive(ai_summary, {s2:String}) > 0)")
            params["s"], params["s2"] = search.strip(), search.strip()
        rows = await db.query(
            f"""
            SELECT vuln_cve, JSONExtractString(risk_level, 'risk_level') AS rl,
                   threat_score, exploitation_status, ts, ai_summary
            FROM {{db:Identifier}}.vulnerability_alerts FINAL
            WHERE {' AND '.join(where)}
            ORDER BY ts DESC LIMIT {{lim:UInt32}}
            """,
            parameters={**params, "db": database, "lim": limit},
        )
        records = [
            {"vuln_cve": r[0], "risk_level": r[1], "threat_score": r[2],
             "exploitation_status": _safe_json(r[3]), "ts": _iso(r[4]), "ai_summary": r[5]}
            for r in rows.result_rows
        ]

    elif resource == "iocs":
        where, params = ["severity >= {ms:Float32}"], {"ms": min_severity}
        if type:
            where.append("type = {t:String}")
            params["t"] = type
        if search and search.strip():
            where.append("positionCaseInsensitive(indicator, {s:String}) > 0")
            params["s"] = search.strip()
        rows = await db.query(
            f"""
            SELECT indicator, type, severity, ts
            FROM {{db:Identifier}}.processed_iocs FINAL
            WHERE {' AND '.join(where)}
            ORDER BY severity DESC, ts DESC LIMIT {{lim:UInt32}}
            """,
            parameters={**params, "db": database, "lim": limit},
        )
        records = [{"indicator": r[0], "type": r[1], "severity": r[2], "ts": _iso(r[3])} for r in rows.result_rows]

    elif resource == "feeds":
        where, params = ["1=1"], {}
        if source:
            where.append("source = {src:String}")
            params["src"] = source
        if category:
            where.append(f"{_CATEGORY_SQL} = {{cat:String}}")
            params["cat"] = category
        if search and search.strip():
            where.append("positionCaseInsensitive(raw_text, {s:String}) > 0")
            params["s"] = search.strip()
        rows = await db.query(
            f"""
            SELECT source, {_CATEGORY_SQL} AS category, url, raw_text, ts
            FROM {{db:Identifier}}.raw_threat_intel FINAL
            WHERE {' AND '.join(where)}
            ORDER BY ts DESC LIMIT {{lim:UInt32}}
            """,
            parameters={**params, "db": database, "lim": limit},
        )
        records = [{"source": r[0], "category": r[1], "url": r[2], "raw_text": r[3], "ts": _iso(r[4])} for r in rows.result_rows]

    else:  # notifications
        where, params = ["1=1"], {}
        if unread_only:
            where.append("read = 0")
        if severity:
            where.append("severity = {sev:String}")
            params["sev"] = severity
        if search and search.strip():
            where.append("(positionCaseInsensitive(title, {s:String}) > 0 OR positionCaseInsensitive(body, {s2:String}) > 0)")
            params["s"], params["s2"] = search.strip(), search.strip()
        rows = await db.query(
            f"""
            SELECT id, category, severity, title, body, cve, source, read, created_at
            FROM {{db:Identifier}}.notifications FINAL
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC LIMIT {{lim:UInt32}}
            """,
            parameters={**params, "db": database, "lim": limit},
        )
        records = [
            {"id": str(r[0]), "category": r[1], "severity": r[2], "title": r[3],
             "body": r[4], "cve": r[5], "source": r[6], "read": r[7], "created_at": _iso(r[8])}
            for r in rows.result_rows
        ]

    body, media_type, ext = _serialize(records, resource, format)
    filename = f"cti_{resource}_{_iso_now()}.{ext}"
    return StreamingResponse(
        iter([body]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _serialize(records: list[dict[str, Any]], resource: str, format: str) -> tuple[str, str, str]:
    """Pick serializer + content-type + file extension for the export."""
    if format == "csv":
        return exporters.to_csv(records, _CSV_FIELDS[resource]), "text/csv; charset=utf-8", "csv"
    if format == "json":
        return exporters.to_json(records), "application/json; charset=utf-8", "json"
    fields = _STIX_CSV_FIELDS[resource]
    stix_records = []
    for r in records:
        flat = {k: r.get(k) for k in fields}
        flat["ai_summary"] = r.get("ai_summary")
        flat["exploitation_status"] = r.get("exploitation_status")
        stix_records.append(flat)
    return (
        exporters.to_stix(stix_records, resource),
        "application/vnd.oasis.stix+json; charset=utf-8",
        "json",
    )


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
