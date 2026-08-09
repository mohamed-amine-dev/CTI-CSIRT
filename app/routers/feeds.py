# =============================================================================
# CTI Platform - /api/v1/feeds routes (raw threat intelligence)
# -----------------------------------------------------------------------------
# Read-only endpoints over raw_threat_intel: the "Live Threat Feeds" view of the
# React dashboard (CISA, CERTs, news, dark web ...). Besides the paginated feed
# list we expose three aggregation endpoints that power the dashboard widgets:
#
#   GET /api/v1/feeds          -> paginated raw feed items + computed category
#   GET /api/v1/feeds/sources  -> distinct sources with item counts
#   GET /api/v1/feeds/categories -> category breakdown (donut chart)
#   GET /api/v1/feeds/timeline -> daily ingestion volume (area chart)
#
# The `category` column is derived in SQL from the raw text (keyword scoring)
# because the raw table stores free text, not a taxonomy.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/v1/feeds", tags=["feeds"])

# Keyword-classification order matters: the first matching bucket wins, so the
# most specific / actionable categories (ransomware, exploit) take precedence
# over the generic "Vulnerability" bucket.
_CATEGORY_SQL = """
    CASE
        WHEN lowerUTF8(raw_text) LIKE '%ransomware%'
          OR lowerUTF8(raw_text) LIKE '%ransom%'
          OR lowerUTF8(raw_text) LIKE '%lockbit%'
          OR lowerUTF8(raw_text) LIKE '%blackcat%'
          OR lowerUTF8(raw_text) LIKE '%cl0p%'
          OR lowerUTF8(raw_text) LIKE '%conti%'     THEN 'Ransomware'
        WHEN lowerUTF8(raw_text) LIKE '%phish%'
          OR lowerUTF8(raw_text) LIKE '%smishing%'
          OR lowerUTF8(raw_text) LIKE '%spearphish%' THEN 'Phishing'
        WHEN lowerUTF8(raw_text) LIKE '%malware%'
          OR lowerUTF8(raw_text) LIKE '%botnet%'
          OR lowerUTF8(raw_text) LIKE '%trojan%'
          OR lowerUTF8(raw_text) LIKE '%stealer%'  THEN 'Malware'
        WHEN lowerUTF8(raw_text) LIKE '%exploit%'
          OR lowerUTF8(raw_text) LIKE '%rce%'
          OR lowerUTF8(raw_text) LIKE '%remote code execution%'
          OR lowerUTF8(raw_text) LIKE '%zero-day%'
          OR lowerUTF8(raw_text) LIKE '%zero day%' THEN 'Exploit'
        WHEN lowerUTF8(raw_text) LIKE '%cve-%'
          OR lowerUTF8(raw_text) LIKE '%vulnerab%'
          OR lowerUTF8(raw_text) LIKE '%advisory%'
          OR lowerUTF8(raw_text) LIKE '%patch%'    THEN 'Vulnerability'
        ELSE 'Other'
    END
"""

VALID_CATEGORIES = ("Ransomware", "Phishing", "Malware", "Exploit", "Vulnerability", "Other")


@router.get("")
async def list_feeds(
    request: Request,
    source: str | None = Query(default=None, description="Filter by feed source (CISA, CERT-FR, ...)"),
    category: str | None = Query(default=None, description="Filter by computed category"),
    search: str | None = Query(default=None, description="Substring search on raw text"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Paginated raw feed items, newest first, with a computed category."""
    db = request.app.state.db
    where, params = ["1=1"], {}
    if source:
        where.append("source = {src:String}")
        params["src"] = source
    if category:
        if category not in VALID_CATEGORIES:
            raise HTTPException(status_code=422, detail=f"category must be one of {VALID_CATEGORIES}")
        where.append(f"{_CATEGORY_SQL} = {{cat:String}}")
        params["cat"] = category
    if search:
        where.append("raw_text ILIKE {s:String}")
        params["s"] = f"%{search}%"

    rows = await db.query(
        f"""
        SELECT source, {_CATEGORY_SQL} AS category, url, raw_text, ts
        FROM {{db:Identifier}}.raw_threat_intel FINAL
        WHERE {' AND '.join(where)}
        ORDER BY ts DESC
        LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}
        """,
        parameters={**params, "db": request.app.state.settings.clickhouse_database,
                    "lim": limit, "off": offset},
    )
    return {
        "items": [
            {
                "source": r[0],
                "category": r[1],
                "url": r[2],
                "raw_text": r[3],
                "ts": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
            }
            for r in rows.result_rows
        ],
        "total": len(rows.result_rows),
        "limit": limit,
        "offset": offset,
    }


@router.get("/sources")
async def feed_sources(request: Request) -> dict[str, Any]:
    """Distinct feed sources with item counts (for filters / sidebar badges)."""
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT source, count()
        FROM {db:Identifier}.raw_threat_intel FINAL
        GROUP BY source ORDER BY count() DESC
        """,
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    return {"sources": {r[0]: r[1] for r in rows.result_rows}}


@router.get("/categories")
async def feed_categories(request: Request) -> dict[str, Any]:
    """Count of items per computed category (dashboard donut chart)."""
    db = request.app.state.db
    rows = await db.query(
        f"""
        SELECT {_CATEGORY_SQL} AS category, count()
        FROM {{db:Identifier}}.raw_threat_intel FINAL
        GROUP BY category ORDER BY count() DESC
        """,
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    return {"by_category": {r[0]: r[1] for r in rows.result_rows}}


@router.get("/timeline")
async def feed_timeline(
    request: Request,
    days: int = Query(default=14, ge=1, le=90),
) -> dict[str, Any]:
    """Daily ingestion volume over the last `days` days (dashboard area chart)."""
    db = request.app.state.db
    rows = await db.query(
        """
        SELECT toDate(ts) AS d, count()
        FROM {db:Identifier}.raw_threat_intel FINAL
        WHERE ts >= toDate(now()) - INTERVAL {n:UInt32} DAY
        GROUP BY d ORDER BY d
        """,
        parameters={"db": request.app.state.settings.clickhouse_database, "n": days},
    )
    return {
        "timeline": [
            {"date": r[0].strftime("%Y-%m-%d"), "count": r[1]} for r in rows.result_rows
        ]
    }
