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

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from ..threat_classify import THREAT_CATEGORIES

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

# --- Human-readable summaries (Bug: raw backend dumps in the ticker) ----------
# The ticker was rendering raw_text verbatim ("ports=[...], hostnames=[...]…").
# `_derive_item` turns each real record into a readable (title, summary) and,
# where the record is a serialised dump (Shodan), a `structured` dict for the
# detail modal. Everything is parsed from the actual raw_text — no invented data.
_SHODAN_RE = re.compile(
    r"^InternetDB enrichment for (?P<ip>[^:]+): ports=\[(?P<ports>.*?)\], "
    r"hostnames=\[(?P<hostnames>.*?)\], tags=\[(?P<tags>.*?)\], "
    r"vulns=\[(?P<vulns>.*?)\], cpes=\[(?P<cpes>.*?)\]"
)
_PIPE_TITLE_SOURCES = {"NEWS", "CERT-FR", "CERT-EU", "CISA-ADV"}


def _csv_fields(s: str) -> list[str]:
    return [x.strip().strip("'\"") for x in s.split(",") if x.strip()]


def _derive_item(source: str, raw_text: str) -> tuple[str, str, dict[str, Any] | None]:
    """Return (title, summary, structured) for one feed item."""
    src = (source or "").upper()
    text = (raw_text or "").strip()
    if not text:
        return source or "Unknown source", "", None

    if src == "SHODAN-INTERNETDB":
        m = _SHODAN_RE.match(text)
        if m:
            ports = _csv_fields(m.group("ports"))
            hostnames = _csv_fields(m.group("hostnames"))
            tags = _csv_fields(m.group("tags"))
            vulns = _csv_fields(m.group("vulns"))
            cpes = _csv_fields(m.group("cpes"))
            bits = []
            if ports:
                shown = ", ".join(ports[:8]) + ("…" if len(ports) > 8 else "")
                bits.append(f"{len(ports)} open port{'s' if len(ports) != 1 else ''} ({shown})")
            if hostnames:
                bits.append("hostname(s): " + ", ".join(hostnames[:4]))
            if vulns:
                bits.append("known CVE(s): " + ", ".join(vulns[:4]))
            if tags:
                bits.append("tags: " + ", ".join(tags[:4]))
            return (
                f"Shodan enrichment for {m.group('ip')}",
                " · ".join(bits) if bits else "No open ports or known CVEs found",
                {"ip": m.group("ip"), "ports": ports, "hostnames": hostnames,
                 "tags": tags, "vulns": vulns, "cpes": cpes},
            )

    if src in _PIPE_TITLE_SOURCES and " | " in text:
        title, body = text.split(" | ", 1)
        return title.strip(), body.strip(), None

    title = text.split("\n", 1)[0].strip()
    if len(title) > 120:
        title = title[:117].rstrip() + "…"
    return title, text, None


@router.get("")
async def list_feeds(
    request: Request,
    source: str | None = Query(default=None, description="Filter by feed source (CISA, CERT-FR, ...)"),
    category: str | None = Query(default=None, description="Filter by computed category"),
    threat: str | None = Query(default=None, description="Filter by threat category (Threat Landscape)"),
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
    if threat:
        if threat not in THREAT_CATEGORIES:
            raise HTTPException(status_code=422, detail=f"threat must be one of {THREAT_CATEGORIES}")
        where.append("threat_category = {th:String}")
        params["th"] = threat
    if search and search.strip():
        # positionCaseInsensitive = robust substring match (Unicode-aware, treats
        # literal % / _ as plain text) — never breaks on user punctuation.
        where.append("positionCaseInsensitive(raw_text, {s:String}) > 0")
        params["s"] = search.strip()

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
                "title": title,
                "summary": summary,
                "structured": structured,
            }
            for r in rows.result_rows
            for title, summary, structured in [_derive_item(r[0], r[3])]
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
