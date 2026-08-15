# =============================================================================
# CTI Platform - /api/v1/search routes (global analyst search)
# -----------------------------------------------------------------------------
# One endpoint, three backends. Runs a single normalized query across the
# platform's read models and groups hits by kind so the Search & Export hub can
# render one pane per corpus:
#
#   raw_threat_intel    -> `feeds`   (source / url / raw_text)
#   processed_iocs      -> `iocs`    (indicator / type / severity)
#   vulnerability_alerts-> `alerts`  (CVE / ai_summary)
#
# Every hit carries its `kind` plus a `relevance` hint (score / ts) so the UI
# can sort within a group. All matching is Unicode-aware case-insensitive
# substring via positionCaseInsensitive (never breaks on user punctuation).
# =============================================================================

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(prefix="/api/v1/search", tags=["search"])

VALID_KINDS = ("feeds", "iocs", "alerts")


def _parse_risk(raw: str) -> dict[str, Any]:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"risk_level": raw}


@router.get("")
async def global_search(
    request: Request,
    q: str = Query(default="", description="Search term across all corpora"),
    kind: str | None = Query(default=None, description="Restrict to feeds|iocs|alerts"),
    limit: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    """Search feeds, iocs and sheets in one call, grouped by corpus."""
    term = (q or "").strip()
    if not term:
        return {"query": term, "results": {"feeds": [], "iocs": [], "alerts": []}, "total": 0}

    db = request.app.state.db
    database = request.app.state.settings.clickhouse_database
    kinds = [k for k in VALID_KINDS if kind in (None, k)]
    if kind and kind not in VALID_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {VALID_KINDS}")

    out: dict[str, list[dict[str, Any]]] = {"feeds": [], "iocs": [], "alerts": []}
    total = 0

    if "feeds" in kinds:
        rows = await db.query(
            """
            SELECT source, url, raw_text, ts
            FROM {db:Identifier}.raw_threat_intel FINAL
            WHERE positionCaseInsensitive(raw_text, {t:String}) > 0
               OR positionCaseInsensitive(url, {t2:String}) > 0
               OR positionCaseInsensitive(source, {t3:String}) > 0
            ORDER BY ts DESC
            LIMIT {lim:UInt32}
            """,
            parameters={"db": database, "t": term, "t2": term, "t3": term, "lim": limit},
        )
        for r in rows.result_rows:
            out["feeds"].append({
                "kind": "feeds",
                "source": r[0],
                "url": r[1],
                "snippet": (r[2] or "")[:500],
                "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
            })
        total += len(rows.result_rows)

    if "iocs" in kinds:
        rows = await db.query(
            """
            SELECT indicator, type, severity, ts
            FROM {db:Identifier}.processed_iocs FINAL
            WHERE positionCaseInsensitive(indicator, {t:String}) > 0
            ORDER BY severity DESC, ts DESC
            LIMIT {lim:UInt32}
            """,
            parameters={"db": database, "t": term, "lim": limit},
        )
        for r in rows.result_rows:
            out["iocs"].append({
                "kind": "iocs",
                "indicator": r[0],
                "type": r[1],
                "severity": r[2],
                "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
            })
        total += len(rows.result_rows)

    if "alerts" in kinds:
        rows = await db.query(
            """
            SELECT vuln_cve, risk_level, threat_score, ai_summary, ts
            FROM {db:Identifier}.vulnerability_alerts FINAL
            WHERE positionCaseInsensitive(vuln_cve, {t:String}) > 0
               OR positionCaseInsensitive(ai_summary, {t2:String}) > 0
            ORDER BY ts DESC
            LIMIT {lim:UInt32}
            """,
            parameters={"db": database, "t": term, "t2": term, "lim": limit},
        )
        for r in rows.result_rows:
            out["alerts"].append({
                "kind": "alerts",
                "vuln_cve": r[0],
                "risk_level": _parse_risk(r[1]),
                "threat_score": r[2],
                "snippet": (r[3] or "")[:500],
                "ts": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
            })
        total += len(rows.result_rows)

    return {"query": term, "results": out, "total": total}
