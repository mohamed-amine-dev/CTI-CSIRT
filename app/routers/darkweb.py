# =============================================================================
# CTI Platform - /api/v1/darkweb routes (Dark Web / Telegram monitoring)
# -----------------------------------------------------------------------------
# Additive analytics endpoint powering the Dark Web & Telegram Monitoring
# views. Returns the same feed items the views already consumed, plus a
# deterministic per-item analysis (severity band + reasons, theme grouping,
# extracted signals, and a "why it matters" briefing) computed from the item's
# own raw text by app/darkweb_analytics.py. No fabricated fields.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from ..darkweb_analytics import analyze
from .feeds import VALID_CHANNELS, _derive_item

router = APIRouter(prefix="/api/v1/darkweb", tags=["darkweb"])


@router.get("/monitor")
async def darkweb_monitor(
    request: Request,
    channel: str = Query(default="darkweb", description="darkweb or telegram"),
    limit: int = Query(default=500, ge=1, le=500),
) -> dict[str, Any]:
    """Enriched stream for one monitoring channel, newest first.

    `total` is the real count for the channel (COUNT over the same WHERE),
    not the page size. Each item carries `analysis` computed deterministically
    from its own text.
    """
    chan = channel.strip().lower()
    source = VALID_CHANNELS.get(chan)
    if source is None:
        raise HTTPException(status_code=422, detail=f"channel must be one of {sorted(VALID_CHANNELS)}")

    db = request.app.state.db
    db_name = request.app.state.settings.clickhouse_database

    count_rows = await db.query(
        f"""
        SELECT count()
        FROM {{db:Identifier}}.raw_threat_intel FINAL
        WHERE source = {{src:String}}
        """,
        parameters={"db": db_name, "src": source},
    )
    total = count_rows.result_rows[0][0] if count_rows.result_rows else 0

    rows = await db.query(
        f"""
        SELECT source, url, raw_text, ts
        FROM {{db:Identifier}}.raw_threat_intel FINAL
        WHERE source = {{src:String}}
        ORDER BY ts DESC
        LIMIT {{lim:UInt32}}
        """,
        parameters={"db": db_name, "src": source, "lim": limit},
    )

    items = []
    for r in rows.result_rows:
        raw_text = r[2]
        source_name = r[0]
        title, summary, structured = _derive_item(source_name, raw_text)
        ts_sec = r[3].timestamp() if hasattr(r[3], "timestamp") else None
        items.append({
            "source": source_name,
            "url": r[1],
            "raw_text": raw_text,
            "ts": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
            "title": title,
            "summary": summary,
            "structured": structured,
            "analysis": analyze(raw_text, source_name, ts_sec),
        })

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "channel": chan,
        "source": source,
    }