# =============================================================================
# CTI Platform - /api/v1/watchlist routes (Org Exposure Search & Watchlist)
# -----------------------------------------------------------------------------
#   GET  /api/v1/watchlist            -> saved targets (active)
#   POST /api/v1/watchlist            -> register a target (domain/phone/email/org)
#   DELETE /api/v1/watchlist/{id}     -> soft-delete a target
#   GET  /api/v1/watchlist/search     -> immediate real-match search over the
#                                         ingested dark-web/telegram corpus
#   GET  /api/v1/watchlist/matches    -> recorded matches (from the sweep)
#   POST /api/v1/watchlist/sweep      -> run the background sweep now (admin)
#
# Matching is deterministic and driven by app/watchlist.py; the search scans
# the REAL corpus (raw_threat_intel, DARKWEB-ONION + TELEGRAM) and never
# fabricates a match. A zero-result search is a legitimate outcome and is
# reported as total=0 with an empty list.
# =============================================================================

from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..darkweb_analytics import extract_signals
from ..watchlist import TARGET_TYPES, domain_valid, match_item, normalize_domain

router = APIRouter(prefix="/api/v1/watchlist", tags=["watchlist"])

_bearer = HTTPBearer(auto_error=False)


def _require_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Same Bearer-token gate as the other state-changing router (ingest)."""
    expected = request.app.state.settings.api_access_token
    if creds is None or creds.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing access token")


# "Org exposure" searches the dark-web / telegram surface only — matching the
# brief (dark web + Telegram content you're already ingesting). These are the
# two sources the collectors store under.
_SEARCH_SOURCES = ("DARKWEB-ONION", "TELEGRAM")
_SEARCH_LIMIT = 500  # the dark corpus is small; hard cap keeps it honest


def _target_row(r: Any) -> dict[str, Any]:
    return {
        "id": str(r[0]),
        "type": str(r[1]),
        "value": str(r[2]),
        "label": str(r[3] or ""),
        "active": int(r[4]),
        "created_at": r[5].strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(r[5], "strftime") else str(r[5]),
    }


@router.get("")
async def list_targets(request: Request) -> dict[str, Any]:
    """Every active (non-deleted) watchlist target, newest first."""
    db = request.app.state.db
    rows = await db.query(
        "SELECT id, target_type, value, label, active, created_at "
        "FROM {db:Identifier}.watchlist_targets FINAL WHERE active = 1 "
        "ORDER BY created_at DESC",
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    items = [_target_row(r) for r in rows.result_rows]
    return {"items": items, "total": len(items)}


@router.post("", status_code=201)
async def add_target(
    request: Request,
    payload: dict[str, Any],
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Register a target: {"type": domain|phone|email|org, "value": ..., "label": ...}"""
    ttype = str(payload.get("type") or "").strip().lower()
    value = str(payload.get("value") or "").strip()
    label = str(payload.get("label") or "").strip()
    if ttype not in TARGET_TYPES:
        raise HTTPException(status_code=422, detail=f"type must be one of {list(TARGET_TYPES)}")
    if not value:
        raise HTTPException(status_code=422, detail="value is required")
    if ttype == "domain":
        nv = normalize_domain(value)
        if not domain_valid(nv):
            raise HTTPException(status_code=422, detail="value is not a valid domain")
        value = nv

    db = request.app.state.db
    dbn = request.app.state.settings.clickhouse_database

    # Dedup: an already-active identical target is returned as-is (no dup rows).
    dup = await db.query(
        "SELECT id FROM {db:Identifier}.watchlist_targets FINAL "
        "WHERE active = 1 AND target_type = {t:String} AND value = {v:String}",
        parameters={"db": dbn, "t": ttype, "v": value},
    )
    if dup.result_rows:
        tid = str(dup.result_rows[0][0])
        rows = await db.query(
            "SELECT id, target_type, value, label, active, created_at "
            "FROM {db:Identifier}.watchlist_targets FINAL WHERE id = {tid:UUID}",
            parameters={"db": dbn, "tid": tid},
        )
        return {"created": False, "target": _target_row(rows.result_rows[0])}

    nid = uuid.uuid4()
    await db.insert(
        "watchlist_targets",
        [[str(nid), ttype, value, label, 1, int(time.time() * 1_000_000)]],
        column_names=["id", "target_type", "value", "label", "active", "version"],
    )
    return {
        "created": True,
        "target": {
            "id": str(nid), "type": ttype, "value": value, "label": label,
            "active": 1, "created_at": "",
        },
    }


@router.delete("/{target_id}")
async def delete_target(
    target_id: str,
    request: Request,
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Soft-delete a target (active=0 via ReplacingMergeTree re-insert)."""
    db = request.app.state.db
    dbn = request.app.state.settings.clickhouse_database
    rows = await db.query(
        "SELECT target_type, value, label, created_at FROM {db:Identifier}.watchlist_targets FINAL "
        "WHERE id = {tid:UUID} AND active = 1",
        parameters={"db": dbn, "tid": target_id},
    )
    if not rows.result_rows:
        raise HTTPException(status_code=404, detail="Unknown or already-deleted target")
    r = rows.result_rows[0]
    await db.insert(
        "watchlist_targets",
        [[target_id, r[0], r[1], r[2], 0, int(time.time() * 1_000_000)]],
        column_names=["id", "target_type", "value", "label", "active", "version"],
    )
    return {"deleted": True, "id": target_id}


@router.get("/search")
async def search_exposure(
    request: Request,
    type: str = Query(..., description="domain | phone | email | org"),
    value: str = Query(..., description="the value to search for"),
    limit: int = Query(default=_SEARCH_LIMIT, ge=1, le=_SEARCH_LIMIT),
) -> dict[str, Any]:
    """Immediate real-match search over the ingested dark-web/telegram corpus.

    Every returned item carries the precise span(s) of the matched term so the
    UI can highlight it. Honest zero-result: total=0 and an empty items list.
    """
    ttype = (type or "").strip().lower()
    value = (value or "").strip()
    if ttype not in TARGET_TYPES:
        raise HTTPException(status_code=422, detail=f"type must be one of {list(TARGET_TYPES)}")
    if not value:
        raise HTTPException(status_code=422, detail="value is required")
    if ttype == "domain":
        nv = normalize_domain(value)
        if not domain_valid(nv):
            raise HTTPException(status_code=422, detail="value is not a valid domain")
        value = nv

    db = request.app.state.db
    dbn = request.app.state.settings.clickhouse_database
    rows = await db.query(
        "SELECT source, url, raw_text, ts "
        "FROM {db:Identifier}.raw_threat_intel FINAL "
        "WHERE source IN ('DARKWEB-ONION', 'TELEGRAM') "
        "ORDER BY ts DESC LIMIT {lim:UInt32}",
        parameters={"db": dbn, "lim": limit},
    )

    items: list[dict[str, Any]] = []
    matched_total = 0
    for r in rows.result_rows:
        source, url, raw_text, ts = r[0], r[1], r[2], r[3]
        domains = extract_signals(raw_text or "").get("domains", []) if ttype == "domain" else None
        ms = match_item(raw_text or "", ttype, value, domains)
        if not ms:
            continue
        matched_total += len(ms)
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(ts, "strftime") else str(ts)
        title = (raw_text or "").split("\n", 1)[0].strip()[:140]
        items.append({
            "source": source, "url": url, "raw_text": raw_text, "ts": ts_iso,
            "title": title or source, "matches": ms,
        })

    return {
        "type": ttype, "value": value, "total": matched_total,
        "items_matched": len(items), "scanned": len(rows.result_rows),
        "items": items,
    }


@router.get("/matches")
async def list_matches(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Recorded sweep matches (newest first), joined to their target."""
    db = request.app.state.db
    dbn = request.app.state.settings.clickhouse_database
    rows = await db.query(
        f"SELECT m.id, m.target_id, m.source, m.url, m.matched_term, m.snippet, m.created_at, "
        f"       t.target_type, t.value, t.label "
        f"FROM {dbn}.watchlist_matches AS m FINAL "
        f"LEFT JOIN (SELECT id, target_type, value, label FROM {dbn}.watchlist_targets FINAL) AS t "
        f"ON m.target_id = t.id "
        f"ORDER BY m.created_at DESC LIMIT {{lim:UInt32}}",
        parameters={"lim": limit},
    )
    items = [
        {
            "id": str(r[0]), "target_id": str(r[1]), "source": str(r[2]),
            "url": str(r[3]), "matched_term": str(r[4]), "snippet": str(r[5]),
            "created_at": r[6].strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(r[6], "strftime") else str(r[6]),
            "target_type": str(r[7] or ""), "target_value": str(r[8] or ""),
            "target_label": str(r[9] or ""),
        }
        for r in rows.result_rows
    ]
    return {"items": items, "total": len(items)}


@router.post("/sweep", status_code=202)
async def sweep_now(
    request: Request,
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Run the watchlist sweep immediately (mirrors what every ingestion cycle
    does in the background) and return what it found."""
    pipeline = request.app.state.pipeline
    result = await pipeline._sweep_watchlist()
    result["status"] = "done"
    return result