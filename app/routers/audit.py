# =============================================================================
# Phase 4 - /api/v1/audit routes (searchable, append-only audit log; admin)
# -----------------------------------------------------------------------------
# Read-only window over the `audit_log` table. Rows are written by
# app/auth.audit() on every interesting action (login, 2FA, views, exports,
# mutations). Result cap keeps the endpoint safe for the UI.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.auth import require_admin

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

_MAX_ROWS = 500


class AuditFilter(BaseModel):
    search: str = ""
    event: str = ""
    username: str = ""
    limit: int = _MAX_ROWS


@router.get("")
async def list_audit(
    request: Request,
    search: str = "",
    event: str = "",
    username: str = "",
    limit: int = _MAX_ROWS,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Admin-only, searchable audit trail (newest first, capped at 500 rows)."""
    if limit < 1:
        limit = 50
    limit = min(limit, _MAX_ROWS)

    clauses: list[str] = []
    params: dict[str, Any] = {}
    if search:
        clauses.append(
            "positionCaseInsensitive(concat(event, ' ', username, ' ', resource, ' ', detail), {s:String}) > 0"
        )
        params["s"] = search
    if event:
        clauses.append("event = {e:String}")
        params["e"] = event
    if username:
        clauses.append("username = {u:String}")
        params["u"] = username
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    settings = request.app.state.settings
    db = request.app.state.db
    rows = await db.query(
        f"""
        SELECT event, coalesce(username, ''), resource, detail, ts
        FROM {settings.clickhouse_database}.audit_log
        {where}
        ORDER BY ts DESC, id
        LIMIT {{lim:UInt32}}
        """,
        parameters={**params, "lim": limit},
    )
    entries = [
        {
            "event": r[0],
            "username": r[1],
            "resource": r[2],
            "detail": r[3],
            "ts": r[4].isoformat() if r[4] else None,
        }
        for r in rows.result_rows
    ]
    return {"entries": entries}


@router.get("/events")
async def list_events(
    request: Request,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Distinct event names currently in the log (fills the filter dropdown)."""
    settings = request.app.state.settings
    rows = await request.app.state.db.query(
        f"SELECT DISTINCT event FROM {settings.clickhouse_database}.audit_log ORDER BY event"
    )
    return {"events": [r[0] for r in rows.result_rows]}