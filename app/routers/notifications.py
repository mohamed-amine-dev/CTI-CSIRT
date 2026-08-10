# =============================================================================
# CTI Platform - /api/v1/notifications routes (Phase 5 real-time alerting)
# -----------------------------------------------------------------------------
#   GET  /api/v1/notifications            -> list recent alerts (newest first)
#   GET  /api/v1/notifications/unread-count
#   POST /api/v1/notifications/read-all   -> mark everything read (Bearer)
#   POST /api/v1/notifications/{id}/read  -> mark one read (Bearer)
#   POST /api/v1/notifications/test       -> push a test alert (Bearer)
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.routers.ingest import _require_token

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


def _notifier(request: Request) -> Any:
    return request.app.state.pipeline.notifier


@router.get("")
async def list_notifications(
    request: Request,
    unread_only: bool = Query(default=False),
    severity: str | None = Query(default=None, description="CRITICAL/HIGH/MEDIUM/LOW/INFO"),
    category: str | None = Query(default=None, description="NEW_FICHE/KEV/SYSTEM"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Recent notifications, newest first. Always 200 (empty list on cold DB)."""
    return await _notifier(request).list(
        limit=limit, offset=offset, unread_only=unread_only, severity=severity, category=category,
    )


@router.get("/unread-count")
async def unread_count(request: Request) -> dict[str, Any]:
    """Number of unread alerts — the top-bar badge. Cheap count query."""
    return {"count": await _notifier(request).unread_count()}


@router.post("/read-all", status_code=200)
async def read_all(request: Request, _: None = Depends(_require_token)) -> dict[str, Any]:
    """Mark every notification as read. Returns how many were flipped."""
    return {"read": await _notifier(request).mark_all_read()}


@router.post("/{notif_id}/read", status_code=200)
async def mark_read(
    notif_id: str,
    request: Request,
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Mark a single notification as read."""
    if not await _notifier(request).mark_read(notif_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"read": True}


@router.post("/test", status_code=200)
async def test_alert(request: Request, _: None = Depends(_require_token)) -> dict[str, Any]:
    """Push a sample alert end-to-end (persist + Telegram) for demo purposes."""
    n = await _notifier(request).notify(
        category="SYSTEM",
        severity="INFO",
        title="Test alert — alerting pipeline operational",
        body="This is a manually triggered test. If you see this in Telegram, outbound alerting works.",
    )
    return {"sent": n is not None}
