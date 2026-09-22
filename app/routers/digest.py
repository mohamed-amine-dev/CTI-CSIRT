# =============================================================================
# Daily email digest — admin API (/api/v1/digest)
# -----------------------------------------------------------------------------
# Every route is gated by `require_admin` (the existing RBAC gate: privileged
# ops-token or an admin user token). There is deliberately NO public sign-up
# endpoint — recipients are only ever written here or via the
# tools/manage_digest_recipients.py CLI. Sending is refused (503) until real
# SMTP credentials are configured in .env; nothing is hard-coded.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import audit, require_admin
from app.digest import (
    FREQUENCIES,
    list_recipients,
    remove_recipient,
    run_due_digests,
    send_test_digest,
    smtp_configured,
    upsert_recipient,
    valid_email,
    valid_frequency,
)

router = APIRouter(prefix="/api/v1/digest", tags=["digest"])


class RecipientBody(BaseModel):
    email: str
    frequency: str = "daily"
    enabled: bool = True


class RecipientPatch(BaseModel):
    frequency: str | None = None
    enabled: bool | None = None


class TestBody(BaseModel):
    email: str
    window_days: int = 1


def _require_smtp(request: Request) -> None:
    settings = request.app.state.settings
    if not smtp_configured(settings):
        raise HTTPException(
            status_code=503,
            detail=(
                "SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME, "
                "SMTP_PASSWORD and SMTP_FROM in .env, then restart the app."
            ),
        )


@router.get("/status")
async def digest_status(
    request: Request,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Configuration + due state for the admin settings page."""
    settings = request.app.state.settings
    db = request.app.state.db
    recipients = await list_recipients(db, settings)
    return {
        "smtp_configured": smtp_configured(settings),
        "digest_enabled": settings.digest_enabled,
        "digest_hour_utc": settings.digest_hour_utc,
        "from_address": settings.smtp_from or settings.smtp_username,
        "frequencies": list(FREQUENCIES),
        "recipients_total": len(recipients),
        "recipients_due": sum(1 for r in recipients if r["due_now"]),
    }


@router.get("/recipients")
async def get_recipients(
    request: Request,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """The admin-managed recipient list with computed cadence/due state."""
    recipients = await list_recipients(
        request.app.state.db, request.app.state.settings
    )
    return {"items": recipients, "total": len(recipients)}


@router.post("/recipients", status_code=201)
async def add_recipient(
    request: Request,
    body: RecipientBody,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Add a recipient (or update the cadence of an existing one)."""
    email = body.email.strip().lower()
    if not valid_email(email):
        raise HTTPException(status_code=422, detail="invalid email address")
    if not valid_frequency(body.frequency):
        raise HTTPException(
            status_code=422,
            detail="frequency must be one of " + ", ".join(FREQUENCIES),
        )
    result = await upsert_recipient(
        request.app.state.db,
        request.app.state.settings,
        email,
        frequency=body.frequency,
        enabled=body.enabled,
        added_by=request.state.user_policy.get("username") or "ops-token",
    )
    await audit(request, "modify.digest_recipient_add", email,
                f"frequency={body.frequency} enabled={body.enabled}")
    return {"status": "ok", **result}


@router.patch("/recipients/{email}")
async def update_recipient(
    request: Request,
    email: str,
    body: RecipientPatch,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Change an existing recipient's cadence and/or enabled flag."""
    settings = request.app.state.settings
    db = request.app.state.db
    current = await list_recipients(db, settings)
    match = next((r for r in current if r["email"] == email.strip().lower()), None)
    if match is None:
        raise HTTPException(status_code=404, detail=f"recipient not found: {email}")
    frequency = body.frequency if body.frequency is not None else match["frequency"]
    enabled = body.enabled if body.enabled is not None else match["enabled"]
    if not valid_frequency(frequency):
        raise HTTPException(
            status_code=422,
            detail="frequency must be one of " + ", ".join(FREQUENCIES),
        )
    result = await upsert_recipient(
        db, settings, match["email"],
        frequency=frequency, enabled=enabled, added_by=match["added_by"],
    )
    await audit(request, "modify.digest_recipient_update", match["email"],
                f"frequency={frequency} enabled={enabled}")
    return {"status": "ok", **result}


@router.delete("/recipients/{email}")
async def delete_recipient(
    request: Request,
    email: str,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Hard-remove a recipient from the mailing list."""
    removed = await remove_recipient(
        request.app.state.db, request.app.state.settings, email
    )
    if not removed:
        raise HTTPException(status_code=404, detail=f"recipient not found: {email}")
    await audit(request, "modify.digest_recipient_remove", email)
    return {"status": "ok", "email": email.strip().lower()}


@router.post("/run")
async def run_now(
    request: Request,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Send to every recipient whose cadence is due right now.

    This is the same code path the daily scheduler runs; it bypasses only the
    once-per-day watermark so an admin can verify cadence on demand. Disabled
    recipients are skipped entirely.
    """
    _require_smtp(request)
    result = await run_due_digests(
        request.app.state.db, request.app.state.settings
    )
    await audit(request, "modify.digest_run", "due",
                f"due={result.get('due')} sent={result.get('sent')}")
    return result


@router.post("/send-test")
async def send_test(
    request: Request,
    body: TestBody,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Send an immediate digest to one address, without touching the list."""
    _require_smtp(request)
    window = 1 if body.window_days < 1 else min(body.window_days, 30)
    result = await send_test_digest(
        request.app.state.db, request.app.state.settings, body.email, window
    )
    if not result.get("sent"):
        raise HTTPException(status_code=502, detail=result.get("error") or "send failed")
    await audit(request, "modify.digest_send_test", body.email, result.get("subject", ""))
    return result
