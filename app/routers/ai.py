# =============================================================================
# CTI Platform - /api/v1/ai routes (AI fiche pipeline status)
# -----------------------------------------------------------------------------
# Exposes the durable state of the Fiche d'Alerte generation pipeline so the
# frontend can show real pending / processing / done / failed counts and the
# configured LLM provider instead of pretending every CVE becomes a fiche.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from app.config import settings
from app.routers.ingest import _require_token

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


@router.get("/status")
async def ai_status(request: Request) -> dict[str, Any]:
    """Aggregate counts of the AI fiche pipeline + the configured provider.

    Reads `fiche_pending` FINAL so the numbers are always the honest latest
    state, even across restarts. Returns 200 with zeros when the table is
    empty (cold start) — never a 500.
    """
    db = request.app.state.db
    counts: dict[str, int] = {"pending": 0, "processing": 0, "done": 0, "failed": 0}
    try:
        rows = await db.query(
            "SELECT status, count() FROM {db:Identifier}.fiche_pending FINAL GROUP BY status",
            parameters={"db": settings.clickhouse_database},
        )
        for status, n in rows.result_rows:
            counts[status] = int(n)
    except Exception:  # noqa: BLE001 - table may not exist yet on a cold boot
        pass
    return {"counts": counts, "provider": settings.llm_provider}


@router.post("/retry-failed", status_code=202)
async def retry_failed(
    request: Request,
    cve: str | None = Query(default=None, description="Retry a single failed CVE; omit to retry all"),
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Manually re-enqueue failed fiches (admin / analyst action).

    Resets their attempt counter and status to pending so they are picked up
    immediately, bypassing the scheduler's cooldown. Returns how many CVEs were
    enqueued.
    """
    pipeline = request.app.state.pipeline
    requeued = await pipeline.retry_failed_fiches(cve)
    return {"status": "accepted", "requeued": requeued}
