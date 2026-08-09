# =============================================================================
# CTI Platform - /api/v1/ingest routes (state-changing operations)
# -----------------------------------------------------------------------------
#   POST /api/v1/ingest          -> run a single poll across all collectors
#   POST /api/v1/process         -> raw text -> Fiche d'Alerte (on demand)
#
# Both endpoints require a Bearer token (see API_ACCESS_TOKEN in .env). This is
# deliberately simple and stateless; a full auth layer belongs to the React app.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.ai_processor import FicheAlerteModel, generate_fiche_d_alerte

router = APIRouter(prefix="/api/v1", tags=["ingest"])

# FastAPI's HTTPBearer auto-validates the "Authorization: Bearer ..." header.
_bearer = HTTPBearer(auto_error=False)


def _require_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Reject requests that do not carry the configured access token."""
    expected = request.app.state.settings.api_access_token
    if creds is None or creds.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing access token")


@router.post("/ingest", status_code=202)
async def trigger_ingest(request: Request, _: None = Depends(_require_token)) -> dict[str, Any]:
    """Run one synchronous poll across every enabled collector and return stats.

    Useful for manual refresh from the frontend ("Sync now" button) and for
    cron-based scheduling without keeping the event loop permanently busy.
    """
    pipeline = request.app.state.pipeline
    result = await pipeline.run_once()
    return {"status": "accepted", **result}


@router.post("/process", status_code=200)
async def process_text(request: Request, payload: dict[str, Any], _: None = Depends(_require_token)) -> dict[str, Any]:
    """On-demand Fiche d'Alerte generation from arbitrary advisory text.

    Body: {"text": "<raw advisory text>"}
    Uses the exact same dedup rules as the background ingestion pipeline.
    """
    text = (payload.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="Missing 'text' field")

    result = await generate_fiche_d_alerte(text, request.app.state.db, request.app.state.settings)
    if result is None:
        return {"generated": False, "reason": "No CVE identifier found in text"}
    if isinstance(result, FicheAlerteModel):
        return {"generated": True, "cve": result.vuln_cve, "fiche": result.model_dump()}
    return {"generated": False, **result}
