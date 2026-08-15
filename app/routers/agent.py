# =============================================================================
# CTI Platform - /api/v1/agent routes (Autonomous CTI Triage & Enrichment)
# -----------------------------------------------------------------------------
#   POST /api/v1/agent/triage
#       {"indicator": "198.51.100.23", "type": "IPv4",
#        "context": "Observed in scanning logs"}
#
# Runs the LangGraph triage agent (app/agent/graph.py) against the indicator
# and returns the full ADR-shaped result: execution trace, tool outputs,
# risk assessment, and the generated Alert Sheet (when one was produced).
#
# Input security: the graph's sensor node sanitises the context and detects
# prompt injection BEFORE any tool or LLM call; flagged inputs are quarantined
# and returned with is_flagged_unsafe=true and the detection reasons.
# Same pattern as the project's other state-changing routes:
#   * bearer token required (see API_ACCESS_TOKEN in .env);
#   * the tools used inside the graph are strictly read-only.
# =============================================================================

from __future__ import annotations

import json
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.agent.graph import run_agent_triage

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])

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


# Indicator format validation (same shapes the enrich endpoint accepts).
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_CVE_RE = re.compile(r"^cve-\d{4}-\d{4,7}$", re.IGNORECASE)

# Accepted type aliases -> canonical internal type.
_TYPE_ALIASES: dict[str, str] = {
    "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv4",
    "domain": "domain", "hostname": "domain",
    "hash": "hash", "file": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "cve": "cve",
}

_TYPE_VALIDATORS: dict[str, re.Pattern[str]] = {
    "ipv4": _IPV4_RE,
    "domain": _DOMAIN_RE,
    "hash": _HASH_RE,
    "cve": _CVE_RE,
}


class TriageRequest(BaseModel):
    indicator: str = Field(min_length=1, description="The IoC (IP/domain/hash) or CVE to triage.")
    type: Literal["IPv4", "Domain", "Hash", "CVE"] = Field(default="IPv4", description="Indicator type.")
    context: str = Field(default="", max_length=20_000, description="Initial feed snippet / context for the indicator.")


@router.post("/triage")
async def agent_triage(request: Request, payload: TriageRequest, _: None = Depends(_require_token)) -> dict[str, Any]:
    """Run the autonomous triage agent against one indicator."""
    ctx = payload.context.strip()
    if not ctx:
        raise HTTPException(status_code=422, detail="'context' is required — the agent needs a raw feed snippet to analyse.")

    itype = _TYPE_ALIASES.get(payload.type.lower())
    if itype is None:
        raise HTTPException(status_code=422, detail=f"Unsupported type: {payload.type!r}")

    validator = _TYPE_VALIDATORS[itype]
    if not validator.match(payload.indicator.strip()):
        raise HTTPException(status_code=422, detail=f"Indicator {payload.indicator!r} does not look like a {itype}.")

    # Run the LangGraph agent.
    result = await run_agent_triage(
        db=request.app.state.db,
        settings=request.app.state.settings,
        indicator=payload.indicator.strip(),
        indicator_type=itype,
        context=ctx,
    )
    return result


@router.get("/history")
async def agent_history(
    request: Request,
    limit: int = 15,
    _: None = Depends(_require_token),
) -> dict[str, Any]:
    """Recent autonomous triage runs (audit trail), newest first.

    Read-only but token-guarded: the traces contain the indicators the CSIRT
    triaged and the quarantine reasons, so they stay internal like the
    state-changing triage route itself.
    """
    limit = max(1, min(limit, 100))
    db = request.app.state.db
    try:
        rows = await db.query(
            """
            SELECT indicator, indicator_type, risk_score, is_flagged_unsafe,
                   execution_trace, created_at
            FROM {db:Identifier}.agent_triage_results FINAL
            ORDER BY created_at DESC
            LIMIT {lim:UInt32}
            """,
            parameters={
                "db": request.app.state.settings.clickhouse_database,
                "lim": limit,
            },
        )
    except Exception as exc:  # noqa: BLE001 - surface a readable failure to the UI
        raise HTTPException(status_code=500, detail=f"Failed to read agent history: {exc}")

    items: list[dict[str, Any]] = []
    for r in rows.result_rows:
        trace_raw = r[4] or ""
        try:
            trace = json.loads(trace_raw) if trace_raw.strip() else []
        except ValueError:
            trace = []
        items.append(
            {
                "indicator": r[0],
                "type": r[1],
                "risk_score": r[2],
                "is_flagged_unsafe": bool(r[3]),
                "execution_trace": trace,
                "created_at": r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5]),
            }
        )
    return {"items": items}
