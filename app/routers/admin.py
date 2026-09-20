# =============================================================================
# Phase 4 - /api/v1/admin routes (TLP marking; privileged ops-token only)
# -----------------------------------------------------------------------------
# Only the privileged ops-token (settings.api_access_token) may call these.
# TLP marking uses INSERT..SELECT on the ReplacingMergeTree tables so a single
# TLP change re-writes a full row with a higher version — no other column is
# ever lost to merge defaults. Never touches existing read routes.
# =============================================================================

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import (
    TLP_ORDER,
    TLP_TIER,
    audit,
    assert_tlp_allowed,
    require_admin,
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

#: tables where the privileged ops-token may set TLP, plus the WHERE columns
#: matching each table's ReplacingMergeTree ORDER BY key.
TLP_TABLES: dict[str, list[str]] = {
    "threat_actors": ["stix_id"],
    "malware_tools": ["stix_id"],
    "attack_patterns": ["stix_id"],
    "processed_iocs": ["type", "indicator"],
    "raw_threat_intel": ["source", "url"],
    "vulnerability_alerts": ["vuln_cve"],
    "agent_triage_results": ["id"],
}


class SetTlpBody(BaseModel):
    table: str
    key: str
    key2: str | None = None
    tlp: str


def _coerce_tlp(value: str) -> str:
    v = value.strip().upper()
    valid = set(TLP_ORDER)
    if v not in valid:
        raise HTTPException(
            status_code=422,
            detail="tlp must be one of " + ", ".join(TLP_ORDER),
        )
    return v


@router.post("/tlp")
async def set_tlp(
    request: Request,
    body: SetTlpBody,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Mark a single item with a TLP level (privileged ops-token only).

    Enforces the requester's own clearance server-side: the privileged token is
    the only credential allowed to RAISE an item to RED, so a plain user can
    never escalate their own access this way.
    """
    table = body.table
    if table not in TLP_TABLES:
        raise HTTPException(
            status_code=422,
            detail="table must be one of " + ", ".join(sorted(TLP_TABLES)),
        )
    where_cols = TLP_TABLES[table]
    if body.key2 is not None and len(where_cols) < 2:
        raise HTTPException(status_code=422, detail=f"{table} uses a single key, key2 not allowed")

    tlp = _coerce_tlp(body.tlp)
    policy = request.state.user_policy
    assert_tlp_allowed(tlp, policy.get("tier", 0))

    keys = [body.key] + ([body.key2] if body.key2 is not None else [])
    if len(keys) < len(where_cols):
        raise HTTPException(status_code=422, detail=f"{table} needs {len(where_cols)} key(s): {', '.join(where_cols)}")

    db = request.app.state.db
    settings = request.app.state.settings
    where = " AND ".join(
        f"{col} = {{k{i}:String}}" for i, col in enumerate(where_cols)
    )
    params: dict[str, Any] = {f"k{i}": keys[i] for i in range(len(where_cols))}

    rows = await db.query(
        f"SELECT count() FROM {settings.clickhouse_database}.{table} FINAL WHERE {where}",
        parameters=params,
    )
    if not rows.result_rows or rows.result_rows[0][0] == 0:
        desc = table.replace("_", " ")
        raise HTTPException(status_code=404, detail=f"{desc} not found: {' / '.join(keys)}")

    version = int(time.time() * 1_000_000)
    params["tlp"] = tlp
    params["ver"] = version
    resource = f"{table}:{'/'.join(keys)}"
    await db.command(
        f"""
        INSERT INTO {settings.clickhouse_database}.{table}
        SELECT * EXCEPT (tlp, version),
               {{tlp:String}} AS tlp,
               {{ver:UInt64}} AS version
        FROM {settings.clickhouse_database}.{table} FINAL
        WHERE {where}
        """,
        parameters=params,
    )
    await audit(request, "modify.tlp_set", resource, tlp)
    return {"status": "ok", "resource": resource, "tlp": tlp}


@router.get("/tlp/values", include_in_schema=False)
async def tlp_values() -> dict[str, Any]:
    """Expose the TLP model to the admin UI."""
    return {
        "tlp_order": TLP_ORDER,
        "tlp_tier": {k: v for k, v in TLP_TIER.items()},
        "tables": sorted(TLP_TABLES),
    }