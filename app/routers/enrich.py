# =============================================================================
# CTI Platform - /api/v1/enrich routes (free Shodan InternetDB enrichment)
# -----------------------------------------------------------------------------
# Proxies the free Shodan InternetDB API (https://internetdb.shodan.io) for the
# frontend "IoC & Shodan Lookup" view. A backend proxy is required because the
# InternetDB API does not send CORS headers, so a browser cannot call it
# directly. Enrichment is limited to IP addresses (the API's supported input).
# =============================================================================

from __future__ import annotations

import re
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1/enrich", tags=["enrich"])

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@router.get("/{indicator}")
async def shodan_lookup(indicator: str, request: Request) -> dict[str, Any]:
    """Return InternetDB enrichment for an IP: open ports, CVEs, hostnames, tags.

    `found: false` (with a human-readable detail) when the IP has no InternetDB
    record — the frontend renders that as a friendly empty state, not an error.
    """
    indicator = indicator.strip().lower()
    if not _IPV4_RE.match(indicator):
        raise HTTPException(
            status_code=422,
            detail="InternetDB only supports IPv4 addresses",
        )

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        resp = await client.get(f"https://internetdb.shodan.io/{indicator}")
        if resp.status_code == 404:
            return {"found": False, "indicator": indicator,
                    "detail": "No InternetDB record for this IP"}
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"InternetDB error: HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="InternetDB returned malformed data") from exc

    return {"found": True, "indicator": indicator, **data}
