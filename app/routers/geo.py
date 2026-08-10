# =============================================================================
# CTI Platform - /api/v1/geo routes (Threat-origin choropleth)
# -----------------------------------------------------------------------------
# Read-only endpoints over `ip_geo_cache` (populated by the GeoEnricher
# background task, see app/geo.py):
#
#   GET /api/v1/geo/summary?days=60 -> per-country count of indicator IPs
#                                      seen in the window (choropleth data)
#   GET /api/v1/geo/status          -> cache / quota / provider health
#
# Country attribution comes from the free, no-key ipwho.is provider. IPs whose
# lookup failed (private/reserved/unresolvable) are cached with status='fail'
# and never surface here — the map only shows *real* resolved countries.
# =============================================================================

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/v1/geo", tags=["geo"])


def _database(request: Request) -> str:
    return request.app.state.settings.clickhouse_database


@router.get("/summary")
async def geo_summary(
    request: Request,
    days: int = Query(default=60, ge=1, le=365),
) -> dict[str, Any]:
    """Per-country count of indicator IPs seen in the window.

    Only IPs geolocated successfully (status='ok') are counted; the
    choropleth therefore renders exclusively real resolutions.
    """
    rows = await request.app.state.db.query(
        """
        SELECT g.country_code, g.country_name, countDistinct(i.indicator)
        FROM {db:Identifier}.processed_iocs AS i FINAL
        ANY LEFT JOIN {db:Identifier}.ip_geo_cache AS g FINAL
          ON i.indicator = g.ip
        WHERE i.type IN ('ipv4', 'ipv6')
          AND g.status = 'ok'
          AND g.country_code != ''
          AND i.ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        GROUP BY g.country_code, g.country_name
        ORDER BY countDistinct(i.indicator) DESC
        """,
        parameters={"db": _database(request), "d": days},
    )
    countries = [
        {"code": r[0], "name": r[1], "count": r[2]} for r in rows.result_rows
    ]
    return {
        "countries": countries,
        "total": sum(c["count"] for c in countries),
    }


@router.get("/status")
async def geo_status(request: Request) -> dict[str, Any]:
    """Cache size, quota usage and last run — rendered as a small footer on
    the choropleth so analysts can trust (and audit) the coverage."""
    enricher = getattr(request.app.state.pipeline, "geo_enricher", None)
    if enricher is not None:
        return await enricher.status()
    return {"cached": 0, "ok": 0, "fail": 0, "countries": 0,
            "monthly_used": 0, "monthly_budget": 0, "provider": "", "last_run": None}
