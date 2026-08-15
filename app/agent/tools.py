# =============================================================================
# CTI Platform - Agent tools (strictly read-only)
# -----------------------------------------------------------------------------
# The tools the triage graph is allowed to call. Every tool is read-only:
#   * shodan_internetdb()         -> free, zero-auth Shodan InternetDB lookup
#   * clickhouse_knowledge_search() -> historical correlation over ClickHouse
#
# Hard rules:
#   * No tool can INSERT / UPDATE / DELETE / ALTER anything.
#   * Every tool returns JSON-safe primitives and never raises: a network or
#     DB failure becomes a `{found: False, detail: ...}` result so the graph
#     can continue and reason about the gap honestly.
# =============================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


async def shodan_internetdb(ip: str) -> dict[str, Any]:
    """Read-only Shodan InternetDB lookup (free, no API key).

    Returns open ports, CVEs, hostnames, tags and CPEs when the IP has a
    record; `{found: False, detail: ...}` otherwise. A 404 simply means "no
    record" — it is an honest answer, not an error.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(_SHODAN_INTERNETDB_URL.format(ip=ip))
    except Exception as exc:  # noqa: BLE001
        return {"source": "shodan_internetdb", "found": False, "detail": f"unreachable: {exc}"}
    if resp.status_code == 404:
        return {"source": "shodan_internetdb", "found": False, "detail": "no InternetDB record for this IP"}
    if resp.status_code != 200:
        return {"source": "shodan_internetdb", "found": False, "detail": f"HTTP {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"source": "shodan_internetdb", "found": False, "detail": "malformed response"}
    return {
        "source": "shodan_internetdb",
        "found": True,
        "ip": data.get("ip"),
        "ports": data.get("ports") or [],
        "cves": data.get("vulns") or [],
        "hostnames": data.get("hostnames") or [],
        "tags": data.get("tags") or [],
        "cpes": data.get("cpes") or [],
    }


async def clickhouse_knowledge_search(
    db: Any,
    indicator: str,
    indicator_type: str,
    dbname: str,
    days: int = 365,
) -> dict[str, Any]:
    """Read-only historical correlation against our own ClickHouse corpus.

    Two lookups:
      * processed_iocs  -> have we seen this exact indicator before? how many
                           times, at what max severity, last seen when?
      * raw_threat_intel-> how many raw records mention it in the last `days`,
                           and across how many distinct feed sources?

    Note: substring matching on raw_text can over-count for very short
    indicators (e.g. an IPv4 octet). The result is a signal, not a verdict —
    the synthesis node is told this explicitly.
    """
    results: dict[str, Any] = {"source": "clickhouse_knowledge", "processed": {}, "raw_matches": {}}

    try:
        rows = await db.query(
            """
            SELECT count(), max(severity), max(ts)
            FROM {db:Identifier}.processed_iocs FINAL
            WHERE indicator = {ind:String}
            """,
            parameters={"db": dbname, "ind": indicator},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("knowledge search processed_iocs failed: %s", exc)
        results["processed"] = {"found": False, "detail": str(exc)[:300]}
    else:
        r = rows.result_rows[0] if rows.result_rows else (0, None, None)
        results["processed"] = {
            "found": int(r[0]) > 0,
            "sightings": int(r[0]),
            "max_severity": float(r[1]) if r[1] is not None else None,
            "last_seen": r[2].isoformat() if r[2] is not None else None,
        }

    try:
        raw_rows = await db.query(
            """
            SELECT count(), uniqExact(source)
            FROM {db:Identifier}.raw_threat_intel FINAL
            WHERE ts >= now() - INTERVAL {d:UInt32} DAY
              AND positionCaseInsensitive(raw_text, {ind:String}) > 0
            """,
            parameters={"db": dbname, "ind": indicator, "d": days},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("knowledge search raw_threat_intel failed: %s", exc)
        results["raw_matches"] = {"found": False, "detail": str(exc)[:300]}
    else:
        r = raw_rows.result_rows[0] if raw_rows.result_rows else (0, 0)
        results["raw_matches"] = {
            "found": int(r[0]) > 0,
            "records": int(r[0]),
            "sources": int(r[1]),
            "window_days": days,
        }

    return results
