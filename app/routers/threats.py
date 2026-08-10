# =============================================================================
# CTI Platform - /api/v1/threats routes (Threat Landscape dashboard)
# -----------------------------------------------------------------------------
# Aggregations over raw_threat_intel for the "Threat & Malware Category
# Landscape" panel:
#
#   GET /api/v1/threats/landscape?days=60  -> weekly-bucket trend per category
#                                             + ranked totals (top attack types)
#   GET /api/v1/threats/ports?days=60      -> top exposed ports & services
#   GET /api/v1/threats/cves?days=60       -> most frequently seen CVEs
#
# The `threat_category` column is populated at ingestion by the deterministic
# classifier (app/threat_classify.py) and backfilled for existing rows.
# Ports / CVEs are parsed from the real Shodan InternetDB enrichment records.
# =============================================================================

from __future__ import annotations

import re
from typing import Any
from collections import Counter

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])

_SHODAN_RE = re.compile(
    r"^InternetDB enrichment for (?P<ip>[^:]+): ports=\[(?P<ports>.*?)\], "
    r"hostnames=\[(?P<hostnames>.*?)\], tags=\[(?P<tags>.*?)\], "
    r"vulns=\[(?P<vulns>.*?)\], cpes=\[(?P<cpes>.*?)\]"
)

# Well-known port -> service name (fixed mapping, used only for display).
_PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 2376: "Docker TLS", 3000: "HTTP-Alt", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt",     9200: "Elasticsearch", 9300: "ES-TCP",
    11211: "Memcached", 27017: "MongoDB", 50070: "HDFS",
}


def _db(request: Request) -> Any:
    return request.app.state.db


def _database(request: Request) -> str:
    return request.app.state.settings.clickhouse_database


@router.get("/landscape")
async def threat_landscape(
    request: Request,
    days: int = Query(default=60, ge=1, le=365),
) -> dict[str, Any]:
    """Weekly-bucket trend + ranked totals of threat categories."""
    rows = await _db(request).query(
        """
        SELECT toStartOfWeek(ts) AS week, threat_category, count()
        FROM {db:Identifier}.raw_threat_intel FINAL
        WHERE ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        GROUP BY week, threat_category
        ORDER BY week, count() DESC
        """,
        parameters={"db": _database(request), "d": days},
    )

    totals: Counter[str] = Counter()
    buckets: dict[str, dict[str, int]] = {}
    for week, category, count in rows.result_rows:
        week_key = week.strftime("%Y-%m-%d")
        buckets.setdefault(week_key, {})[category] = count
        totals[category] += count

    # Only the top `days/7 + 2` categories are charted (others -> "Other")
    # so the trend stays readable; totals stay complete.
    top = [c for c, _ in totals.most_common()]
    return {
        "weeks": sorted(buckets),
        "trend": buckets,
        "ranked": [{"category": c, "count": n} for c, n in totals.most_common()],
        "categories": top,
    }


@router.get("/ports")
async def top_ports(
    request: Request,
    days: int = Query(default=60, ge=1, le=365),
) -> dict[str, Any]:
    """Top exposed ports & services from Shodan InternetDB enrichment records."""
    rows = await _db(request).query(
        """
        SELECT raw_text
        FROM {db:Identifier}.raw_threat_intel FINAL
        WHERE source = 'SHODAN-INTERNETDB'
          AND ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        """,
        parameters={"db": _database(request), "d": days},
    )
    ports: Counter[int] = Counter()
    for (raw_text,) in rows.result_rows:
        m = _SHODAN_RE.match(raw_text or "")
        if not m:
            continue
        for p in _csv_int(m.group("ports")):
            ports[p] += 1
    return {
        "ports": [
            {
                "port": p,
                "count": n,
                "service": _PORT_SERVICES.get(p, "Unknown"),
            }
            for p, n in ports.most_common(10)
        ]
    }


@router.get("/cves")
async def top_cves(
    request: Request,
    days: int = Query(default=60, ge=1, le=365),
) -> dict[str, Any]:
    """Most frequently seen CVEs across all raw records in the window."""
    rows = await _db(request).query(
        """
        SELECT cve, count() AS n
        FROM (
            SELECT arrayJoin(arrayDistinct(
                extractAll(raw_text, 'CVE-[0-9]{4}-[0-9]{4,7}')
            )) AS cve
            FROM {db:Identifier}.raw_threat_intel FINAL
            WHERE ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        )
        WHERE cve != ''
        GROUP BY cve
        ORDER BY n DESC
        LIMIT 10
        """,
        parameters={"db": _database(request), "d": days},
    )
    return {"cves": [{"cve": r[0], "count": r[1]} for r in rows.result_rows]}


@router.get("/heatmap")
async def tactic_heatmap(
    request: Request,
    days: int = Query(default=60, ge=1, le=365),
) -> dict[str, Any]:
    """ATT&CK tactic heatmap: category counts mapped to tactics per the
    analyst-owned table in app/tactics.py. Cells = records of a category that
    map onto a tactic; a category mapping to several tactics contributes to
    each. Unknown / "Other" land in the always-present "Unclassified" column —
    the heatmap never guesses an attribution."""
    from app.tactics import TACTIC_ORDER, map_category

    rows = await _db(request).query(
        """
        SELECT threat_category, count()
        FROM {db:Identifier}.raw_threat_intel FINAL
        WHERE ts >= toDate(now()) - INTERVAL {d:UInt32} DAY
        GROUP BY threat_category
        ORDER BY count() DESC
        """,
        parameters={"db": _database(request), "d": days},
    )

    matrix: dict[str, dict[str, int]] = {}
    tactic_totals: dict[str, int] = {t: 0 for t in TACTIC_ORDER}
    category_totals: dict[str, int] = {}
    total = 0
    for category, count in rows.result_rows:
        category_totals[category] = count
        total += count
        for tactic in map_category(category):
            cell = matrix.setdefault(category, {}).setdefault(tactic, 0)
            matrix[category][tactic] = cell + count
            tactic_totals[tactic] = tactic_totals.get(tactic, 0) + count

    return {
        "tactics": TACTIC_ORDER,
        "categories": list(category_totals),
        "matrix": matrix,
        "tactic_totals": tactic_totals,
        "category_totals": category_totals,
        "total": total,
    }


def _csv_int(s: str) -> list[int]:
    out = []
    for part in s.split(","):
        part = part.strip().strip("'\"")
        if part.isdigit():
            out.append(int(part))
    return out
