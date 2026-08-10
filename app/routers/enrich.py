# =============================================================================
# CTI Platform - /api/v1/enrich routes (free multi-source enrichment)
# -----------------------------------------------------------------------------
# VirusTotal-style lookup for an indicator against free, no-key sources:
#   * IPv4   -> Shodan InternetDB (ports / CVEs / hostnames / tags) + DNS PTR
#   * Domain -> DNS-over-HTTPS (A/AAAA) + URLhaus host lookup
#   * URL    -> URLhaus URL lookup
#   * CVE    -> NVD API 2.0 (description, CVSS score/severity, references)
#
# A backend proxy is required because none of these APIs send CORS headers, so
# a browser cannot call them directly. Every source is independent: a failure
# (network error, rate limit, 404) sets that source to null and never fails the
# whole request. Zero-cost constraint: all sources are free and key-less.
# =============================================================================

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/enrich", tags=["enrich"])

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)
_CVE_RE = re.compile(r"^cve-\d{4}-\d{4,7}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}$")

# Which free sources run for each indicator type.
_SOURCE_PLAN: dict[str, list[str]] = {
    "ipv4": ["internetdb", "dns"],
    "domain": ["dns", "urlhaus"],
    "url": ["urlhaus"],
    "cve": ["nvd"],
}


def _indicator_type(indicator: str) -> str:
    if _IPV4_RE.match(indicator):
        return "ipv4"
    if _CVE_RE.match(indicator):
        return "cve"
    if _URL_RE.match(indicator):
        return "url"
    if _DOMAIN_RE.match(indicator):
        return "domain"
    if _HASH_RE.match(indicator):
        return "hash"
    return "unknown"


def _external_links(itype: str, indicator: str) -> dict[str, str]:
    """Public pages an analyst can open for a deeper look (no API key needed)."""
    links = {"virustotal": f"https://www.virustotal.com/gui/search/{indicator}"}
    if itype in ("ipv4", "domain"):
        links["shodan"] = f"https://www.shodan.io/host/{indicator}"
    if itype in ("domain", "url"):
        links["urlhaus"] = f"https://urlhaus.abuse.ch/{'url' if itype == 'url' else 'host'}/{indicator}"
    if itype == "cve":
        links["nvd"] = f"https://nvd.nist.gov/vuln/detail/{indicator.upper()}"
    return links


async def _source_internetdb(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    try:
        resp = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=15.0)
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "detail": f"InternetDB unreachable: {exc}"}
    if resp.status_code == 404:
        return {"found": False, "detail": "No InternetDB record for this IP"}
    if resp.status_code != 200:
        return {"found": False, "detail": f"InternetDB error: HTTP {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"found": False, "detail": "InternetDB returned malformed data"}
    return {
        "found": True,
        "ports": data.get("ports", []),
        "cves": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "cpes": data.get("cpes", []),
    }


async def _source_dns(client: httpx.AsyncClient, indicator: str, qtype: str) -> dict[str, Any]:
    """DNS lookup through Google's DNS-over-HTTPS (free, no key, CORS proxied)."""
    name = indicator
    if qtype == "PTR":
        name = ".".join(reversed(indicator.split("."))) + ".in-addr.arpa"
    try:
        resp = await client.get(
            "https://dns.google/resolve", params={"name": name, "type": qtype}, timeout=10.0
        )
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "detail": f"DNS-over-HTTPS unreachable: {exc}"}
    if resp.status_code != 200:
        return {"found": False, "detail": f"DNS error: HTTP {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"found": False, "detail": "DNS returned malformed data"}
    answers = [a.get("data") for a in (data.get("Answer") or []) if a.get("data")]
    if not answers:
        return {"found": False, "detail": "No record"}
    return {"found": True, "records": sorted(set(answers))}


async def _source_urlhaus(client: httpx.AsyncClient, indicator: str, itype: str) -> dict[str, Any]:
    """URLhaus lookup (abuse.ch): POST {"host"|"url": ...} — free, no key."""
    payload = {"url": indicator} if itype == "url" else {"host": indicator}
    try:
        resp = await client.post("https://urlhaus.abuse.ch/api/", json=payload, timeout=20.0)
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "detail": f"URLhaus unreachable: {exc}"}
    try:
        data = resp.json()
    except ValueError:
        return {"found": False, "detail": "URLhaus lookup unavailable (service returned no JSON)"}
    if data.get("query_status") != "ok":
        return {"found": False, "detail": data.get("query_status") or f"HTTP {resp.status_code}"}
    urls = data.get("urls") or []
    return {
        "found": True,
        "url_count": data.get("url_count", len(urls)),
        "urls": [
            {
                "url": u.get("url"),
                "threat": u.get("threat"),
                "tags": u.get("tags") or [],
            }
            for u in urls
        ],
    }


async def _source_nvd(client: httpx.AsyncClient, cve: str) -> dict[str, Any]:
    """NVD API 2.0 lookup by CVE id (free; ~5 req/30s without a key)."""
    try:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve.upper()},
            timeout=25.0,
        )
    except Exception as exc:  # noqa: BLE001
        return {"found": False, "detail": f"NVD unreachable: {exc}"}
    if resp.status_code == 404:
        return {"found": False, "detail": "CVE not found in NVD"}
    if resp.status_code == 403:
        return {"found": False, "detail": "NVD rate limit reached — wait a moment and retry"}
    if resp.status_code != 200:
        return {"found": False, "detail": f"NVD error: HTTP {resp.status_code}"}
    try:
        vulns = (resp.json() or {}).get("vulnerabilities") or []
    except ValueError:
        return {"found": False, "detail": "NVD returned malformed data"}
    if not vulns:
        return {"found": False, "detail": "CVE not found in NVD"}
    cve_data = vulns[0]["cve"]
    description = next(
        (d.get("value", "") for d in (cve_data.get("descriptions") or []) if d.get("lang") == "en"),
        "",
    )
    metrics = cve_data.get("metrics") or {}
    metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV2") or [{}])[0]
    cvss = metric.get("cvssData") or {}
    return {
        "found": True,
        "id": cve_data.get("id"),
        "published": cve_data.get("published"),
        "description": description,
        "cvss_score": cvss.get("baseScore"),
        "cvss_severity": cvss.get("baseSeverity"),
        "cvss_vector": cvss.get("vectorString"),
        "references": [r.get("url") for r in (cve_data.get("references") or []) if r.get("url")],
    }


@router.get("/{indicator}")
async def enrich_lookup(indicator: str) -> dict[str, Any]:
    """Return free, multi-source enrichment for any indicator type.

    Response shape (the frontend renders one panel per source):
      {indicator, type, found, sources: {internetdb?, dns?, urlhaus?, nvd?}, links}
    Each present source is either `{found: true, ...}` or `{found: false, detail}`;
    a source that could not be queried at all is `null`. `found` is true when at
    least one source has a record.
    """
    indicator = indicator.strip().lower()
    itype = _indicator_type(indicator)
    sources: dict[str, Any] = {"internetdb": None, "dns": None, "urlhaus": None, "nvd": None}
    links = _external_links(itype, indicator)

    if itype not in _SOURCE_PLAN:
        return {
            "indicator": indicator,
            "type": itype,
            "found": False,
            "sources": sources,
            "links": links,
            "detail": f"No free enrichment source for {itype} indicators",
        }

    async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
        if itype == "ipv4":
            internetdb, dns = await asyncio.gather(
                _source_internetdb(client, indicator),
                _source_dns(client, indicator, "PTR"),
            )
            sources["internetdb"] = internetdb
            sources["dns"] = dns
        elif itype == "domain":
            a, aaaa, urlhaus = await asyncio.gather(
                _source_dns(client, indicator, "A"),
                _source_dns(client, indicator, "AAAA"),
                _source_urlhaus(client, indicator, "domain"),
            )
            records = sorted(set((a.get("records") or []) + (aaaa.get("records") or [])))
            sources["dns"] = {"found": bool(records), "records": records}
            if not records:
                sources["dns"]["detail"] = "No DNS record"
            sources["urlhaus"] = urlhaus
        elif itype == "url":
            sources["urlhaus"] = await _source_urlhaus(client, indicator, "url")
        elif itype == "cve":
            sources["nvd"] = await _source_nvd(client, indicator)

    found = any(s and s.get("found") for s in sources.values())
    return {"indicator": indicator, "type": itype, "found": found, "sources": sources, "links": links}
