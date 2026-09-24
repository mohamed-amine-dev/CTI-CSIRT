# =============================================================================
# CTI Platform - /api/v1/pcap routes (Network Analysis module)
# -----------------------------------------------------------------------------
# A capture is uploaded, quarantined and replayed through Zeek (see
# app/pcap_analytics.py). These routes serve:
#
#   GET  /api/v1/pcap/status                    zeek/broker availability
#   POST /api/v1/pcap/analyze                   upload + analyse (token)
#   GET  /api/v1/pcap/list                      recent captures (cards)
#   GET  /api/v1/pcap/{id}                      detail + stage-1 charts
#   GET  /api/v1/pcap/{id}/graph                stage-2 connection graph + IOCs
#   GET  /api/v1/pcap/{id}/summary              stage-5 grounded AI summary
#   POST /api/v1/pcap/{id}/rules                stage-5 rule DRAFT generation
#
# Stage 1 (charts) and stage 2 (graph) are pure, additive reads over the four
# zeek_* tables; stage 3/5 cross-reference the platform's own indicator corpus
# (processed_iocs / ioc_actor_attribution) that the ingestion pipeline already
# populated — nothing is invented for a capture.
# =============================================================================

from __future__ import annotations

import ipaddress
import time
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.ai_processor import get_llm
from app.ioc_rulegen import generate as generate_rules
from app.pcap_analytics import (
    analyze_pcap,
    ioc_cross_reference,
    pcap_dir,
)

router = APIRouter(prefix="/api/v1/pcap", tags=["pcap"])

_bearer = HTTPBearer(auto_error=False)


def _require_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Reject state-changing calls that do not carry the configured token."""
    expected = request.app.state.settings.api_access_token
    if creds is None or creds.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing access token")


def _db(request: Request) -> Any:
    return request.app.state.db


def _database(request: Request) -> str:
    return request.app.state.settings.clickhouse_database


def _settings(request: Request) -> Any:
    return request.app.state.settings


def _capture_id(request: Request, capture_id: str) -> None:
    """Validate the UUID path segment before it reaches any SQL."""
    if not capture_id or len(capture_id) != 36 or "-" not in capture_id:
        raise HTTPException(status_code=422, detail="invalid capture id")
    settings = _settings(request)
    if not (pcap_dir(settings) / f"{capture_id}.pcap").is_file():
        raise HTTPException(status_code=404, detail="capture not found")


def _iso(value: Any) -> str | None:
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value) if value is not None else None


# --------------------------------------------------------------------------- #
# Status                                                                      #
# --------------------------------------------------------------------------- #

@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    """Zeek runtime + plumbing present? Rendered as the page footer/banner."""
    settings = _settings(request)
    import pathlib
    return {
        "zeek": {
            "present": pathlib.Path(settings.zeek_binary).is_file(),
            "binary": settings.zeek_binary,
        },
        "max_upload_bytes": settings.pcap_max_bytes,
        "extraction_enabled": settings.pcap_extract_enabled,
        "quarantine_dir": str(pcap_dir(settings)),
        "yara_present": pathlib.Path(settings.yara_bundle_path).is_file()
        and pathlib.Path(settings.yara_binary).is_file(),
    }


# --------------------------------------------------------------------------- #
# Upload + analyse                                                            #
# --------------------------------------------------------------------------- #

class AnalyzeResponse(BaseModel):
    pcap_id: str
    filename: str
    size_bytes: int
    sha256: str
    format: str
    status: str
    error: str
    counts: dict[str, int]


@router.post("/analyze")
async def analyze(request: Request, file: UploadFile = File(...),
                  _: None = Depends(_require_token)) -> dict[str, Any]:
    """Upload a capture and run the full Zeek pipeline synchronously."""
    settings = _settings(request)
    data = await file.read(settings.pcap_max_bytes + 1)
    if len(data) > settings.pcap_max_bytes:
        raise HTTPException(status_code=413,
                            detail=f"File exceeds the {settings.pcap_max_bytes} byte limit")
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    db = _db(request)
    result = await analyze_pcap(db, _database(request), settings, data,
                                file.filename or "capture.pcap")
    if result.get("error"):
        raise HTTPException(status_code=422, detail=result["error"])
    return result


# --------------------------------------------------------------------------- #
# Capture list + detail (stage 1 data)                                        #
# --------------------------------------------------------------------------- #

@router.get("/list")
async def list_captures(request: Request) -> dict[str, Any]:
    """Recent captures for the cards list (metadata + counts only)."""
    db_name = _database(request)
    rows = await _db(request).query(
        f"""
        SELECT id, filename, size_bytes, sha256, status, error,
               conn_rows, http_rows, dns_rows, file_rows, extracted,
               malicious_files, ts
        FROM {db_name}.pcap_captures FINAL
        ORDER BY ts DESC
        LIMIT 50
        """,
    )
    captures = []
    for r in rows.result_rows or []:
        captures.append({
            "id": str(r[0]),
            "filename": str(r[1]),
            "size_bytes": int(r[2]),
            "sha256": str(r[3]),
            "status": str(r[4]),
            "error": str(r[5]),
            "counts": {
                "conn": int(r[6]), "http": int(r[7]), "dns": int(r[8]),
                "files": int(r[9]), "extracted": int(r[10]),
                "malicious_files": int(r[11]),
            },
            "ts": _iso(r[12]),
        })
    return {"captures": captures, "total": len(captures)}


async def _chart_payload(db: Any, db_name: str, pcap_id: str) -> dict[str, Any]:
    """Stage-1 aggregations over the parsed zeek tables."""
    pid = {"pid": pcap_id}

    proto = await db.query(
        f"""
        SELECT proto, count() AS n, sum(orig_bytes + resp_bytes) AS bytes
        FROM {db_name}.zeek_conn FINAL
        WHERE pcap_id = {{pid:UUID}}
        GROUP BY proto ORDER BY bytes DESC
        """, parameters=pid)
    protocol = [{"proto": str(r[0]), "n": int(r[1]), "bytes": int(r[2])}
                for r in proto.result_rows or []]

    span = await db.query(
        f"SELECT min(ts_ms), max(ts_ms) FROM {db_name}.zeek_conn FINAL "
        f"WHERE pcap_id = {{pid:UUID}}", parameters=pid)
    min_ms, max_ms = ((span.result_rows or [(0, 0)])[0])
    min_ms, max_ms = int(min_ms or 0), int(max_ms or 0)
    bucket_s = 1
    if max_ms > min_ms:
        bucket_s = max(1, min(300, int((max_ms - min_ms) / 60 / 1000)))
    ts_rows = await db.query(
        f"""
        SELECT toStartOfInterval(ts, toIntervalSecond({{b:UInt32}})) AS bk,
               sum(orig_bytes + resp_bytes) AS bytes, count() AS n
        FROM {db_name}.zeek_conn FINAL
        WHERE pcap_id = {{pid:UUID}}
        GROUP BY bk ORDER BY bk
        """, parameters={**pid, "b": bucket_s})
    timeline = []
    for r in ts_rows.result_rows or []:
        timeline.append({
            "bucket": _iso(r[0]),
            "bucket_ms": int(r[0].timestamp() * 1000) if hasattr(r[0], "timestamp") else 0,
            "bytes": int(r[1]), "conns": int(r[2]),
        })

    tt = await db.query(
        f"""
        SELECT orig_h, resp_h, sum(orig_bytes + resp_bytes) AS bytes, count() AS n,
               argMin(orig_p, ts) AS op, argMin(resp_p, ts) AS rp
        FROM {db_name}.zeek_conn FINAL
        WHERE pcap_id = {{pid:UUID}}
        GROUP BY orig_h, resp_h ORDER BY bytes DESC LIMIT 12
        """, parameters=pid)
    top_talkers = [{
        "src": str(r[0]), "dst": str(r[1]), "bytes": int(r[2]), "n": int(r[3]),
        "src_port": int(r[4]), "dst_port": int(r[5]),
    } for r in tt.result_rows or []]

    svc = await db.query(
        f"""
        SELECT service, count() AS n
        FROM {db_name}.zeek_conn FINAL
        WHERE pcap_id = {{pid:UUID}} AND service != ''
        GROUP BY service ORDER BY n DESC LIMIT 10
        """, parameters=pid)
    services = [{"service": str(r[0]), "n": int(r[1])} for r in svc.result_rows or []]

    hs = await db.query(
        f"""
        SELECT ts, method, host, uri, user_agent, status_code, resp_len, uid
        FROM {db_name}.zeek_http FINAL
        WHERE pcap_id = {{pid:UUID}}
        ORDER BY ts DESC LIMIT 300
        """, parameters=pid)
    http_sample = [{
        "ts": _iso(r[0]), "method": str(r[1]), "host": str(r[2]),
        "uri": str(r[3]), "user_agent": str(r[4]), "status": int(r[5]),
        "resp_len": int(r[6]), "uid": str(r[7]),
    } for r in hs.result_rows or []]

    ds = await db.query(
        f"""
        SELECT ts, query, qtype_name, rcode_name, answers
        FROM {db_name}.zeek_dns FINAL
        WHERE pcap_id = {{pid:UUID}}
        ORDER BY ts DESC LIMIT 300
        """, parameters=pid)
    dns_sample = [{
        "ts": _iso(r[0]), "query": str(r[1]), "qtype": str(r[2]),
        "rcode": str(r[3]), "answers": list(r[4] or []) if r[4] else [],
    } for r in ds.result_rows or []]

    return {
        "protocol": protocol,
        "timeline": timeline,
        "top_talkers": top_talkers,
        "services": services,
        "http_sample": http_sample,
        "dns_sample": dns_sample,
        "span_sec": (max_ms - min_ms) / 1000 if max_ms > min_ms else 0,
        "bucket_sec": bucket_s,
    }


@router.get("/{capture_id}")
async def capture_detail(request: Request, capture_id: str) -> dict[str, Any]:
    """Full stage-1 payload for one capture (charts + structured samples)."""
    _capture_id(request, capture_id)
    db = _db(request)
    db_name = _database(request)
    meta = await db.query(
        f"""
        SELECT id, filename, size_bytes, sha256, status, error,
               conn_rows, http_rows, dns_rows, file_rows, extracted,
               malicious_files, tlp, ts
        FROM {db_name}.pcap_captures FINAL
        WHERE id = {{pid:UUID}}
        LIMIT 1
        """, parameters={"pid": capture_id})
    if not (meta.result_rows or []):
        raise HTTPException(status_code=404, detail="capture not found")
    r = meta.result_rows[0]

    fr = await db.query(
        f"""
        SELECT ts, uid, source, mime_type, sha256, size_bytes, verdict,
               verdict_reason, yara_rules
        FROM {db_name}.zeek_files FINAL
        WHERE pcap_id = {{pid:UUID}}
        ORDER BY ts ASC LIMIT 200
        """, parameters={"pid": capture_id})
    files = [{
        "ts": _iso(row[0]), "uid": str(row[1]), "source": str(row[2]),
        "mime_type": str(row[3]), "sha256": str(row[4]), "size_bytes": int(row[5]),
        "verdict": str(row[6]), "verdict_reason": str(row[7]),
        "yara_rules": str(row[8]),
    } for row in fr.result_rows or []]

    return {
        "capture": {
            "id": str(r[0]), "filename": str(r[1]), "size_bytes": int(r[2]),
            "sha256": str(r[3]), "status": str(r[4]), "error": str(r[5]),
            "counts": {
                "conn": int(r[6]), "http": int(r[7]), "dns": int(r[8]),
                "files": int(r[9]), "extracted": int(r[10]),
                "malicious_files": int(r[11]),
            },
            "tlp": str(r[12]), "ts": _iso(r[13]),
        },
        "charts": await _chart_payload(db, db_name, capture_id),
        "files": files,
    }


# --------------------------------------------------------------------------- #
# Connection graph (stage 2 + 3 IOC cross-reference)                          #
# --------------------------------------------------------------------------- #

@router.get("/{capture_id}/graph")
async def capture_graph(request: Request, capture_id: str) -> dict[str, Any]:
    """Nodes/edges for the d3-force graph + IOC flags + geolocation.

    Edges are aggregated per (orig, resp, proto, service) pair, capped at the
    busiest 400 for rendering. Every IP / domain is cross-referenced against
    `processed_iocs` (real corpus, ingested feeds) and geolocation comes from
    the platform's own `ip_geo_cache` (never invented).
    """
    _capture_id(request, capture_id)
    db = _db(request)
    db_name = _database(request)
    pid = {"pid": capture_id}

    edges_raw = await db.query(
        f"""
        SELECT orig_h, resp_h, proto, service,
               sum(orig_bytes + resp_bytes) AS bytes, count() AS n,
               min(ts_ms) AS t0ms, max(ts_ms) AS t1ms,
               argMin(orig_p, ts) AS op, argMin(resp_p, ts) AS rp
        FROM {db_name}.zeek_conn FINAL
        WHERE pcap_id = {{pid:UUID}}
        GROUP BY orig_h, resp_h, proto, service
        ORDER BY bytes DESC
        LIMIT 400
        """, parameters=pid)

    edges = []
    ip_set: set[str] = set()
    for r in edges_raw.result_rows or []:
        src, dst = str(r[0]), str(r[1])
        ip_set.update((src, dst))
        edges.append({
            "source": src, "target": dst,
            "proto": str(r[2]), "service": str(r[3]),
            "bytes": int(r[4]), "n": int(r[5]),
            "ts0": int(r[6] or 0), "ts1": int(r[7] or 0),
            "ports": {"src": int(r[8]), "dst": int(r[9])},
        })

    # Hostname resolution: DNS answers -> IP, and HTTP Host header -> responder.
    hosts: dict[str, set[str]] = {}
    hr = await db.query(
        f"SELECT query, answers FROM {db_name}.zeek_dns FINAL "
        f"WHERE pcap_id = {{pid:UUID}} AND answers != []",
        parameters=pid)
    for row in hr.result_rows or []:
        query = str(row[0])
        for answer in (row[1] or []):
            a = str(answer)
            if ":" in a or a.isdigit():
                hosts.setdefault(a, set()).add(query)
    hr2 = await db.query(
        f"""
        SELECT c.resp_h, h.host, count() AS n
        FROM {db_name}.zeek_http AS h FINAL
        ANY INNER JOIN {db_name}.zeek_conn AS c FINAL USING (uid)
        WHERE h.pcap_id = {{pid:UUID}} AND h.host != ''
        GROUP BY c.resp_h, h.host
        """, parameters=pid)
    for row in hr2.result_rows or []:
        hosts.setdefault(str(row[0]), set()).add(str(row[1]))

    # Geolocation from the platform's own cache (status='ok' only).
    geo: dict[str, dict[str, str]] = {}
    if ip_set:
        gr = await db.query(
            f"SELECT ip, country_code, country_name FROM {db_name}.ip_geo_cache FINAL "
            f"WHERE ip IN {{ips:Array(String)}} AND status = 'ok'",
            parameters={"ips": sorted(ip_set)})
        geo = {str(r[0]): {"country_code": str(r[1]), "country_name": str(r[2])}
               for r in gr.result_rows or []}

    domain_set = set(d for dlist in hosts.values() for d in dlist)
    ioc = await ioc_cross_reference(db, db_name, capture_id, ip_set, domain_set)

    ip_flag = {f["indicator"] for f in ioc["flagged"]
               if f["type"] in ("ipv4", "ipv6")}
    dom_flag = {f["indicator"] for f in ioc["flagged"]
                if f["type"] in ("domain", "url")}

    def _is_internal(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    nodes = []
    for ip in sorted(ip_set):
        names = sorted(hosts.get(ip, set()))[:20]
        flagged = ip in ip_flag or any(name in dom_flag for name in names)
        nodes.append({
            "id": ip,
            "hostnames": names,
            "internal": _is_internal(ip),
            "geo": geo.get(ip),
            "flagged": flagged,
        })
    flagged_ips = sorted(ip_flag)
    flagged_domains = sorted({f["indicator"] for f in ioc["flagged"]
                              if f["type"] in ("domain", "url")})
    return {
        "nodes": nodes,
        "edges": edges,
        "capped": len(edges_raw.result_rows or []) >= 400,
        "ioc": {
            "count": ioc["count"],
            "flagged": ioc["flagged"],
            "flagged_ips": flagged_ips,
            "flagged_domains": flagged_domains,
        },
    }


# --------------------------------------------------------------------------- #
# Stage 5: grounded AI summary + detection-rule DRAFTs                        #
# --------------------------------------------------------------------------- #

@router.get("/{capture_id}/summary")
async def capture_summary(request: Request, capture_id: str) -> dict[str, Any]:
    """A short analyst summary written ONLY from facts the pipeline gathered.

    The LLM (local Ollama first, free Gemini/Groq fallback) receives a JSON
    fact sheet and is instructed to stay strictly within it; the fact sheet is
    returned alongside so the analyst can audit every claim.
    """
    _capture_id(request, capture_id)
    db = _db(request)
    db_name = _database(request)
    detail = await capture_detail(request, capture_id)

    capture = detail["capture"]
    charts = detail["charts"]
    facts = {
        "filename": capture["filename"],
        "size_bytes": capture["size_bytes"],
        "capture_span_sec": charts["span_sec"],
        "counts": capture["counts"],
        "protocols": charts["protocol"],
        "top_talkers": charts["top_talkers"][:5],
        "services": charts["services"],
        "top_http_hosts": sorted(
            h["host"] for h in charts["http_sample"][:200] if h.get("host")
        )[:8],
        "http_requests": len(charts["http_sample"]),
        "dns_queries": len(charts["dns_sample"]),
    }
    graph = await capture_graph(request, capture_id)
    facts["ioc_cross_reference"] = {
        "flagged_count": graph["ioc"]["count"],
        "flagged_ips": graph["ioc"]["flagged_ips"][:10],
        "flagged_domains": graph["ioc"]["flagged_domains"][:10],
    }

    system = (
        "You are a senior CSIRT network analyst. Write ONE concise report "
        "(max 180 words, plain English, no markdown tables) for a packet "
        "capture. Base every claim ONLY on the JSON facts provided. If an "
        "expected element is absent in the facts (for example no flagged "
        "indicators), state so explicitly. Never invent IPs, domains, files or "
        "families."
    )
    import json as _json
    user = (_json.dumps(facts, indent=2, ensure_ascii=False)
            + "\n\nWrite the report now.")
    try:
        llm = get_llm(_settings(request))
        ai_message = await llm.ainvoke([
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ])
        text = (getattr(ai_message, "content", "") or "").strip()
        if not text:
            raise RuntimeError("empty model output")
    except Exception as exc:  # noqa: BLE001 - provider down is surfaced, not fatal
        return {
            "status": "error",
            "summary": None,
            "reason": f"LLM unavailable: {exc}",
            "facts": facts,
        }
    return {"status": "ok", "summary": text, "facts": facts}


class PcapRulesRequest(BaseModel):
    iocs: list[dict[str, str]] = []   # {type, value} network indicators


@router.post("/{capture_id}/rules")
async def capture_rules(request: Request, capture_id: str, body: PcapRulesRequest,
                        _: None = Depends(_require_token)) -> dict[str, Any]:
    """Generate detection-rule DRAFTs for the IOC set surfaced from the capture.

    Reuses the sample-scanner rule generator (`ioc_rulegen.generate`) so the
    drafts share the same DISCLAIMER/draft conventions and syntax-compatible
    Suricata/Snort subset; they are drafts, never deployed automatically.
    """
    _capture_id(request, capture_id)
    iocs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for i in body.iocs:
        t = str(i.get("type", "")).lower().strip()
        v = str(i.get("value", "")).strip()
        if not t or not v or (t, v) in seen:
            continue
        iocs.append({"type": t, "value": v})
        seen.add((t, v))
    if not iocs:
        raise HTTPException(status_code=422, detail="at least one {type,value} IOC required")

    drafts = generate_rules(None, None, iocs)
    drafts["generated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    drafts["capture_id"] = capture_id
    return drafts