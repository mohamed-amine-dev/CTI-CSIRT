# =============================================================================
# CTI Platform - PCAP analysis (Network Analysis module)
# -----------------------------------------------------------------------------
# Static dissection of a network capture. The uploaded bytes are never
# executed: they are (1) parked in an isolated quarantine dir (0700), (2)
# fingerprinted with SHA-256, then (3) replayed through Zeek (`zeek -C -r`),
# which turns raw packets into typed TSV logs (conn/http/dns/files) that are
# parsed and batch-inserted into ClickHouse. Zeek also recovers application
# payloads; every recovered file is YARA-scanned with the SAME pinned
# signature-base bundle the sample scanner uses (stage 4).
# =============================================================================

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import pathlib
import re
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any

from .db import insert_rows
from .ip_utils import is_non_public_ip
from .sample_scanner import compute_hashes, run_yara

logger = logging.getLogger(__name__)

# Magic numbers of the only capture formats we accept (.pcap classic - µs and
# ns variants, little/big endian — and pcapng).
_PCAP_MAGICS: list[tuple[bytes, str]] = [
    (b"\xd4\xc3\xb2\xa1", "pcap"),    # classic, little-endian (µs)
    (b"\xa1\xb2\xc3\xd4", "pcap"),    # classic, big-endian
    (b"\x4d\x3c\xb2\xa1", "pcap"),    # nanosecond timestamps, LE
    (b"\xa1\xb2\x3c\x4d", "pcap"),    # nanosecond timestamps, BE
    (b"\x0a\x0d\x0d\x0a", "pcapng"),  # pcap next-generation
]

_CAPTURE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Zeek renders absent values as `-` and set/empty markers as `(empty)`.
_UNSET = {"-", "(empty)", ""}


def detect_pcap_format(magic: bytes) -> str | None:
    """Return 'pcap' | 'pcapng' for a recognised magic, else None."""
    if len(magic) < 4:
        return None
    for m, name in _PCAP_MAGICS:
        if magic.startswith(m):
            return name
    return None


def pcap_dir(settings: Any) -> pathlib.Path:
    """Ensure the isolated capture quarantine dir exists (0700)."""
    qdir = pathlib.Path(settings.pcap_quarantine_dir).resolve()
    qdir.mkdir(parents=True, exist_ok=True)
    try:
        qdir.chmod(0o700)
    except OSError:  # pragma: no cover - non-POSIX host
        pass
    return qdir


def park_pcap(data: bytes, settings: Any) -> tuple[str, pathlib.Path]:
    """Write capture bytes under a random handle (0600, never world-readable)."""
    qid = str(uuid.uuid4())
    path = pcap_dir(settings) / f"{qid}.pcap"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    logger.info("pcap quarantined id=%s bytes=%d", qid, len(data))
    return qid, path


def quarantined_path(settings: Any, capture_id: str) -> pathlib.Path:
    """Resolve a capture UUID -> parked file, rejecting user-controlled input."""
    if not _CAPTURE_ID_RE.match(capture_id):
        raise ValueError("invalid capture id")
    path = pcap_dir(settings) / f"{capture_id}.pcap"
    if not path.is_file():
        raise FileNotFoundError(capture_id)
    return path


# --------------------------------------------------------------------------- #
# Zeek TSV parsing                                                            #
# --------------------------------------------------------------------------- #

def parse_zeek_log(path: pathlib.Path) -> list[dict[str, str]]:
    """Turn a zeek *.log into a list of row dicts (unset/empty markers -> '').

    Zeek logs are TSV with `#fields` / `#types` separator lines before the
    data rows; any row whose leading `#` line declares fields counts.
    """
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line[len("#fields\t"):].split("\t")
                continue
            if not fields or not line:
                continue
            parts = line.split("\t")
            row: dict[str, str] = {}
            for i, f in enumerate(fields):
                v = parts[i] if i < len(parts) else ""
                row[f] = "" if v in _UNSET else v
            rows.append(row)
    return rows


def _ts_bits(value: str) -> tuple[datetime, int]:
    """Zeek epoch-seconds string -> (naive-UTC datetime, epoch_ms)."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc).replace(tzinfo=None), 0
    dt = datetime.fromtimestamp(f, tz=timezone.utc).replace(tzinfo=None)
    return dt, int(round(f * 1000))


def _utcnow_naive() -> datetime:
    """Naive UTC datetime the way the rest of the codebase inserts ts columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _int(value: str, default: int = 0) -> int:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return default


def _float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Zeek run                                                                    #
# --------------------------------------------------------------------------- #

async def _zeek_capture(settings: Any, pcap_path: pathlib.Path,
                        workdir: pathlib.Path) -> dict[str, Any]:
    """Replay the capture through Zeek into `workdir`.

    Returns a dict mirroring the known log verdict: `rc`, `stderr` and, when
    extraction is enabled, the files recovered under `extract/`. Extraction
    uses Zeek's own documented knob (`Files::extract_files`); if that form
    fails on a given capture, the parse is re-run WITHOUT extraction (the file
    logs are still analysed — extraction is best-effort, parsing is not).
    """
    def args(with_extraction: bool) -> list[str]:
        # Zeek 8 dropped the legacy `Files::extract_files` knobs (they exist in
        # older versions only). File recovery is now the extract-all-files
        # policy (`@load base/files/extract` + per-file analyzer), which writes
        # recovered bytes under `./extract_files/` in the working directory.
        base = [settings.zeek_binary, "-C", "-r", str(pcap_path)]
        if with_extraction:
            base.append("policy/frameworks/files/extract-all-files")
        return base

    result: dict[str, Any] = {"rc": 1, "stderr": "", "extract_dir": None}
    attempts = [True, False] if settings.pcap_extract_enabled else [False]
    for with_extraction in attempts:
        proc = await asyncio.create_subprocess_exec(
            *args(with_extraction),
            cwd=str(workdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _out, err = await asyncio.wait_for(
                proc.communicate(), timeout=settings.zeek_timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            result["stderr"] = "zeek timed out"
            break
        result["rc"] = proc.returncode
        result["stderr"] = err.decode("utf-8", errors="replace").strip()
        if proc.returncode == 0:
            if with_extraction:
                result["extract_dir"] = workdir / "extract_files"
            break
        logger.warning("zeek rc=%d (extraction=%s) err=%s",
                       proc.returncode, with_extraction, result["stderr"][:400])
    return result


# --------------------------------------------------------------------------- #
# Stage 4: recovered-file extraction + YARA scan                              #
# --------------------------------------------------------------------------- #

async def _scan_extracted_files(
    settings: Any,
    workdir: pathlib.Path,
    extract_dir: pathlib.Path,
    files_rows: list[dict[str, str]],
    pcap_id: str,
    version: int,
) -> tuple[list[list[Any]], int, int]:
    """YARA-scan every file Zeek recovered; row list for `zeek_files`.

    Rows are built from the files actually recovered on disk (Zeek 8 does not
    guarantee a `sha256` in files.log, so the log is only used to enrich
    mime/source/uid/ts on a byte-identical match). Matching a recovered file
    to its files.log entry is by SHA-256 of the bytes on disk. Returns
    (rows, extracted_count, malicious_count).
    """
    rows: list[list[Any]] = []
    if not extract_dir or not extract_dir.is_dir():
        return rows, 0, 0
    bundle = pathlib.Path(settings.yara_bundle_path)
    scan_ok = bundle.is_file() and pathlib.Path(settings.yara_binary).is_file()

    # files.log entries keyed by the SHA-256 Zeek published (when it hashed)
    # and by fuid (always present; recovered filenames embed it).
    log_by_sha: dict[str, dict[str, str]] = {}
    log_by_fuid: dict[str, dict[str, str]] = {}
    for fr in files_rows:
        sha = fr.get("sha256", "")
        if sha.isalnum() and len(sha) >= 40:
            log_by_sha.setdefault(sha, fr)
        if fr.get("fuid"):
            log_by_fuid.setdefault(fr["fuid"], fr)

    extracted = 0
    malicious = 0
    total = 0
    for f in sorted(extract_dir.rglob("*")):
        if not f.is_file():
            continue
        size = f.stat().st_size
        if size > settings.pcap_extract_max_file_bytes:
            continue
        total += size
        if total > settings.pcap_extract_max_total_bytes:
            break

        sha = hashlib.sha256(f.read_bytes()).hexdigest()
        fr = log_by_sha.get(sha, {})
        ts, ts_ms = _ts_bits(fr.get("ts", ""))
        uid = str(fr.get("uid", ""))
        source = str(fr.get("source", ""))
        mime = str(fr.get("mime_type", ""))
        if not fr:
            # Metadata came from the parseable extraction filename
            # extract-<ts>-<source>-<fuid> (set by base/files/extract).
            name = f.name
            if name.startswith("extract-"):
                parts = name[len("extract-"):].rsplit("-", 2)
                if len(parts) == 3:
                    fts = _float(parts[0])
                    if fts:
                        ts, ts_ms = _ts_bits(str(fts))
                    source = parts[1]
                    uid = parts[2]
                    fr = log_by_fuid.get(uid) or {}
                    ts2, _ = _ts_bits(fr.get("ts", ""))
                    if ts2:
                        ts = ts2
                    uid = str(fr.get("fuid", uid))
                    source = str(fr.get("source", source))
                    mime = str(fr.get("mime_type", mime))

        rules: list[str] = []
        reason = "scan disabled"
        if scan_ok:
            rules, yerr = await run_yara(bundle, f, settings.yara_binary)
            if yerr:
                reason = f"scan failed: {yerr[:120]}"
            elif rules:
                reason = f"matched {len(rules)} public YARA rule(s)"
            else:
                reason = "no public YARA rule matched"
        verdict = "malicious" if (scan_ok and rules) else "clean"
        if verdict == "malicious":
            malicious += 1
        extracted += 1
        rows.append([
            pcap_id, ts, uid, source, mime, sha, size, verdict, reason,
            ",".join(sorted(set(rules)))[:2000], version,
        ])
        logger.info("zeek extract scanned sha=%s source=%s verdict=%s rules=%d",
                    sha[:12], source or "<no-files.log>", verdict, len(rules))

    # The table's ORDER BY (pcap_id, sha256) intentionally stores ONE row per
    # unique recovered artifact (a payload downloaded repeatedly collapses to
    # a single chain-of-custody entry). Dedupe here so the reported extracted
    # count equals the rows actually stored. The last occurrence is kept.
    by_sha: dict[str, list[Any]] = {}
    for r in rows:
        by_sha[r[5]] = r
    rows = list(by_sha.values())
    extracted = len(rows)
    malicious = sum(1 for r in rows if r[7] == "malicious")
    return rows, extracted, malicious


# --------------------------------------------------------------------------- #
# Row builders (column order MUST match the DDL column_names)                 #
# --------------------------------------------------------------------------- #

_CONN_COLS = ["pcap_id", "ts", "ts_ms", "uid", "proto", "service", "orig_h",
              "orig_p", "resp_h", "resp_p", "orig_bytes", "resp_bytes",
              "duration_sec", "conn_state", "history", "missed_bytes",
              "orig_pkts", "resp_pkts", "version"]

_HTTP_COLS = ["pcap_id", "ts", "ts_ms", "uid", "method", "host", "uri",
              "user_agent", "status_code", "resp_len", "version"]

_DNS_COLS = ["pcap_id", "ts", "ts_ms", "uid", "query", "qtype_name",
             "rcode_name", "answers", "version"]

_FILES_COLS = ["pcap_id", "ts", "uid", "source", "mime_type", "sha256",
               "size_bytes", "verdict", "verdict_reason", "yara_rules", "version"]

_CAPTURE_COLS = ["id", "filename", "size_bytes", "sha256", "status", "error",
                 "conn_rows", "http_rows", "dns_rows", "file_rows",
                 "extracted", "malicious_files", "tlp", "ts", "version"]


def _conn_row(pcap_id: str, r: dict[str, str], version: int) -> list[Any] | None:
    ts, ts_ms = _ts_bits(r.get("ts", ""))
    orig_h = str(r.get("id.orig_h", ""))
    resp_h = str(r.get("id.resp_h", ""))
    if not orig_h or not resp_h:
        return None
    return [pcap_id, ts, ts_ms, str(r.get("uid", "")),
            str(r.get("proto", "")), str(r.get("service", "")),
            orig_h, _int(r.get("id.orig_p", "")), resp_h, _int(r.get("id.resp_p", "")),
            _int(r.get("orig_bytes", "")), _int(r.get("resp_bytes", "")),
            _float(r.get("duration", "")), str(r.get("conn_state", "")),
            str(r.get("history", "")), _int(r.get("missed_bytes", "")),
            _int(r.get("orig_pkts", "")), _int(r.get("resp_pkts", "")), version]


def _http_row(pcap_id: str, r: dict[str, str], version: int) -> list[Any] | None:
    ts, ts_ms = _ts_bits(r.get("ts", ""))
    if not r.get("uid"):
        return None
    return [pcap_id, ts, ts_ms, str(r.get("uid", "")),
            str(r.get("method", "")), str(r.get("host", "")),
            str(r.get("uri", ""))[:4000], str(r.get("user_agent", ""))[:4000],
            _int(r.get("status_code", "")), _int(r.get("response_body_len", "")),
            version]


def _dns_row(pcap_id: str, r: dict[str, str], version: int) -> list[Any] | None:
    ts, ts_ms = _ts_bits(r.get("ts", ""))
    query = str(r.get("query", ""))
    if not query:
        return None
    answers = [a.strip() for a in str(r.get("answers", "")).split(",") if a.strip()]
    return [pcap_id, ts, ts_ms, str(r.get("uid", "")), query,
            str(r.get("qtype_name", "")), str(r.get("rcode_name", "")),
            answers, version]


# --------------------------------------------------------------------------- #
# Public entry point                                                          #
# --------------------------------------------------------------------------- #

async def analyze_pcap(
    db: Any,
    db_name: str,
    settings: Any,
    data: bytes,
    filename: str,
) -> dict[str, Any]:
    """Full pipeline: park → zeek → parse → batch-insert → capture record.

    Returns the capture metadata + per-log row counts (never the raw bytes).
    The lifecycle row is inserted with status 'done' on success or 'failed'
    with a retained error message on failure, so the UI always shows the true
    outcome.
    """
    magic = detect_pcap_format(data[:4])
    if magic is None:
        return {"error": "not a pcap/pcapng file (unrecognised magic)"}
    if len(data) > settings.pcap_max_bytes:
        return {"error": f"file exceeds the {settings.pcap_max_bytes} byte limit"}

    qid, path = park_pcap(data, settings)
    hashes = compute_hashes(data)
    version = int(datetime.now(timezone.utc).timestamp() * 1_000_000)

    conn_rows: list[list[Any]] = []
    http_rows: list[list[Any]] = []
    dns_rows: list[list[Any]] = []
    files_rows: list[list[Any]] = []
    extracted = 0
    malicious = 0
    error = ""

    try:
        with tempfile.TemporaryDirectory(prefix="zeekrun-") as td:
            workdir = pathlib.Path(td)
            run = await _zeek_capture(settings, path, workdir)
            conns = parse_zeek_log(workdir / "conn.log") if (workdir / "conn.log").is_file() else []
            if run["rc"] == 0:
                for r in conns:
                    row = _conn_row(qid, r, version)
                    if row:
                        conn_rows.append(row)
            for log, cols in (("http", _HTTP_COLS), ("dns", _DNS_COLS)):
                lp = workdir / f"{log}.log"
                if not lp.is_file():
                    continue
                for r in parse_zeek_log(lp):
                    row = (_http_row(qid, r, version) if log == "http"
                           else _dns_row(qid, r, version))
                    if row:
                        (http_rows if log == "http" else dns_rows).append(row)

            # Recovered files (stage 4): match by SHA-256, then YARA-scan.
            frows = (parse_zeek_log(workdir / "files.log")
                     if (workdir / "files.log").is_file() else [])
            files_rows, extracted, malicious = await _scan_extracted_files(
                settings, workdir,
                pathlib.Path(run["extract_dir"]) if run.get("extract_dir") else None,
                frows, qid, version - 1,
            )

        if not conn_rows and not http_rows and not dns_rows:
            if run["rc"] != 0:
                error = f"zeek parse failed (rc={run['rc']}): {run['stderr'][:300]}"
            else:
                error = "no connection/http/dns events parsed from this capture"
    except Exception as exc:  # noqa: BLE001 - any parse failure is captured & stored
        logger.exception("pcap analysis failed id=%s", qid)
        error = f"analysis failed: {exc}"

    status = "done" if not error else "failed"

    # Batch-insert everything; a write failure makes the capture record failed.
    try:
        if conn_rows:
            await insert_rows(db, "zeek_conn", conn_rows, _CONN_COLS)
        if http_rows:
            await insert_rows(db, "zeek_http", http_rows, _HTTP_COLS)
        if dns_rows:
            await insert_rows(db, "zeek_dns", dns_rows, _DNS_COLS)
        if files_rows:
            await insert_rows(db, "zeek_files", files_rows, _FILES_COLS)
        await insert_rows(db, "pcap_captures", [[
            qid, filename, len(data), hashes["sha256"], status, error,
            len(conn_rows), len(http_rows), len(dns_rows), len(files_rows),
            extracted, malicious, "AMBER",
            _utcnow_naive(), version,
        ]], _CAPTURE_COLS)
    except Exception as exc:  # noqa: BLE001
        logger.exception("pcap insert failed id=%s", qid)
        status = "failed"
        error = f"storage failed: {exc}"

    if status == "failed" and error:
        try:
            await insert_rows(db, "pcap_captures", [[
                qid, filename, len(data), hashes["sha256"], "failed", error,
                0, 0, 0, 0, 0, 0, "AMBER",
                _utcnow_naive(), version,
            ]], _CAPTURE_COLS)
        except Exception:  # noqa: BLE001
            logger.exception("pcap failure-record insert failed id=%s", qid)

    return {
        "pcap_id": qid,
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashes["sha256"],
        "format": magic,
        "status": status,
        "error": error,
        "counts": {
            "conn_rows": len(conn_rows),
            "http_rows": len(http_rows),
            "dns_rows": len(dns_rows),
            "file_rows": len(files_rows),
            "extracted": extracted,
            "malicious_files": malicious,
        },
    }


# --------------------------------------------------------------------------- #
# IOC cross-reference (stage 3): match capture hosts/hosts against the        #
# platform's own ingested indicator corpus + actor attribution.               #
# --------------------------------------------------------------------------- #

async def ioc_cross_reference(
    db: Any,
    db_name: str,
    pcap_id: str,
    ip_set: set[str],
    domain_set: set[str],
) -> dict[str, Any]:
    """Return flagged IP/domain hits with severity + actor attribution."""
    flagged: list[dict[str, Any]] = []
    # Platform-wide guard: private/reserved IPs (internal hosts, RFC1918,
    # CGNAT, ...) are never matched against the malicious corpus — the graph
    # labels them `internal`, flags only genuinely public addresses.
    ip_set = {ip for ip in ip_set if not is_non_public_ip(ip)}
    if not ip_set and not domain_set:
        return {"flagged": flagged}

    clauses: list[str] = []
    params: dict[str, Any] = {}
    if ip_set:
        clauses.append("(i.type IN ('ipv4','ipv6') AND i.indicator IN {ips:Array(String)})")
        params["ips"] = sorted(ip_set)
    if domain_set:
        clauses.append("(i.type IN ('domain','url') AND i.indicator IN {dns:Array(String)})")
        params["dns"] = sorted(domain_set)
    where = " OR ".join(clauses)

    rows = await db.query(
        f"""
        SELECT i.indicator, i.type, i.severity, i.malware_id, i.ts
        FROM {db_name}.processed_iocs AS i FINAL
        WHERE {where}
        LIMIT 500
        """,
        parameters=params,
    )
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows.result_rows or []:
        key = (str(r[0]), str(r[1]))
        by_key[key] = {
            "indicator": str(r[0]), "type": str(r[1]), "severity": float(r[2]),
            "malware_id": str(r[3] or ""),
            "ts": r[4].strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(r[4], "strftime") else str(r[4]),
        }

    if by_key:
        keys = [f"{ind}\x1f{typ}" for ind, typ in by_key]
        attr_rows = await db.query(
            f"""
            SELECT concat(a.indicator, '\x1f', a.type) AS pair, t.name
            FROM {db_name}.ioc_actor_attribution AS a FINAL
            INNER JOIN {db_name}.threat_actors AS t FINAL ON a.threat_actor_id = t.stix_id
            WHERE concat(a.indicator, '\x1f', a.type) IN {{keys:Array(String)}}
            """,
            parameters={"keys": keys},
        )
        actors: dict[tuple[str, str], list[str]] = {}
        for r in attr_rows.result_rows or []:
            pair = str(r[0]).split("\x1f")
            if len(pair) == 2:
                actors.setdefault((pair[0], pair[1]), []).append(str(r[1]))

        fam_ids = sorted({v["malware_id"] for v in by_key.values() if v["malware_id"]})
        fam_names: dict[str, str] = {}
        if fam_ids:
            fam_rows = await db.query(
                f"SELECT stix_id, name FROM {db_name}.malware_tools FINAL "
                f"WHERE stix_id IN {{fams:Array(String)}}",
                parameters={"fams": fam_ids},
            )
            fam_names = {str(r[0]): str(r[1]) for r in fam_rows.result_rows or []}

        for key, v in by_key.items():
            fam = fam_names.get(v["malware_id"], "")
            v["family"] = fam or None
            v["actors"] = actors.get(key, [])
            flagged.append(v)

    flagged.sort(key=lambda x: -x["severity"])
    return {"flagged": flagged, "count": len(flagged)}