# =============================================================================
# CTI Platform - /api/v1/samples routes (Malware & Tools -> sample scanner)
# -----------------------------------------------------------------------------
#   GET  /api/v1/samples/status        -> scanner availability / bundle info
#   POST /api/v1/samples/scan          -> upload + quarantine + hash + YARA scan
#                                          (+ corpus hash-match, family cross-link)
#   POST /api/v1/samples/rules         -> generate Suricata/Snort/ModSecurity/
#                                          firewall/YARA DRAFTS for a confirmed
#                                          malicious sample (server re-verifies)
#   POST /api/v1/samples/validate      -> syntax-check a draft with the engine's
#                                          own parser (suricata -T / yarac)
#
# Safety: uploaded files are NEVER executed. They are parked in the isolated
# quarantine dir (0700), fingerprinted, and pattern-scanned with `yara -C` over
# a pinned, publicly maintained rule bundle (Neo23x0/signature-base). Size is
# capped server-side. Every generated rule is a reviewable draft.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from ..ioc_rulegen import generate as generate_rules, DISCLAIMER
from ..sample_scanner import (
    compute_hashes,
    corpus_hash_match,
    family_by_id,
    guess_malicious,
    known_families,
    park_sample,
    quarantine_dir,
    run_yara,
    yara_family_links,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/samples", tags=["samples"])

_bearer = HTTPBearer(auto_error=False)

_QUARANTINE_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


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


def _quarantined_path(settings: Any, quarantine_id: str) -> Path:
    """Resolve a quarantine_id -> parked file, rejecting anything user-controlled."""
    if not _QUARANTINE_RE.match(quarantine_id):
        raise HTTPException(status_code=400, detail="Invalid quarantine id")
    path = quarantine_dir(settings) / f"{quarantine_id}.bin"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Quarantined sample not found")
    return path


def _bundle_snapshot(settings: Any) -> dict[str, Any]:
    """Bundle presence/manifest info for /status (never leaks file contents)."""
    bundle = Path(settings.yara_bundle_path)
    if not bundle.is_file():
        return {"present": False}
    marker = Path(str(bundle) + ".txt")
    return {
        "present": True,
        "size_bytes": bundle.stat().st_size,
        "source": marker.read_text(encoding="utf-8", errors="replace").strip()
        if marker.is_file() else "unknown",
    }


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    settings = _settings(request)
    snapshot = _bundle_snapshot(settings)
    return {
        "yara": snapshot,
        "yara_binary": Path(settings.yara_binary).is_file(),
        "suricata_binary": Path(settings.suricata_binary).is_file(),
        "yarac_binary": Path(settings.yarac_binary).is_file(),
        "max_upload_bytes": settings.sample_max_bytes,
        "quarantine_dir": str(Path(settings.sample_quarantine_dir).resolve()),
        "quarantine_writeable": quarantine_dir(settings).is_dir(),  # noqa: 100
    }


class ScanResult(BaseModel):
    quarantine_id: str
    filename: str
    size: int
    hashes: dict[str, str]
    corpus_matches: list[dict[str, Any]]
    yara_rules: list[str]
    verdict: str
    verdict_reason: str
    family_links: list[dict[str, Any]]


@router.post("/scan")
async def scan(request: Request, file: UploadFile = File(...),
               _: None = Depends(_require_token)) -> ScanResult:
    """Upload + quarantine + fingerprint + scan (never executes the sample)."""
    settings = _settings(request)
    snapshot = _bundle_snapshot(settings)
    if not snapshot.get("present"):
        raise HTTPException(status_code=503,
                            detail="YARA rule bundle unavailable (image build issue)")

    # Read the upload stream with a hard server-side size cap.
    data = await file.read(settings.sample_max_bytes + 1)
    if len(data) > settings.sample_max_bytes:
        raise HTTPException(status_code=413,
                            detail=f"File exceeds the {settings.sample_max_bytes} byte limit")
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    qid, path = park_sample(data, settings)
    hashes = compute_hashes(data)

    db = _db(request)
    db_name = _database(request)
    corpus = await corpus_hash_match(db, db_name, hashes)

    rules, yerr = await run_yara(settings.yara_bundle_path, path, settings.yara_binary)
    if yerr:
        logger.warning("yara scan failed id=%s err=%s", qid, yerr)

    # Family cross-links: (1) a corpus row carrying malware_id, (2) YARA rule
    # names that overlap a malware_tools family (real name association).
    family_links: list[dict[str, Any]] = []
    if corpus:
        for row in corpus:
            fam = await family_by_id(db, db_name, row.get("malware_id", ""))
            if fam:
                family_links.append(fam)
    try:
        fams = await known_families(db, db_name)
    except Exception as exc:  # noqa: BLE001 - family index is best-effort
        logger.warning("family index failed: %s", exc)
        fams = {}
    family_links += yara_family_links(rules, fams)

    verdict, reason = guess_malicious(rules, corpus)
    return ScanResult(
        quarantine_id=qid,
        filename=file.filename or "upload.bin",
        size=len(data),
        hashes=hashes,
        corpus_matches=corpus,
        yara_rules=rules,
        verdict=verdict,
        verdict_reason=reason,
        family_links=family_links,
    )


class RulesRequest(BaseModel):
    quarantine_id: str
    iocs: list[dict[str, str]] = []   # extra network IOCs the analyst provides


@router.post("/rules")
async def rules(request: Request, body: RulesRequest,
                _: None = Depends(_require_token)) -> dict[str, Any]:
    """Generate detection-rule DRAFTS for a sample ALREADY confirmed malicious.

    The server re-verifies the verdict (hash corpus + YARA) before generating —
    the client cannot ask the platform to draft rules for an unverified file.
    """
    settings = _settings(request)
    snapshot = _bundle_snapshot(settings)
    if not snapshot.get("present"):
        raise HTTPException(status_code=503,
                            detail="YARA rule bundle unavailable (image build issue)")

    path = _quarantined_path(settings, body.quarantine_id)
    data = path.read_bytes()
    if len(data) > settings.sample_max_bytes:
        raise HTTPException(status_code=413, detail="Quarantined sample exceeds size limit")
    hashes = compute_hashes(data)

    db = _db(request)
    db_name = _database(request)
    corpus = await corpus_hash_match(db, db_name, hashes)
    rules_matched, yerr = await run_yara(settings.yara_bundle_path, path, settings.yara_binary)
    verdict, reason = guess_malicious(rules_matched, corpus)
    if verdict != "malicious":
        raise HTTPException(
            status_code=409,
            detail=f"Sample not confirmed malicious ({reason}); rule generation requires a verdict",
        )

    iocs: list[dict[str, str]] = []
    for key in ("sha256", "md5"):
        value = hashes.get(key)
        if value:
            iocs.append({"type": key, "value": value})
    seen = {(i.get("type"), i.get("value")) for i in iocs}
    for extra in body.iocs:
        t = str(extra.get("type", "")).lower().strip()
        v = str(extra.get("value", "")).strip()
        if not t or not v or (t, v) in seen:
            continue
        iocs.append({"type": t, "value": v})
        seen.add((t, v))

    drafts = generate_rules(
        {"sha256": hashes["sha256"], "md5": hashes["md5"]},
        data,
        iocs,
    )
    drafts["generated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    drafts["quarantine_id"] = body.quarantine_id
    drafts["verdict_reason"] = reason
    drafts["yara_rules_matched"] = rules_matched
    return drafts


class ValidateRequest(BaseModel):
    engine: str   # "suricata" | "snort" | "yara"
    content: str


@router.post("/validate")
async def validate(request: Request, body: ValidateRequest,
                   _: None = Depends(_require_token)) -> dict[str, Any]:
    """Syntax-check a draft with the engine's own parser where available."""
    settings = _settings(request)
    # Normalise line endings + guarantee a trailing \n: the companion-list regex
    # below requires a newline after the last hash, and generators emit exactly
    # one trailing newline. Stripping it would silently drop the final list.
    content = body.content.replace("\r\n", "\n").strip() + "\n"
    if not content.strip():
        raise HTTPException(status_code=400, detail="Empty rule content")

    with tempfile.TemporaryDirectory(prefix="argus-validate-") as tmp:
        if body.engine in ("suricata", "snort"):
            if not Path(settings.suricata_binary).is_file():
                return {"engine": body.engine, "available": False,
                        "valid": False,
                        "detail": "suricata binary not present in this image"}
            # Materialise any `# [file] companion hash list `name`:` blocks the
            # generator embeds, so the rule validates together with the list it
            # references (Suricata resolves those against default-rule-path).
            rule_dir = Path(tmp)
            src = rule_dir / "draft.rules"
            src.write_text(content, encoding="utf-8")
            seen_names: set[str] = set()
            for m in re.finditer(
                r"companion hash list `([\w.]+)`:\s*\n((?:#\s+[0-9a-fA-F]+\n)+)",
                content,
            ):
                name = m.group(1)
                if name in seen_names or "/" in name or "\\" in name or not name:
                    continue
                seen_names.add(name)
                hashes = re.findall(r"#\s+([0-9a-fA-F]+)", m.group(2))
                (rule_dir / name).write_text("\n".join(hashes) + "\n", encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                settings.suricata_binary, "-T",
                "-S", str(src),
                "-c", settings.suricata_config,
                "--set", f"default-rule-path={rule_dir}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            ok = proc.returncode == 0
            # Suricata 7 emits rule paths; strip non-authoritative parse noise.
            tail = (stdout + stderr).decode("utf-8", errors="replace").strip().splitlines()
            return {
                "engine": body.engine,
                "available": True,
                "valid": ok,
                "output": "\n".join(tail[-6:]) if tail else f"exit {proc.returncode}",
                "note": "validated with Suricata 7 parser (syntax-compatible "
                        "subset; Snort 2.9 itself is not installable on Debian 13)",
            }
        if body.engine == "yara":
            if not Path(settings.yarac_binary).is_file():
                return {"engine": "yara", "available": False, "valid": False,
                        "detail": "yarac binary not present in this image"}
            src = Path(tmp) / "draft.yar"
            out = Path(tmp) / "draft.yarc"
            src.write_text(content, encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                settings.yarac_binary, str(src), str(out),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            ok = proc.returncode == 0
            tail = (stdout + stderr).decode("utf-8", errors="replace").strip().splitlines()
            return {
                "engine": "yara",
                "available": True,
                "valid": ok,
                "output": "\n".join(tail[-6:]) if tail else f"exit {proc.returncode}",
            }
    raise HTTPException(status_code=400, detail="Unknown engine (suricata|snort|yara)")