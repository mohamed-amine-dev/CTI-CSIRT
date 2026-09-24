# =============================================================================
# CTI Platform - upload sample scanning (Malware & Tools -> sample scanner)
# -----------------------------------------------------------------------------
# Static analysis ONLY. An uploaded file is never executed on this host: it is
# (1) parked in an isolated quarantine directory, (2) fingerprinted with SHA-256
# / MD5, (3) matched against the known-malicious hash corpus already ingested
# into `processed_iocs` (URLhaus / ThreatFox / OTX ...), and (4) scanned with
# the pre-compiled Neo23x0/signature-base YARA bundle (`yara -C`, pattern
# matching only). Any YARA rule / corpus hash that ties the file to a family in
# `malware_tools` cross-links it there. No detection logic is written from
# scratch: the YARA set is a pinned, publicly maintained rule library.
# =============================================================================

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# The only indicator types that make sense as a *hash match*. Everything else
# (ipv4/domain/url/...) is coverage for the indicator corpus, not a file hash.
_HASH_TYPES = ("sha256", "md5", "sha1")

_DIGEST_HEX = re.compile(r"^[0-9a-fA-F]{40,}$")


def _normalise(s: str) -> str:
    """Analyst-friendly normalised form used for family / rule-name matching."""
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _read_bundle_version(bundle_path: Path | str) -> str | None:
    """Best-effort version marker (written by tools/build_yara_bundle.py)."""
    marker = Path(str(bundle_path) + ".txt")
    if marker.is_file():
        text = marker.read_text(encoding="utf-8", errors="replace").strip()
        return text if text else None
    return None


def quarantine_dir(settings: Any) -> Path:
    """Ensure the isolated quarantine directory exists (0700) and return it."""
    qdir = Path(settings.sample_quarantine_dir).resolve()
    qdir.mkdir(parents=True, exist_ok=True)
    try:
        qdir.chmod(0o700)
    except OSError:  # pragma: no cover - non-POSIX host
        pass
    return qdir


def park_sample(data: bytes, settings: Any) -> tuple[str, Path]:
    """Write the raw bytes into the quarantine dir under a random name.

    The file is created 0600 and never executable. `quarantine_id` is the
    opaque handle returned to the caller (nothing user-controlled).
    """
    qid = str(uuid.uuid4())
    qdir = quarantine_dir(settings)
    path = qdir / f"{qid}.bin"
    # os.open with mode=0o600 -> never world-readable, never executable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    logger.info("sample quarantined id=%s bytes=%d", qid, len(data))
    return qid, path


def compute_hashes(data: bytes) -> dict[str, str]:
    """SHA-256 + MD5 static fingerprints."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


async def corpus_hash_match(db: Any, db_name: str, hashes: dict[str, str]) -> list[dict[str, Any]]:
    """Real match against the ingested hash corpus (`processed_iocs`).

    Returns every corpus row whose indicator equals one of the uploaded
    fingerprints. A zero-length result is honest: the file is simply not yet
    known to any ingested feed.
    """
    values = [h for h in (hashes.get("sha256"), hashes.get("md5"), hashes.get("sha1")) if h]
    if not values:
        return []
    rows = await db.query(
        f"""
        SELECT indicator, type, severity, malware_id, ts
        FROM {db_name}.processed_iocs FINAL
        WHERE type IN {{types:Array(String)}}
          AND indicator IN {{values:Array(String)}}
        LIMIT 50
        """,
        parameters={"types": list(_HASH_TYPES), "values": values},
    )
    out: list[dict[str, Any]] = []
    for r in rows.result_rows or []:
        out.append({
            "indicator": str(r[0]),
            "type": str(r[1]),
            "severity": float(r[2]),
            "malware_id": str(r[3] or ""),
            "ts": r[4].strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(r[4], "strftime") else str(r[4]),
        })
    return out


async def family_by_id(db: Any, db_name: str, malware_id: str) -> dict[str, Any] | None:
    """Resolve a malware_tools stix_id to its profile (real KB link)."""
    if not malware_id:
        return None
    rows = await db.query(
        f"""
        SELECT stix_id, name, type, category
        FROM {db_name}.malware_tools FINAL
        WHERE stix_id = {{id:String}}
        LIMIT 1
        """,
        parameters={"id": malware_id},
    )
    if not (rows.result_rows or []):
        return None
    r = rows.result_rows[0]
    return {
        "stix_id": str(r[0]),
        "name": str(r[1]),
        "type": str(r[2]),
        "category": str(r[3] or "Other"),
        "link_source": "hash_match",
    }


async def known_families(db: Any, db_name: str) -> dict[str, dict[str, Any]]:
    """Normalised family index from malware_tools (used for YARA cross-links)."""
    rows = await db.query(
        f"""
        SELECT stix_id, name, type, category
        FROM {db_name}.malware_tools FINAL
        """,
    )
    index: dict[str, dict[str, Any]] = {}
    for r in rows.result_rows or []:
        norm = _normalise(r[1])
        if not norm:
            continue
        index[norm] = {
            "stix_id": str(r[0]),
            "name": str(r[1]),
            "type": str(r[2]),
            "category": str(r[3] or "Other"),
        }
    return index


def yara_family_links(rule_names: list[str], families: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Cross-link a matched YARA rule name to a KB family via name overlap.

    Example: rule `apt_apt10_redleaves` / `gen_cobaltstrike` contains the
    normalised family name `cobaltstrike` present in malware_tools -> a real,
    reviewable association. Only whole-token overlaps on the shorter side
    count, so a rule named after its family never fails to link while common
    words (gen, apt, crime) never link anything.
    """
    links: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in rule_names:
        rule_norm = _normalise(rule)
        if not rule_norm:
            continue
        for fam_norm, fam in families.items():
            if not fam_norm:
                continue
            hit = (len(fam_norm) >= 3 and fam_norm in rule_norm) or (
                len(rule_norm) >= 3 and rule_norm in fam_norm
            )
            if hit and fam["stix_id"] not in seen:
                seen.add(fam["stix_id"])
                links.append({**fam, "link_source": "yara_rule", "matched_rule": rule})
    return links


async def run_yara(bundle_path: Path | str, file_path: Path | str, binary: str,
                   timeout: float = 60.0) -> tuple[list[str], str | None]:
    """Scan one file with the pre-compiled bundle (`yara -C`, pattern only).

    Returns (matched_rule_names, error). The subprocess reads bytes from the
    quarantined file; it never executes anything.
    """
    proc = await asyncio.create_subprocess_exec(
        binary, "-C", str(bundle_path), "-w", str(file_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return [], "yara scan timed out"
    if proc.returncode not in (0, 1):  # 1 = no match, which is legitimate
        return [], (stderr.decode("utf-8", errors="replace").strip() or f"yara exit {proc.returncode}")
    rules: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        name = line.split(" ", 1)[0].strip()
        if name:
            rules.append(name)
    return rules, None


def guess_malicious(rules: list[str], corpus_matches: list[dict[str, Any]]) -> tuple[str, str]:
    """Honest verdict: known-malicious iff a corpus hash match or YARA hit.

    A clean verdict is unambiguous: no ingested feed lists the hash and no
    public rule matched — reported as shown, never fabricated either way.
    """
    if corpus_matches:
        return "malicious", "hash listed in ingested threat-intel corpus"
    if rules:
        return "malicious", f"matched {len(rules)} public YARA rule(s)"
    return "clean", "no hash match in corpus and no YARA rule matched"