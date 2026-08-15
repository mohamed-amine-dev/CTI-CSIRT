# =============================================================================
# CTI Platform - Export serializers (CSV / JSON / STIX 2.1)
# -----------------------------------------------------------------------------
# Pure functions that turn the read-model rows of the platform (alerts, iocs,
# raw feeds, notifications) into analyst-ready export payloads:
#
#   to_csv(rows, fields)   -> RFC-4180 CSV text (Excel-safe quoting)
#   to_json(rows)          -> pretty-printed JSON array
#   to_stix(rows, kind)    -> STIX 2.1 Bundle for alerts/iocs/feeds
#
# The STIX emitter intentionally maps only well-defined cases to standard
# object types (vulnerability / indicator / report). The Sheet is a
# vulnerability, an IOC is an indicator, a raw feed item is a report.
# =============================================================================

from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

STIX_VERSION = "2.1"

_ESC = "\\'"


def _now() -> str:
    """UTC timestamp in STIX 2.1 format (RFC 3339)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stix_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"


def to_csv(rows: list[dict[str, Any]], fields: list[str]) -> str:
    """Serialize a list of dicts to RFC-4180 CSV, always writing the header."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: (_json_str(v) if isinstance(v, (dict, list)) else _plain(v)) for k, v in row.items()})
    return buf.getvalue()


def to_json(rows: list[dict[str, Any]]) -> str:
    return json.dumps(rows, indent=2, ensure_ascii=False, default=str)


def to_stix(rows: list[dict[str, Any]], kind: str) -> str:
    """Build a STIX 2.1 Bundle for a list of normalized export rows."""
    objects: list[dict[str, Any]] = []
    for r in rows:
        obj = _to_stix_object(r, kind)
        if obj is not None:
            objects.append(obj)
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": STIX_VERSION,
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False, default=str)


def _to_stix_object(row: dict[str, Any], kind: str) -> dict[str, Any] | None:
    if kind == "alerts":
        return {
            "type": "vulnerability",
            "id": _stix_id("vulnerability"),
            "name": row.get("vuln_cve") or row.get("cve") or "UNKNOWN",
            "description": (row.get("ai_summary") or "").strip() or None,
            "external_references": [
                {"source_name": "cve", "external_id": row.get("vuln_cve") or row.get("cve") or ""}
            ],
            "x_threat_score": row.get("threat_score"),
            "x_risk_level": row.get("risk_level"),
            "x_exploitation_status": row.get("exploitation_status"),
            "created": _now(),
            "modified": _now(),
        }
    if kind == "iocs":
        indicator = row.get("indicator")
        if not indicator:
            return None
        pattern = _stix_pattern(row.get("type"), indicator)
        obj: dict[str, Any] = {
            "type": "indicator",
            "id": _stix_id("indicator"),
            "name": f"{row.get('type', 'ioc').upper()} {indicator}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _now(),
            "labels": ["malicious-activity", "osint"],
        }
        sev = row.get("severity")
        if sev is not None:
            obj["x_threat_score"] = round(sev, 2)
        return obj
    if kind == "feeds":
        return {
            "type": "report",
            "id": _stix_id("report"),
            "name": row.get("source") or "Raw feed item",
            "description": (row.get("raw_text") or "").strip()[:5000] or None,
            "published": (row.get("ts") or _now()),
            "report_types": ["threat-report"],
            "created": _now(),
            "modified": _now(),
        }
    return None


def _stix_pattern(ioc_type: str | None, indicator: str) -> str:
    """STIX 2.1 pattern literal for the supported indicator families."""
    t = (ioc_type or "").lower()
    v = str(indicator).replace(_ESC, "\\'")
    if t == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if t == "ipv6":
        return f"[ipv6-addr:value = '{v}']"
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t in ("md5", "sha1", "sha256"):
        key = t.upper()
        return f"[file:hashes.'{key}' = '{v}']"
    if t == "cve":
        return f"[vulnerability:name = '{v}']"
    if t == "email":
        return f"[email-addr:value = '{v}']"
    if t == "ja3":
        return f"[x-ja3:value = '{v}']"
    return f"[x-custom-indicator:value = '{v}']"


def _plain(v: Any) -> Any:
    """Normalize scalars for CSV cells (dates to iso, None to empty)."""
    if v is None:
        return ""
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def _json_str(v: Any) -> str:
    """Flatten nested objects into a compact JSON string for a CSV cell."""
    return json.dumps(v, ensure_ascii=False, default=str)
