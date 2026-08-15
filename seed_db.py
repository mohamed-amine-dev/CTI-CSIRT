#!/usr/bin/env python3
# =============================================================================
# CTI Platform - database seeder for LOCAL DEVELOPMENT ONLY
# -----------------------------------------------------------------------------
# !! DEV-ONLY CONVENIENCE SCRIPT. Never part of the production start command,
# !! never imported by the app, never used to fake a "working" demo. The running
# !! product must be powered by real collector/AI rows written into ClickHouse;
# !! this script exists so a developer can populate a blank local DB to test the
# !! UI when external feeds are blocked / rate-limited.
# -----------------------------------------------------------------------------
# Fills an (empty) ClickHouse instance with 50 realistic mock CTI records so the
# React dashboard is immediately testable even when external feeds are blocked,
# rate-limited or empty:
#
#   * ~30 raw threat-intel items      -> raw_threat_intel   (feeds, APT intel)
#   * ~20 processed indicators (IOCs) -> processed_iocs     (IPs, hashes, ...)
#   * ~6  dummy Alert Sheets       -> vulnerability_alerts (full 4-point JSON)
#
# The mock corpus is APT-flavoured (Lazarus, LockBit, Turla ...) so the search
# pages, charts and "Alert Sheet" viewer all have realistic content.
#
# Prerequisites:
#   1. ClickHouse is running  (tools/clickhouse server --daemon -- --path=...)
#   2. Backend venv is active (uses app.config + app.db, so run from the repo
#      root with the same .env / CLICKHOUSE_* settings as the app).
#
# Usage (from the repository root):
#   .venv/bin/python seed_db.py            # (or)  python seed_db.py
#   .venv/bin/python seed_db.py --reset    # wipe the 3 tables first, then seed
#
# The script is idempotent: re-running it upserts (ReplacingMergeTree) with a
# newer `version`, so repeated runs never create duplicate rows.
# =============================================================================

from __future__ import annotations

import argparse
import logging
import random
import time
from typing import Any

from app.ai_processor import (
    EnvironmentalImpact,
    ExploitationStatus,
    AlertSheetModel,
    RemediationPlan,
    RiskAssessment,
)
from app.config import settings
from app.db import get_sync_client
from app.db_init import create_schema

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("seed_db")

TABLES = ("raw_threat_intel", "processed_iocs", "vulnerability_alerts")

# ---------------------------------------------------------------------------
# Mock raw threat-intel corpus (source, raw_text, url)
# ---------------------------------------------------------------------------
RAW_RECORDS: list[tuple[str, str, str]] = [
    # --- CISA KEV -----------------------------------------------------------
    ("CISA-KEV", "CVE-2024-3400 Palo Alto Networks PAN-OS GlobalProtect command injection affects PAN-OS 10.2/11.0/11.1. Added 2024-04-19, due 2025-01-15. Ransomware campaign use: no. Notes: exploited in the wild by APT groups. Required action: apply vendor hotfix.", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("CISA-KEV", "CVE-2023-34362 Progress MOVEit Transfer SQL injection affects MOVEit Transfer versions prior to 2023.0. Added 2023-06-15. Ransomware campaign use: yes (CL0P). Required action: apply vendor patch.", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("CISA-KEV", "CVE-2021-44228 Apache Log4j2 remote code execution affects Log4j 2.0-beta9 through 2.15.0. Added 2021-12-10. Ransomware campaign use: yes (numerous groups). Required action: upgrade to Log4j 2.17.0.", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),

    # --- NVD ----------------------------------------------------------------
    ("NVD", "CVE-2024-6387 OpenSSH server race condition in signal handling leads to unauthenticated remote code execution on glibc-based Linux systems (regreSSHion). Base score 8.1 HIGH.", "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
    ("NVD", "CVE-2023-44487 HTTP/2 Rapid Reset denial-of-service: attacker opens thousands of streams and resets them, exhausting server resources. Base score 7.5 HIGH.", "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"),

    # --- European CERTs -----------------------------------------------------
    ("CERT-FR", "CERTFR-2024-ACT-008 : recommandations de sécurité relatives à la campagne d'exploitation de CVE-2024-3400 sur les pare-feux PAN-OS. Application du correctif d'urgence recommandée.", "https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-ACT-008/"),
    ("CERT-FR", "CERTFR-2023-ACT-042 : vulnérabilité critique dans MOVEit Transfer (CVE-2023-34362) exploitée par le groupe CL0P. Mise à jour immédiate obligatoire.", "https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-ACT-042/"),
    ("CERT-EU", "CERT-EU SA-2024-014 : exploitation active de CVE-2024-3400 dans des environnements de l'UE. Segregation réseau et correctif d'urgence recommandés.", "https://cert.europa.eu/publications/security-advisories/CERT-EU-SA-2024-014/"),
    ("CERT-EU", "CERT-EU SA-2023-091 : campagne LockBit contre les passerelles MOVEit. Surveillance renforcée des logs IIS/WebShell.", "https://cert.europa.eu/publications/security-advisories/CERT-EU-SA-2023-091/"),

    # --- News / APT intelligence ---------------------------------------------
    ("NEWS", "Lazarus Group (DPRK) targeted cryptocurrency exchanges in Europe using fake job interviews and malicious npm packages; IOCs include wallet-drainer binaries and C2 domains under .top.", "https://thehackernews.com/2024/05/lazarus-group-targets-crypto.html"),
    ("NEWS", "LockBit ransomware claimed 1,800 victims before the takedown; the group's data-leak site resurfaced with a list of recent attacks on healthcare providers.", "https://thehackernews.com/2024/03/lockbit-takedown-aftermath.html"),
    ("NEWS", "Global phishing wave abuses Microsoft 365 brandings: over 40k credential-harvesting pages detected this week, largely hosted on compromised .tk and .xyz domains.", "https://www.cybercrimenews.com/feed"),
    ("OTX", "AlienVault pulse 'Lazarus Operation DreamJob 2.0' bundles IOCs: droppers, C2 IPs 45.77.55.111 and 103.105.53.110, and KeePass-triggered beaconing.", "https://otx.alienvault.com/pulse/6354a1e3d4c9f0e5b7a81234"),
    ("APT", "APT28 (Fancy Bear) spear-phishing campaign against NATO staff: lure documents (iso + chm) drop Graphite/Gooberload; C2 via compromised blog .ru endpoints.", "https://www.cert.ssi.gouv.fr/"),
    ("APT", "Turla uses 'Topinambour' backdoor against European ministries; commands hidden in PNG steganography, C2 over https on 185.220.101.22.", "https://www.cert.ssi.gouv.fr/"),

    # --- URLhaus / OpenPhish / botnets ---------------------------------------
    ("URLHAUS", "Malicious URL: http://kavtest.top/u7h2 threat=botnet tags=emotet,trickbot", "http://kavtest.top/u7h2"),
    ("URLHAUS", "Malicious URL: https://dload-lockbit.onion/dl tags=ransomware,lockbit", "https://dload-lockbit.onion/dl"),
    ("URLHAUS", "Malicious URL: http://cdn-update-m365.tk/payload.exe tags=stealer,redline", "http://cdn-update-m365.tk/payload.exe"),
    ("OPENPHISH", "Phishing URL: https://login-microsoft-verify.tk/", "https://login-microsoft-verify.tk/"),
    ("OPENPHISH", "Phishing URL: https://secure-appleid-help.xyz/", "https://secure-appleid-help.xyz/"),
    ("OPENPHISH", "Phishing URL: https://webmail-auth-confirm.cc/", "https://webmail-auth-confirm.cc/"),
    ("FEODO-C2", "Botnet C2 IP: 91.219.215.77", "https://feodotracker.abuse.ch/host/91.219.215.77/"),
    ("FEODO-C2", "Botnet C2 IP: 185.220.101.22", "https://feodotracker.abuse.ch/host/185.220.101.22/"),
    ("FEODO-C2", "Botnet C2 IP: 45.77.55.111", "https://feodotracker.abuse.ch/host/45.77.55.111/"),
    ("BLOCKLISTDE", "Brute-force attacker IP: 45.155.205.33", ""),
    ("BLOCKLISTDE", "Brute-force attacker IP: 198.51.100.77", ""),
    ("SPAMHAUS-DROP", "Hijacked netblock: 45.154.0.0/17", ""),
    ("SPAMHAUS-DROP", "Hijacked netblock: 103.105.52.0/22", ""),
    ("THREATFOX", "IOC 4f7c3a1b2e9d8c7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e type=sha256 malware=HermeticWiper threat_type=wiper", "https://threatfox.abuse.ch/browse.php?search=4f7c3a1b2e9d8c7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"),
    ("THREATFOX", "IOC http://c2-lazarus-top-2024.top:8080 type=url malware=AppleJeus threat_type=banking", "https://threatfox.abuse.ch/browse.php?search=c2-lazarus-top-2024.top"),
    ("SSLBL-JA3", "Malicious JA3 7e5b8e4a4f2c9d0b1a3f6e8c5d4b7a2f: TLS client fingerprint tied to Qakbot C2 communications", ""),

    # --- Shodan / dark web -----------------------------------------------------
    ("SHODAN-INTERNETDB", "InternetDB enrichment for 91.219.215.77: ports=[80, 443, 8443], hostnames=[c2-bootstrap.ru], tags=[botnet], vulns=[CVE-2024-3400]", "https://internetdb.shodan.io/91.219.215.77"),
    ("DARKWEB-ONION", "Ransomware leak-site listing for a European logistics firm: 12 GB of internal documents staged for release in 72 hours unless payment is made in BTC.", "http://lockbit7wvg5ttx2gstqj6d4vklbzdyfihc6c4k6m5qy2j3k.onion"),
]

# ---------------------------------------------------------------------------
# Mock processed indicators (indicator, type, severity)
# ---------------------------------------------------------------------------
MOCK_IOCS: list[tuple[str, str, float]] = [
    # IPs (APT C2 / botnets)
    ("45.77.55.111", "ipv4", 8.5),
    ("103.105.53.110", "ipv4", 8.0),
    ("91.219.215.77", "ipv4", 8.0),
    ("185.220.101.22", "ipv4", 7.5),
    ("45.155.205.33", "ipv4", 6.0),
    ("198.51.100.77", "ipv4", 5.0),
    # Domains
    ("c2-lazarus-top-2024.top", "domain", 8.0),
    ("login-microsoft-verify.tk", "domain", 7.5),
    ("secure-appleid-help.xyz", "domain", 7.0),
    ("kavtest.top", "domain", 6.5),
    # Hashes (malware)
    ("4f7c3a1b2e9d8c7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e", "sha256", 9.0),
    ("2c1b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", "sha256", 8.5),
    ("5d41402abc4b2a76b9719d911017c592", "md5", 7.0),
    ("7f138f09197bdfe7bd5f0b9d7c0f1f1f", "md5", 6.5),
    ("3c8c1f1a1f1b1c1d1e1f2a2b2c2d2e2f2a3b3c3d3e3f4a4b4c4d4e4f5a5b5c", "sha1", 6.0),
    # URLs
    ("http://cdn-update-m365.tk/payload.exe", "url", 8.5),
    ("http://kavtest.top/u7h2", "url", 7.0),
    # CIDR + JA3
    ("45.154.0.0/17", "cidr", 7.0),
    ("7e5b8e4a4f2c9d0b1a3f6e8c5d4b7a2f", "ja3", 7.0),
    # CVEs
    ("CVE-2024-3400", "cve", 9.8),
    ("CVE-2023-34362", "cve", 9.8),
]

# ---------------------------------------------------------------------------
# Mock Alert Sheets (dummy, valid 4-point JSON per AlertSheetModel)
# ---------------------------------------------------------------------------
def _sheet(
    cve: str,
    risk: str,
    score: float,
    poc: bool,
    summary: str,
) -> AlertSheetModel:
    return AlertSheetModel(
        vuln_cve=cve,
        environmental_impact=EnvironmentalImpact(
            affected_versions=["version >= 10.2 (see advisory)"],
            check_procedure="Run the vendor version check script or compare `show system info` output with the affected range.",
            evidence="Mock evidence extracted from the advisory: product in the affected version range.",
        ),
        risk_level=RiskAssessment(
            risk_level=risk,  # type: ignore[arg-type]  # valid literal
            exploit_paths=["Network-exposed service", "Unauthenticated request path"],
            compromise_impact="Full remote compromise: confidentiality, integrity and availability.",
        ),
        exploitation_status=ExploitationStatus(
            public_poc_available=poc,
            poc_url="https://github.com/rapid7/metasploit-framework" if poc else None,
            conditions="Exploitation requires no authentication; mitigation possible via patching.",
        ),
        remediation_solutions=RemediationPlan(
            patch=f"Apply the official vendor patch for {cve} immediately.",
            hardening="Disable the affected module if it is not required for business operations.",
            isolation="Segment the affected hosts behind an internal-only VLAN.",
            access_restriction="Restrict exposure to trusted networks; enforce MFA on administrative interfaces.",
        ),
        ai_summary=summary,
    )

MOCK_SHEETS: list[AlertSheetModel] = [
    _sheet("CVE-2024-3400", "CRITICAL", 9.8, True,
           "Critical unauthenticated command injection in PAN-OS GlobalProtect, actively exploited in the wild by state-sponsored actors. Patch immediately and restrict GlobalProtect exposure."),
    _sheet("CVE-2023-34362", "CRITICAL", 9.8, True,
           "Progress MOVEit Transfer SQL injection abused by CL0P ransomware. Mass exploitation observed; patch and inspect IIS logs for web-shell uploads."),
    _sheet("CVE-2021-44228", "HIGH", 9.8, True,
           "Log4Shell remote code execution in Apache Log4j2. Trivial exploitation via crafted log lines; upgrade to 2.17.0 and sweep for other vulnerable Java services."),
    _sheet("CVE-2024-6387", "HIGH", 8.1, True,
           "regreSSHion: race condition in OpenSSH sshd leading to unauthenticated RCE on glibc Linux. No public PoC initially, then proven; upgrade to 9.8p1."),
    _sheet("CVE-2023-44487", "HIGH", 7.5, False,
           "HTTP/2 Rapid Reset denial-of-service. No single vendor fix; apply proxy rate limits and HTTP/2 stream limits."),
    _sheet("CVE-2021-41773", "MEDIUM", 7.5, True,
           "Apache HTTP Server path traversal enabling RCE in CGI setups. Upgrade to 2.4.50 and disable CGI or restrict path access."),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ts() -> int:
    return int(time.time() * 1_000_000)


def _wipe(client: Any) -> None:
    for table in TABLES:
        client.command(f"TRUNCATE TABLE {settings.clickhouse_database}.{table}")
        logger.info("truncated %s.%s", settings.clickhouse_database, table)


def _seed_raw(client: Any, base_ts: int) -> int:
    now = base_ts
    rows = []
    for i, (source, text, url) in enumerate(RAW_RECORDS):
        now += 1_000_000  # strictly increasing version per row
        rows.append([source, text, url or f"https://mock.local/{source.lower()}/{i}", now])
    client.insert(table="raw_threat_intel", data=rows,
                  column_names=["source", "raw_text", "url", "version"])
    logger.info("seeded %d rows -> raw_threat_intel", len(rows))
    return len(rows)


def _seed_iocs(client: Any, base_ts: int) -> int:
    now = base_ts + 100_000_000
    rows = []
    for indicator, ioc_type, severity in MOCK_IOCS:
        now += 1_000_000
        rows.append([indicator, ioc_type, severity, now])
    client.insert(table="processed_iocs", data=rows,
                  column_names=["indicator", "type", "severity", "version"])
    logger.info("seeded %d rows -> processed_iocs", len(rows))
    return len(rows)


def _seed_sheets(client: Any, base_ts: int) -> int:
    now = base_ts + 200_000_000
    rows = []
    for i, sheet in enumerate(MOCK_SHEETS):
        now += 1_000_000
        rows.append([
            sheet.vuln_cve,
            sheet.environmental_impact.model_dump_json(),
            sheet.risk_level.model_dump_json(),
            sheet.exploitation_status.model_dump_json(),
            sheet.remediation_solutions.model_dump_json(),
            sheet.ai_summary,
            sheet.risk_level.risk_level == "CRITICAL" and 9.8 or 7.5,
            now,
        ])
    client.insert(table="vulnerability_alerts", data=rows,
                  column_names=[
                      "vuln_cve", "environmental_impact", "risk_level",
                      "exploitation_status", "remediation_solutions",
                      "ai_summary", "threat_score", "version",
                  ])
    logger.info("seeded %d rows -> vulnerability_alerts", len(rows))
    return len(rows)


def _summary(client: Any) -> None:
    db = settings.clickhouse_database
    for table in TABLES:
        rows = client.query(f"SELECT count() FROM {db}.{table} FINAL")
        logger.info("FINAL count %s.%s = %d", db, table, rows.result_rows[0][0])


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ClickHouse with mock CTI data.")
    parser.add_argument("--reset", action="store_true",
                        help="TRUNCATE the three tables before seeding (idempotent reruns).")
    args = parser.parse_args()

    logger.info("ensuring schema on %s/%s", settings.clickhouse_url, settings.clickhouse_database)
    create_schema()

    client = get_sync_client()
    try:
        if args.reset:
            _wipe(client)
        random.seed(42)
        base_ts = _ts()
        n_raw = _seed_raw(client, base_ts)
        n_iocs = _seed_iocs(client, base_ts)
        n_sheets = _seed_sheets(client, base_ts)
        logger.info("done: %d raw + %d iocs + %d sheets (total %d records)",
                    n_raw, n_iocs, n_sheets, n_raw + n_iocs + n_sheets)
        _summary(client)
        logger.info("start the app: .venv/bin/uvicorn app.main:app --port 8000")
    finally:
        client.close()


if __name__ == "__main__":
    main()
