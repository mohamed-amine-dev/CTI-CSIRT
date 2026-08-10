# =============================================================================
# CTI Platform - Threat & malware category classification (deterministic)
# -----------------------------------------------------------------------------
# Maps a raw intel record to one of the supervisor's threat categories:
#   Ransomware, Worm, Trojan/RAT, Botnet, Infostealer, Wiper, Phishing Kit,
#   DDoS Tool, Exploit/PoC, Backdoor, Other.
#
# Pure rule-based classification over the record's OWN text (no LLM): specific
# family names and action words first, then a per-source default. Everything is
# derived from real record content — nothing is invented. This is used both at
# ingestion time (new records) and by the backfill for existing rows, so the
# Threat Landscape dashboard is deterministic and auditable.
# =============================================================================

from __future__ import annotations

from typing import Any

THREAT_CATEGORIES = (
    "Ransomware", "Worm", "Trojan/RAT", "Botnet", "Infostealer",
    "Wiper", "Phishing Kit", "DDoS Tool", "Exploit/PoC", "Backdoor", "Other",
)

# Category -> lowercased family names / action words. Order matters: the first
# matching category in this list wins, so the most specific signal
# (e.g. "redline" -> Infostealer) beats the generic keyword.
_CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Ransomware", (
        "ransomware", " ransom ", "lockbit", "cl0p", " clop ", "conti", "revil",
        "blackcat", "blackbasta", "ryuk", "wannacry", "notpetya", " petya ",
        " hive ", " akira ", " play ransomware", " qilin", "alphv", " mallox",
        " medusa ransomware", "knight ransomware", "ransomed.vc", "8base",
    )),
    ("Wiper", (
        " wiper", "killdisk", "akaruh", "dustman", "destructive malware",
        "data-wiping", "disk-wiping",
    )),
    ("Infostealer", (
        "infostealer", " stealer", "redline", "raccoon", "stealc", "vidar",
        "lumma", "agenttesla", "azorult", "formbook", "rhadamanthys",
        "amarok", "keylog", "credential theft", "password stealer",
        "exfiltrat", "information stealer", " info stealer",
    )),
    ("Phishing Kit", (
        "phishing", "phish kit", "phishkit", "smish", "spearphish",
        "credential harvest", "fake login", "credential harvester",
    )),
    ("Botnet", (
        "botnet", "command and control", " c2 ", "c2 server", " c&c ", "mirai",
        "ekoi", "qakbot", "qbot", "emotet", "trickbot", "icedid", "dridex",
        "bots", "zombie", "proxybot", "tsunami", "gafgyt",
    )),
    ("DDoS Tool", (
        "ddos", "distributed denial of service", "stresser", "booters",
        "amplification attack",
    )),
    ("Backdoor", (
        "backdoor", "webshell", "cobaltstrike", "cobalt strike", "beacon ",
        "remote access trojan", "njtel", "njrat", "asyncrat", "nanocore",
        "remcos", "darkcomet",
    )),
    ("Worm", (
        " worm", "self-propagat", "self replicat", "worm-like",
    )),
    ("Trojan/RAT", (
        "trojan", " rat ", "remote access", "loader", "dropper", "malware_download",
        "payload delivery", "payload_delivery", "banking trojan",
    )),
    ("Exploit/PoC", (
        "exploit", " poc ", "rce", "remote code execution", "zero-day",
        "buffer overflow", "privilege escalation", "xss", "cross-site scripting",
        "sql injection", "csrf", "deserialization", "command injection",
        "arbitrary code execution", "cve-", "vulnerability", "advisory",
    )),
)

# Sources whose records carry no malware-family signal get an honest default so
# the landscape reflects what the source actually reports.
_SOURCE_DEFAULTS = {
    "OPENPHISH": "Phishing Kit",
    "FEODO-C2": "Botnet",
    "SSLBL-JA3": "Botnet",
    "SPAMHAUS-DROP": "Botnet",       # hijacked netblocks used for spam / C2
    "BLOCKLISTDE": "Other",          # brute-force scanners / attacks
    "DARKWEB-ONION": "Other",        # scraped pages (real target list decides)
    "NVD": "Exploit/PoC",
    "CISA-KEV": "Exploit/PoC",
    "CISA-ADV": "Exploit/PoC",
    "CERT-FR": "Exploit/PoC",
    "CERT-EU": "Exploit/PoC",
}


def classify_threat(source: str | None, raw_text: str | None, **_: Any) -> str:
    """Deterministic threat category for one record.

    Keyword rules are evaluated first (family names beat source defaults), then
    the per-source default applies. Extra kwargs (indicators, meta, ...) are
    accepted for forward-compatibility but not required.
    """
    src = (source or "").upper()
    text = (raw_text or "").lower()

    for category, keywords in _CATEGORY_RULES:
        for kw in keywords:
            if kw in text:
                return category
    return _SOURCE_DEFAULTS.get(src, "Other")
