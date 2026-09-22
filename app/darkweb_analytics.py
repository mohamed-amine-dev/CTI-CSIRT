# =============================================================================
# CTI Platform - Dark Web / Telegram monitoring analytics (DRPS-style)
# -----------------------------------------------------------------------------
# Deterministic, auditable analytics for the monitoring stream. Everything is
# derived from the item's OWN raw_text: theme grouping, severity band, signal
# extraction and the "why it matters" briefing. There is no LLM, no guesswork:
# every severity reason carries the exact keyword that fired, and the briefing
# recommendations are bound to signals actually present in the text (and to
# real platform capabilities). The engine is stdlib-only so it can be loaded
# and cross-checked by verification scripts without the app package.
# =============================================================================

from __future__ import annotations

import re
import time
from typing import Any

SEVERITY_BANDS: tuple[str, str, str, str] = ("Critical", "High", "Medium", "Low")
_SEV_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# band -> [(reason label, keyword)]. First band with ANY match wins the band;
# but the full match list across all bands is kept so the briefing can justify
# itself. Keywords match case-insensitively against the lowercased raw text.
SEVERITY_RULES: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Critical",
        [
            ("carding operation", "carding"),
            ("CVV / payment-card data", "cvv"),
            ("stolen payment cards", "stolen cards"),
            ("card dump site", "card dump"),
            ("credential list dump", "combolist"),
            ("credential dump", "credential dump"),
            ("password dump", "password dump"),
            ("infostealer log data", "stealer log"),
            ("infostealer malware", "infostealer"),
            ("credential stuffing", "credential stuffing"),
            ("mass credential leak", "billion leaked"),
            ("mass stolen-data claim", "million stolen"),
            ("account takeover", "account takeover"),
        ],
    ),
    (
        "High",
        [
            ("LockBit ransomware group", "lockbit"),
            ("Cl0p ransomware group", "cl0p"),
            ("BlackCat ransomware group", "blackcat"),
            ("ransomware activity", "ransomware"),
            ("extortion pressure", "ransom"),
            ("data leaked", "leaked"),
            ("data leak", "data leak"),
            ("data breach", "data breach"),
            ("breach archive", "breach"),
            ("leak-search portal", "leak-lookup"),
            ("exploit chain", "exploit"),
            ("remote code execution", "rce"),
            ("zero-day", "zero-day"),
            ("zero-day", "zero day"),
            ("phishing", "phishing"),
            ("stealer malware", "stealer"),
            ("malware", "malware"),
            ("trojan", "trojan"),
            ("botnet", "botnet"),
            ("credential harvesting", "credential dumping"),
            ("credential theft", "credentials"),
            ("credential access", "credential"),
            ("CVE referenced", "cve-"),
        ],
    ),
    (
        "Medium",
        [
            ("vulnerability context", "vulnerab"),
            ("attack activity", "attack"),
            ("compromise", "compromis"),
            ("exposure", "exposed"),
            ("dark web context", "dark web"),
            ("dark web context", "darkweb"),
            (".onion service", ".onion"),
            ("forum discussion", "forum"),
            ("marketplace", "marketplace"),
            ("dump archive", "dump"),
            ("fraud", "fraud"),
            ("scam", "scam"),
            ("threat intelligence reference", "threat intelligence"),
        ],
    ),
]

# Phrasing that marks an item as educational/defensive rather than an active
# threat. If present, Critical/High findings are capped to Medium with the
# reason recorded (transparent down-rank, never hidden).
_DEFENSIVE_CONTEXT = (
    "how to",
    "defense",
    "defend",
    "prevent",
    "mitigation",
    "best practice",
    "awareness",
    "guide",
    "detection and prevention",
    "use cases",
    "what is",
)

# theme_id -> (display label, [keywords]). First theme per item is the primary
# grouping; multiple themes are allowed and each carries its matched keywords.
THEME_RULES: list[tuple[str, str, list[str]]] = [
    ("credential", "Credentials & Infostealers",
     ["credential", "password", "login", "hash", "infostealer", "stealer",
      "credential stuffing", "combolist", "logging"]),
    ("ransomware", "Ransomware & Extortion",
     ["ransom", "lockbit", "cl0p", "blackcat", "extort"]),
    ("breach", "Data Breaches & Leaks",
     ["leak", "breach", "dump", "expos", "stolen", "compromis"]),
    ("carding", "Carding & Financial Fraud",
     ["carding", "cvv", "card", "fraud", "payment", "stash"]),
    ("malware", "Malware & Exploitation",
     ["malware", "trojan", "botnet", "exploit", "rce", "zero-day", "payload",
      "backdoor", "mimikatz"]),
    ("phishing", "Phishing & Scams",
     ["phish", "smish", "scam", "spoof"]),
    ("darkweb", "Dark Web & Marketplaces",
     ["onion", "dark web", "darkweb", "marketplace", "forum", "dumps site"]),
]

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ONION_RE = re.compile(r"\b[a-z0-9]{1,56}\.onion\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|info|me|dev|xyz|"
    r"onion|gov|edu|ru|cn|de|uk|fr|cloud|app|ai|site|shop|biz|su|top)\b",
    re.IGNORECASE,
)
_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9_.])@[A-Za-z0-9_]{3,32}")
_TELEGRAM_RE = re.compile(r"(?:t\.me|telegram\.me)/[A-Za-z0-9_]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        low = it.rstrip(".,;)]")
        if low and low.lower() not in seen:
            seen.add(low.lower())
            out.append(low)
    return out


def extract_signals(text: str) -> dict[str, Any]:
    """Real artifacts found *in the text* of one finding. No inference."""
    t = text or ""
    urls = _dedup(m.strip() for m in _URL_RE.findall(t))
    onions = _dedup(_ONION_RE.findall(t))
    ips = _dedup(
        o for o in _IPV4_RE.findall(t)
        if all(0 <= int(part) <= 255 for part in o.split("."))
    )
    domains = _dedup(d.lower() for d in _DOMAIN_RE.findall(t))
    handles = _dedup(_TELEGRAM_RE.findall(t) + _HANDLE_RE.findall(t))
    emails = _dedup(_EMAIL_RE.findall(t))
    cves = _dedup(c.upper() for c in _CVE_RE.findall(t))

    counts = {
        "domains": len(domains),
        "urls": len(urls),
        "ips": len(ips),
        "onions": len(onions),
        "handles": len(handles),
        "emails": len(emails),
        "cves": len(cves),
    }
    return {**counts, "domains": domains, "urls": urls, "ips": ips,
            "onions": onions, "handles": handles, "emails": emails,
            "cves": cves, "counts": counts}


def assess_severity(text: str) -> dict[str, Any]:
    """Band + auditable reasons. Every reason quotes the keyword that fired."""
    t = (text or "").lower()
    reasons: list[dict[str, str]] = []
    band = "Low"
    for b, rules in SEVERITY_RULES:
        hits = [(label, kw) for (label, kw) in rules if kw in t]
        for label, kw in hits:
            reasons.append({"band": b, "label": label, "kw": kw})
        if band == "Low" and hits:
            band = b
    defensive_kw = next((d for d in _DEFENSIVE_CONTEXT if d in t), None)
    if defensive_kw and band in ("Critical", "High"):
        band = "Medium"
        reasons.append(
            {"band": "Low", "label": "defensive / educational framing caps urgency", "kw": defensive_kw}
        )
    return {"band": band, "score": _SEV_WEIGHT[band], "reasons": reasons}


def assess_themes(text: str) -> list[dict[str, Any]]:
    t = (text or "").lower()
    out: list[dict[str, Any]] = []
    for tid, label, kws in THEME_RULES:
        matched = [kw for kw in kws if kw in t]
        if matched:
            out.append({"id": tid, "label": label, "keywords": matched})
    if not out:
        out.append({"id": "other", "label": "Other", "keywords": []})
    return out


def _human_ago(ts_sec: float | None) -> str:
    if not ts_sec:
        return "unknown age"
    now = time.time()
    ago = max(0, int(now - ts_sec))
    if ago < 3600:
        return f"{max(1, ago // 60)}m ago"
    if ago < 86400:
        return f"{ago // 3600}h ago"
    return f"{ago // 86400}d ago"


def build_briefing(raw_text: str, source: str, ts_sec: float | None,
                   severity: dict[str, Any], themes: list[dict[str, Any]],
                   signals: dict[str, Any]) -> dict[str, Any]:
    """'Why it matters' — deterministic guidance bound to real signals."""
    text = (raw_text or "").strip()
    headline = text.split("\n", 1)[0].strip()
    if len(headline) > 160:
        headline = headline[:157].rstrip() + "…"

    reasons = severity.get("reasons", [])
    summary: list[str] = []
    if reasons:
        reason_bits = reasons[:4]
        for i, r in enumerate(reason_bits):
            plural = "mentions" if i == 0 else "also mentions"
            label = r["label"]
            summary.append(f'{plural} “{r["kw"]}” ({label})')
        if not summary:
            summary.append(f"text is classified {severity.get('band', 'Low')} by the monitoring rules")
    theme_labels = ", ".join(th["label"] for th in themes if th["id"] != "other")
    if theme_labels:
        summary.append(f"reads as: {theme_labels}.")
    if not summary:
        summary.append(
            "No explicit severity or theme keyword fired in this item — treat it as background "
            "corpus context rather than an active finding."
        )

    cnt = signals.get("counts", {})
    bits = []
    for key, label in (("cves", "CVE"), ("onions", ".onion"), ("ips", "IP"), ("domains", "domain"),
                       ("urls", "URL"), ("emails", "email"), ("handles", "handle")):
        v = cnt.get(key, 0)
        if v:
            bits.append(f"{v} {label}{'' if v == 1 else 's'}")
    if bits:
        summary.append(f"{len(bits)} signal type{'s' if len(bits) != 1 else ''} in the text: {', '.join(bits)}.")

    check_next: list[str] = []
    if cnt.get("cves"):
        check_next.append(
            "Check the referenced CVE(s) against CISA KEV and Alert Sheets, then search the IOC corpus "
            "for them before triaging."
        )
    if cnt.get("onions"):
        check_next.append(
            "Inspect the .onion service via the Tor proxy and note whether the Dark Web collector is "
            "already tracking it."
        )
    if cnt.get("domains") or cnt.get("urls"):
        check_next.append(
            "Cross-check the domain(s)/URL(s) against the URLhaus & OpenPhish feeds (Live Threat Feeds) "
            "and the IOC corpus."
        )
    if cnt.get("handles"):
        check_next.append(
            "Open the Telegram handle/channel in Telegram Monitoring to catch follow-on posts."
        )
    if any(th["id"] in ("carding", "credential") for th in themes):
        check_next.append(
            "Treat any listed credential / card material as potentially compromised: search the IOC "
            "corpus for the related accounts and domains."
        )
    if any(th["id"] == "ransomware" for th in themes):
        check_next.append(
            "Correlate any named victim/group against Alert Sheets and NVD CVEs; escalate matching "
            "organisations to triage."
        )
    if not check_next:
        check_next.append(
            "No high-signal IOC was extracted — treat as background monitoring context, revisit when "
            "the source posts a follow-up."
        )
    check_next.append(f"Seen on {source}, content age {_human_ago(ts_sec)}.")

    return {"headline": headline, "summary": summary, "check_next": check_next,
            "recency": _human_ago(ts_sec)}


def analyze(raw_text: str, source: str = "", ts_sec: float | None = None) -> dict[str, Any]:
    """Full per-item analysis: theme + severity + signals + briefing."""
    severity = assess_severity(raw_text)
    themes = assess_themes(raw_text)
    signals = extract_signals(raw_text)
    briefing = build_briefing(raw_text, source, ts_sec, severity, themes, signals)
    return {
        "severity": severity,
        "themes": themes,
        "signals": signals,
        "briefing": briefing,
    }