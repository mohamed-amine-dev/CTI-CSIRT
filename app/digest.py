# =============================================================================
# Daily email digest for the CSIRT team
# -----------------------------------------------------------------------------
# Additive feature, no refactor of existing modules:
#   * `digest_recipients` (ClickHouse) is the admin-managed mailing list — there
#     is NO public sign-up; rows are written only through the admin API
#     (/api/v1/digest) or tools/manage_digest_recipients.py.
#   * Each recipient has its own cadence: `daily` (window = 1 day) or
#     `every_2_days` (window = 2 days). A recipient is due when
#     `now - last_sent_at >= window`; `enabled = 0` recipients are skipped
#     entirely and never counted as due. `last_sent_at` is updated ONLY after a
#     successful send, so a transient SMTP failure is retried next cycle.
#   * Content is built from the SAME real ClickHouse rows the dashboard reads
#     (raw feed volume, Alert Sheet risk, malware-family observations, dark-web
#     themes, watchlist matches, actor attributions) — never fabricated. Empty
#     sections say so honestly.
#   * The short narrative reuses the platform's existing free LLM pipeline
#     (Ollama first, Gemini/Groq fallback). If no engine answers, a deterministic
#     summary built from the same numbers is used instead — the digest is always
#     sendable, and the text never claims facts outside the data.
#   * Delivery is plain SMTP (stdlib `smtplib`). Credentials come from config
#     (.env) only; with none configured the admin API refuses (503) instead of
#     guessing.
# =============================================================================

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import re
import smtplib
from email.message import EmailMessage
from typing import Any

from .config import Settings, settings as app_settings
from .db import insert_rows

logger = logging.getLogger(__name__)

#: Supported cadences → activity-window length in days.
FREQUENCIES: dict[str, int] = {"daily": 1, "every_2_days": 2}

_RECIPIENT_COLUMNS = [
    "email", "enabled", "frequency", "added_by", "created_at", "last_sent_at", "version",
]
_EPOCH = _dt.datetime(1970, 1, 1, 0, 0, 0)

_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Sections kept deliberately short — the digest is a summary, not a dump.
_MAX_CRITICAL_CVES = 10
_MAX_MALWARE_FAMILIES = 8
_MAX_DARKWEB_THEMES = 8
_MAX_WATCHLIST = 10
_MAX_ATTRIBUTIONS = 10


# ---------------------------------------------------------------------------
# Validation + recipient management
# ---------------------------------------------------------------------------
def valid_email(email: str) -> bool:
    return bool(_RE_EMAIL.match((email or "").strip()))


def valid_frequency(frequency: str) -> bool:
    return (frequency or "").strip().lower() in FREQUENCIES


def frequency_days(frequency: str) -> int:
    return FREQUENCIES.get((frequency or "").strip().lower(), 1)


def smtp_configured(settings: Settings = app_settings) -> bool:
    """True only when a host and a From/username are actually configured."""
    return bool(settings.smtp_host) and bool(settings.smtp_from or settings.smtp_username)


def _now(now: _dt.datetime | None = None) -> _dt.datetime:
    if now is not None:
        return now
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


async def list_recipients(db: Any, settings: Settings = app_settings) -> list[dict[str, Any]]:
    """Every configured recipient (newest first), with its computed due state."""
    dbn = settings.clickhouse_database
    try:
        rows = await db.query(
            f"""
            SELECT email, enabled, frequency, added_by, created_at, last_sent_at
            FROM {dbn}.digest_recipients FINAL
            ORDER BY created_at DESC, email
            """
        )
    except Exception as exc:  # noqa: BLE001 - table may not exist yet
        logger.warning("digest_recipients not queryable: %s", exc)
        return []

    now = _now()
    out: list[dict[str, Any]] = []
    for r in rows.result_rows:
        last = r[5] or _EPOCH
        window = frequency_days(str(r[2]))
        enabled = bool(r[1])
        due = enabled and (now - last) >= _dt.timedelta(days=window)
        out.append({
            "email": str(r[0]),
            "enabled": enabled,
            "frequency": str(r[2]),
            "added_by": str(r[3] or ""),
            "created_at": _iso(r[4]),
            "last_sent_at": _iso(last) if last > _EPOCH else None,
            "window_days": window,
            "due_now": due,
        })
    return out


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


async def _write_recipient(
    db: Any,
    settings: Settings,
    *,
    email: str,
    enabled: bool,
    frequency: str,
    added_by: str,
    created_at: _dt.datetime,
    last_sent_at: _dt.datetime,
    version: int,
) -> None:
    """Insert a full row. A ReplacingMergeTree re-insert by `email` collapses to
    the newest version, so every write must carry ALL columns (otherwise an
    update would reset created_at/last_sent_at to their DDL defaults)."""
    await insert_rows(
        db,
        "digest_recipients",
        [[email, 1 if enabled else 0, frequency, added_by, created_at, last_sent_at, version]],
        _RECIPIENT_COLUMNS,
    )


async def _get_recipient(db: Any, settings: Settings, email: str) -> dict[str, Any] | None:
    dbn = settings.clickhouse_database
    rows = await db.query(
        f"""
        SELECT email, enabled, frequency, added_by, created_at, last_sent_at
        FROM {dbn}.digest_recipients FINAL
        WHERE email = {{e:String}}
        """,
        parameters={"e": email},
    )
    if not rows.result_rows:
        return None
    r = rows.result_rows[0]
    return {
        "email": str(r[0]),
        "enabled": bool(r[1]),
        "frequency": str(r[2]),
        "added_by": str(r[3] or ""),
        "created_at": r[4] or _now(),
        "last_sent_at": r[5] or _EPOCH,
    }


async def upsert_recipient(
    db: Any,
    settings: Settings,
    email: str,
    *,
    frequency: str = "daily",
    enabled: bool = True,
    added_by: str = "",
) -> dict[str, Any]:
    """Add a recipient, or update an existing one's cadence / enabled flag.

    Additive: an update preserves the original `created_at` and `last_sent_at`,
    so changing cadence never re-sends or loses send history.
    """
    email = (email or "").strip().lower()
    if not valid_email(email):
        raise ValueError("invalid email address")
    frequency = (frequency or "daily").strip().lower()
    if not valid_frequency(frequency):
        raise ValueError("frequency must be one of " + ", ".join(FREQUENCIES))

    existing = await _get_recipient(db, settings, email)
    created_at = existing["created_at"] if existing else _now()
    last_sent_at = existing["last_sent_at"] if existing else _EPOCH
    added_by = added_by or (existing["added_by"] if existing else "")
    await _write_recipient(
        db, settings,
        email=email, enabled=enabled, frequency=frequency, added_by=added_by,
        created_at=created_at, last_sent_at=last_sent_at,
        version=int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1_000_000),
    )
    return {"email": email, "enabled": enabled, "frequency": frequency,
            "created": existing is None}


async def remove_recipient(db: Any, settings: Settings, email: str) -> bool:
    """Hard-remove a recipient (ClickHouse lightweight DELETE mutation)."""
    dbn = settings.clickhouse_database
    email = (email or "").strip().lower()
    existing = await _get_recipient(db, settings, email)
    if existing is None:
        return False
    await db.command(
        f"ALTER TABLE {dbn}.digest_recipients DELETE WHERE email = {{e:String}}",
        parameters={"e": email},
    )
    return True


async def due_recipients(db: Any, settings: Settings, now: _dt.datetime | None = None) -> list[dict[str, Any]]:
    """Recipients that should receive a digest right now (enabled only)."""
    now = _now(now)
    due: list[dict[str, Any]] = []
    for r in await list_recipients(db, settings):
        if not r["enabled"]:
            continue  # disabled: skipped entirely, never counted as due
        last = _parse(r["last_sent_at"]) if r["last_sent_at"] else _EPOCH
        if (now - last) >= _dt.timedelta(days=r["window_days"]):
            due.append(r)
    return due


def _parse(value: str) -> _dt.datetime:
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return _EPOCH


# ---------------------------------------------------------------------------
# Window aggregation — mirrors what the dashboard / Executive Report reads
# ---------------------------------------------------------------------------
async def collect_window(db: Any, settings: Settings, window_days: int) -> dict[str, Any]:
    """Real activity summary for the last `window_days`, straight from the
    same ClickHouse tables the dashboard uses."""
    dbn = settings.clickhouse_database
    now = _now()
    start = now - _dt.timedelta(days=window_days)
    p = {"wm": start}

    # 1. Ingested raw items by source -----------------------------------------
    rows = await db.query(
        f"""
        SELECT source, count() AS c
        FROM {dbn}.raw_threat_intel FINAL
        WHERE ts >= {{wm:DateTime}}
        GROUP BY source ORDER BY c DESC
        """,
        parameters=p,
    )
    by_source = [(str(r[0]), int(r[1])) for r in rows.result_rows]

    # 2. Alert Sheets by risk + new CRITICAL CVEs -----------------------------
    rows = await db.query(
        f"""
        SELECT JSONExtractString(risk_level, 'risk_level') AS rl, count() AS c
        FROM {dbn}.vulnerability_alerts FINAL
        WHERE ts >= {{wm:DateTime}}
        GROUP BY rl ORDER BY c DESC
        """,
        parameters=p,
    )
    alerts_by_risk = [(str(r[0] or "UNKNOWN"), int(r[1])) for r in rows.result_rows]

    rows = await db.query(
        f"""
        SELECT vuln_cve, threat_score
        FROM {dbn}.vulnerability_alerts FINAL
        WHERE ts >= {{wm:DateTime}}
          AND JSONExtractString(risk_level, 'risk_level') = 'CRITICAL'
        ORDER BY threat_score DESC, vuln_cve
        LIMIT {{lim:UInt32}}
        """,
        parameters={**p, "lim": _MAX_CRITICAL_CVES},
    )
    critical_cves = [(str(r[0]), float(r[1] or 0)) for r in rows.result_rows]

    # 3. Malware-family observations (processed_iocs linked to malware_tools) --
    rows = await db.query(
        f"""
        SELECT m.name, i.indicator
        FROM {dbn}.processed_iocs AS i FINAL
        LEFT JOIN (SELECT stix_id, name FROM {dbn}.malware_tools FINAL) AS m
               ON i.malware_id = m.stix_id
        WHERE i.ts >= {{wm:DateTime}} AND i.malware_id != ''
        ORDER BY m.name, i.ts DESC
        LIMIT 400
        """,
        parameters=p,
    )
    fam: dict[str, dict[str, Any]] = {}
    for r in rows.result_rows:
        name = str(r[0] or "(unknown family)")
        entry = fam.setdefault(name, {"name": name, "count": 0, "examples": []})
        entry["count"] += 1
        if len(entry["examples"]) < 3:
            entry["examples"].append(str(r[1]))
    malware_families = sorted(fam.values(), key=lambda e: (-e["count"], e["name"]))[:_MAX_MALWARE_FAMILIES]

    # 4. Dark web / Telegram items + themes -----------------------------------
    rows = await db.query(
        f"""
        SELECT source, url, raw_text, ts
        FROM {dbn}.raw_threat_intel FINAL
        WHERE source IN ('DARKWEB-ONION', 'TELEGRAM') AND ts >= {{wm:DateTime}}
        ORDER BY ts DESC LIMIT 500
        """,
        parameters=p,
    )
    dark_rows = rows.result_rows
    theme_counts: dict[str, int] = {}
    try:
        from .darkweb_analytics import assess_themes

        for r in dark_rows:
            for th in assess_themes(str(r[2] or "")):
                label = str(th.get("label") or th.get("id") or "").strip()
                if label and th.get("id") != "other":
                    theme_counts[label] = theme_counts.get(label, 0) + 1
    except Exception as exc:  # noqa: BLE001 - analytics must never break a digest
        logger.warning("theme assessment failed: %s", exc)
    darkweb_themes = sorted(theme_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_DARKWEB_THEMES]
    darkweb_recent = [
        {"source": str(r[0]), "url": str(r[1]), "ts": _iso(r[3])}
        for r in dark_rows[:5]
    ]

    # 5. Org-exposure watchlist matches ---------------------------------------
    rows = await db.query(
        f"""
        SELECT m.source, m.url, m.matched_term, t.target_type, t.value, t.label, m.created_at
        FROM {dbn}.watchlist_matches AS m FINAL
        LEFT JOIN (SELECT id, target_type, value, label FROM {dbn}.watchlist_targets FINAL) AS t
               ON m.target_id = t.id
        WHERE m.created_at >= {{wm:DateTime}}
        ORDER BY m.created_at DESC LIMIT {{lim:UInt32}}
        """,
        parameters={**p, "lim": _MAX_WATCHLIST},
    )
    watchlist_matches = [
        {
            "source": str(r[0]), "url": str(r[1]), "matched_term": str(r[2]),
            "target_type": str(r[3] or ""), "target_value": str(r[4] or ""),
            "target_label": str(r[5] or ""), "created_at": _iso(r[6]),
        }
        for r in rows.result_rows
    ]

    # 6. New threat-actor attributions ----------------------------------------
    rows = await db.query(
        f"""
        SELECT a.indicator, a.type, a.source, t.name, a.ts
        FROM {dbn}.ioc_actor_attribution AS a FINAL
        LEFT JOIN (SELECT stix_id, name FROM {dbn}.threat_actors FINAL) AS t
               ON a.threat_actor_id = t.stix_id
        WHERE a.ts >= {{wm:DateTime}} AND a.threat_actor_id != '' AND a.source != 'removed'
        ORDER BY a.ts DESC LIMIT {{lim:UInt32}}
        """,
        parameters={**p, "lim": _MAX_ATTRIBUTIONS},
    )
    actor_attributions = [
        {"indicator": str(r[0]), "type": str(r[1]), "source": str(r[2]),
         "actor": str(r[3] or ""), "ts": _iso(r[4])}
        for r in rows.result_rows
    ]

    ingested_total = sum(c for _, c in by_source)
    alerts_total = sum(c for _, c in alerts_by_risk)
    return {
        "window_days": window_days,
        "window_start": _iso(start),
        "window_end": _iso(now),
        "ingested_total": ingested_total,
        "by_source": by_source,
        "alerts_total": alerts_total,
        "alerts_by_risk": alerts_by_risk,
        "critical_cves": critical_cves,
        "malware_families": malware_families,
        "malware_total_iocs": sum(e["count"] for e in malware_families),
        "darkweb_total": len(dark_rows),
        "darkweb_themes": darkweb_themes,
        "darkweb_recent": darkweb_recent,
        "watchlist_matches": watchlist_matches,
        "actor_attributions": actor_attributions,
    }


# ---------------------------------------------------------------------------
# Narrative (reuses the existing free LLM pipeline; deterministic fallback)
# ---------------------------------------------------------------------------
def _deterministic_narrative(data: dict[str, Any]) -> str:
    """Always-available summary built only from the aggregated numbers."""
    parts: list[str] = []
    top_src = ", ".join(f"{s} ({c})" for s, c in data["by_source"][:5]) or "none"
    parts.append(
        f"{data['ingested_total']} raw intelligence items were ingested over the "
        f"last {data['window_days']} day(s) (top sources: {top_src})."
    )
    if data["alerts_total"]:
        risk_txt = ", ".join(f"{r}: {c}" for r, c in data["alerts_by_risk"][:5])
        parts.append(f"{data['alerts_total']} Alert Sheet(s) were produced ({risk_txt}).")
    else:
        parts.append("No new Alert Sheets were produced in this window.")
    if data["critical_cves"]:
        parts.append(
            "New CRITICAL CVEs: " + ", ".join(c for c, _ in data["critical_cves"][:5]) + "."
        )
    if data["malware_families"]:
        fams = ", ".join(f"{e['name']} ({e['count']})" for e in data["malware_families"][:5])
        parts.append(f"Malware families observed: {fams}.")
    if data["darkweb_total"]:
        themes = ", ".join(t for t, _ in data["darkweb_themes"][:5]) or "no dominant theme"
        parts.append(
            f"{data['darkweb_total']} dark-web/Telegram item(s) were collected (themes: {themes})."
        )
    if data["watchlist_matches"]:
        parts.append(
            f"{len(data['watchlist_matches'])} new watchlist match(es) require attention."
        )
    if data["actor_attributions"]:
        parts.append(
            f"{len(data['actor_attributions'])} new threat-actor attribution(s) were recorded."
        )
    return " ".join(parts)


async def build_narrative(data: dict[str, Any], settings: Settings = app_settings) -> tuple[str, str]:
    """Return `(narrative, engine)`. Engine is `deterministic` when no LLM
    answered — the text is then still grounded in the same real numbers."""
    fallback = _deterministic_narrative(data)
    try:
        from .ai_processor import _engine_candidates, _throttle_llm, get_llm
        from .assistant_busy import yield_to_assistant

        engines = await _engine_candidates(settings)
        summary = {
            "window_days": data["window_days"],
            "ingested_total": data["ingested_total"],
            "top_sources": data["by_source"][:8],
            "alerts_total": data["alerts_total"],
            "alerts_by_risk": data["alerts_by_risk"],
            "critical_cves": [c for c, _ in data["critical_cves"]],
            "malware_families": [(e["name"], e["count"]) for e in data["malware_families"]],
            "darkweb_total": data["darkweb_total"],
            "darkweb_themes": data["darkweb_themes"],
            "watchlist_matches": len(data["watchlist_matches"]),
            "actor_attributions": len(data["actor_attributions"]),
        }
        prompt = (
            "You are a senior CSIRT analyst writing the opening paragraph of a "
            "daily threat-intelligence digest for the team. Using ONLY the JSON "
            "statistics below, write 4-6 plain sentences in English. Do not "
            "invent CVEs, actors, vendors or numbers that are not present. Do not "
            "use markdown. If a section is empty, do not mention it.\n\n"
            f"Statistics:\n{summary}"
        )
        messages = [
            {"role": "system", "content": "You write concise, factual CSIRT briefings in English."},
            {"role": "user", "content": prompt},
        ]
        for engine in engines:
            try:
                await yield_to_assistant(settings.ai_engine_timeout_seconds)
                await _throttle_llm(settings)
                llm = get_llm(settings, engine)
                result = await asyncio.wait_for(
                    llm.ainvoke(messages), timeout=settings.ai_engine_timeout_seconds
                )
                content = getattr(result, "content", result)
                if isinstance(content, list):  # Gemini can return content parts
                    content = " ".join(
                        part.get("text", "") if isinstance(part, dict) else str(part)
                        for part in content
                    )
                text = str(content).strip()
                if text:
                    return text, engine
            except Exception as exc:  # noqa: BLE001 - try the next engine
                logger.warning("digest narrative engine=%s failed: %s", engine, exc)
    except Exception as exc:  # noqa: BLE001 - fall back to the deterministic text
        logger.warning("digest narrative unavailable (%s) — using deterministic summary", exc)
    return fallback, "deterministic"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_digest(data: dict[str, Any], narrative: str, engine: str) -> tuple[str, str]:
    """Return `(subject, body)` as plain UTF-8 text."""
    day = (data["window_end"] or "")[:10]
    subject = f"[Argus CTI] Threat digest — {day} (last {data['window_days']} day(s))"

    L: list[str] = []
    L.append("ARGUS CTI — DAILY THREAT INTELLIGENCE DIGEST")
    L.append("=" * 60)
    L.append(f"Window : {data['window_start']} → {data['window_end']} "
             f"({data['window_days']} day(s))")
    L.append(f"Brief  : {narrative}")
    L.append(f"        (narrative engine: {engine})")
    L.append("")

    L.append("1. INGESTION ACTIVITY")
    L.append("-" * 60)
    L.append(f"Raw items ingested: {data['ingested_total']}")
    if data["by_source"]:
        for src, cnt in data["by_source"][:15]:
            L.append(f"  • {src:<22} {cnt}")
    else:
        L.append("  None in this window.")
    L.append("")

    L.append("2. NEW ALERT SHEETS & CRITICAL CVEs")
    L.append("-" * 60)
    L.append(f"Alert Sheets produced: {data['alerts_total']}")
    if data["alerts_by_risk"]:
        L.append("  By risk: " + ", ".join(f"{r}={c}" for r, c in data["alerts_by_risk"]))
    if data["critical_cves"]:
        L.append("  New CRITICAL CVEs:")
        for cve, score in data["critical_cves"]:
            L.append(f"    • {cve} (threat_score {score:.0f})")
    else:
        L.append("  No new CRITICAL CVEs in this window.")
    L.append("")

    L.append("3. MALWARE / TOOL OBSERVATIONS")
    L.append("-" * 60)
    if data["malware_families"]:
        L.append(f"{data['malware_total_iocs']} indicator(s) linked to known families:")
        for e in data["malware_families"]:
            L.append(f"  • {e['name']} — {e['count']} indicator(s)")
            for ex in e["examples"]:
                L.append(f"      {ex}")
    else:
        L.append("  None in this window.")
    L.append("")

    L.append("4. DARK WEB / TELEGRAM")
    L.append("-" * 60)
    L.append(f"Items collected: {data['darkweb_total']}")
    if data["darkweb_themes"]:
        L.append("  Themes in window: " + ", ".join(f"{t} ({c})" for t, c in data["darkweb_themes"]))
    if data["darkweb_recent"]:
        L.append("  Most recent:")
        for it in data["darkweb_recent"]:
            L.append(f"    • [{it['source']}] {it['url']}")
    if not data["darkweb_total"]:
        L.append("  None in this window.")
    L.append("")

    L.append("5. EXPOSURE / WATCHLIST MATCHES")
    L.append("-" * 60)
    if data["watchlist_matches"]:
        for m in data["watchlist_matches"]:
            label = m["target_label"] or m["target_value"] or m["target_type"]
            L.append(f"  • [{m['source']}] {label} — matched '{m['matched_term']}'")
            L.append(f"      {m['url']}")
    else:
        L.append("  No new matches in this window.")
    L.append("")

    L.append("6. NEW THREAT-ACTOR ATTRIBUTIONS")
    L.append("-" * 60)
    if data["actor_attributions"]:
        for a in data["actor_attributions"]:
            L.append(f"  • {a['indicator']} ({a['type']}) → {a['actor'] or 'unnamed actor'}")
    else:
        L.append("  No new attributions in this window.")
    L.append("")
    L.append("=" * 60)
    L.append("Generated automatically by Argus CTI from live platform data.")
    return subject, "\n".join(L)


# ---------------------------------------------------------------------------
# Delivery (plain SMTP, stdlib only)
# ---------------------------------------------------------------------------
async def _send_email(settings: Settings, to: str, subject: str, body: str) -> None:
    if not smtp_configured(settings):
        raise RuntimeError(
            "SMTP is not configured — set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD "
            "and SMTP_FROM in .env before sending digests"
        )
    from_addr = settings.smtp_from or settings.smtp_username
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{settings.digest_from_name} <{from_addr}>"
    msg["To"] = to
    msg.set_content(body, charset="utf-8")

    def _deliver() -> None:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            if settings.smtp_starttls:
                smtp.starttls()
                smtp.ehlo()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(msg)

    await asyncio.to_thread(_deliver)


async def send_digest(
    db: Any,
    settings: Settings,
    email: str,
    window_days: int,
    *,
    advance_last_sent: bool = False,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Build + send one digest to `email`. On success (and only then) advance
    `last_sent_at` when `advance_last_sent` is set."""
    try:
        data = await collect_window(db, settings, window_days)
        narrative, engine = await build_narrative(data, settings)
        subject, body = render_digest(data, narrative, engine)
        await _send_email(settings, email, subject, body)
    except Exception as exc:  # noqa: BLE001 - report honestly, never crash a cycle
        logger.warning("digest send to %s failed: %s", email, exc)
        return {"email": email, "sent": False, "error": str(exc)}

    if advance_last_sent:
        recipient = await _get_recipient(db, settings, email)
        if recipient is not None:
            await _write_recipient(
                db, settings,
                email=recipient["email"], enabled=recipient["enabled"],
                frequency=recipient["frequency"], added_by=recipient["added_by"],
                created_at=recipient["created_at"], last_sent_at=_now(now),
                version=int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1_000_000),
            )
    return {"email": email, "sent": True, "engine": engine, "subject": subject,
            "ingested_total": data["ingested_total"]}


async def send_test_digest(
    db: Any, settings: Settings, email: str, window_days: int = 1
) -> dict[str, Any]:
    """Send an immediate digest to an arbitrary address WITHOUT touching the
    recipient list or cadence (used by the admin "send test" action)."""
    if not valid_email(email):
        return {"email": email, "sent": False, "error": "invalid email address"}
    return await send_digest(db, settings, email.strip().lower(), window_days,
                             advance_last_sent=False)


async def run_due_digests(
    db: Any, settings: Settings, now: _dt.datetime | None = None
) -> dict[str, Any]:
    """Evaluate every recipient and send to those whose cadence is due.

    Shared by the admin "run now" action and the scheduled job (which adds its
    own once-per-day watermark around this). Disabled recipients are skipped
    entirely and never appear in the result.
    """
    if not settings.digest_enabled:
        return {"status": "disabled", "due": 0, "sent": 0, "failed": 0, "results": []}

    due = await due_recipients(db, settings, now)
    results: list[dict[str, Any]] = []
    for r in due:
        results.append(await send_digest(
            db, settings, r["email"], r["window_days"], advance_last_sent=True, now=now,
        ))
    sent = sum(1 for x in results if x.get("sent"))
    return {
        "status": "ok",
        "due": len(due),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    }
