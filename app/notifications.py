# =============================================================================
# CTI Platform - real-time alerting service (Phase 5)
# -----------------------------------------------------------------------------
# Owns the `notifications` table + outbound Telegram push. The ingestion
# pipeline calls `notify()` when a new sheet meets the alert thresholds; the
# service persists the row for the in-app bell and (fire-and-forget) sends it
# to the configured Telegram channel. A failure to persist or send NEVER
# crashes the caller — alerting is best-effort by design.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from .config import Settings, settings as app_settings
from .db import insert_rows

logger = logging.getLogger(__name__)

RISK_ORDER: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

#: Feed families that are "known exploited" regardless of modelled risk.
KEV_SOURCES = ("CISA-KEV", "CISA-ADV")


def _utcnow():
    """Timezone-naive UTC datetime — the shape ClickHouse `DateTime` wants."""
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def risk_meets_threshold(risk: str, settings: Settings) -> bool:
    """True when a risk level is at least as urgent as `alert_min_risk`."""
    return RISK_ORDER.get(str(risk).upper(), 0) >= RISK_ORDER.get(settings.alert_min_risk.upper(), RISK_ORDER["HIGH"])


class NotificationService:
    """Persist + push alerts. Safe to call from any async context."""

    def __init__(self, db: Any, settings: Settings = app_settings) -> None:
        self.db = db
        self.settings = settings

    # -- write ---------------------------------------------------------------
    async def notify(
        self,
        *,
        category: str,
        severity: str,
        title: str,
        body: str,
        cve: str = "",
        source: str = "",
    ) -> dict[str, Any] | None:
        """Persist a notification and push it to Telegram (best-effort).

        Returns the serialised row when a notification was created, or None
        when alerting is disabled. Callers should never depend on the return.
        """
        if not self.settings.alerting_enabled:
            return None
        nid = uuid.uuid4()
        now = time.time()
        try:
            await insert_rows(
                self.db,
                "notifications",
                [[str(nid), category, severity.upper(), title, body, cve, source, 0, _utcnow(), int(now * 1_000_000)]],
                ["id", "category", "severity", "title", "body", "cve", "source", "read", "created_at", "version"],
            )
        except Exception as exc:  # noqa: BLE001 - alerting must never kill the pipeline
            logger.error("notification persist failed: %s", exc)
            return None

        if self.settings.alert_telegram:
            asyncio.create_task(self._telegram_push_async(category, severity, title, body, cve, source))
        logger.info("alert category=%s severity=%s cve=%s title=%r", category, severity, cve or "-", title)
        return {
            "id": str(nid), "category": category, "severity": severity.upper(),
            "title": title, "body": body, "cve": cve, "source": source, "read": 0,
        }

    # -- Telegram -------------------------------------------------------------
    def _telegram_text(self, category: str, severity: str, title: str, body: str, cve: str, source: str) -> str:
        lines = [
            f"<b>[{severity.upper()}] {category}</b>",
            f"{title}",
        ]
        if cve:
            lines.insert(1, f"<code>{cve}</code>")
        if source:
            lines.append(f"Source: {source}")
        if body:
            lines.append(body[:900])
        return "\n".join(lines)

    async def _telegram_push_async(self, category: str, severity: str, title: str, body: str, cve: str, source: str) -> None:
        try:
            ok = await self.telegram_send(self._telegram_text(category, severity, title, body, cve, source))
            if not ok:
                logger.warning("telegram alert push returned failure (category=%s cve=%s)", category, cve or "-")
        except Exception as exc:  # noqa: BLE001
            logger.error("telegram alert push failed: %s", exc)

    async def telegram_send(self, text: str) -> bool:
        """Send a message to the configured channel via the free Bot API."""
        token = self.settings.telegram_bot_token
        channel = self.settings.telegram_channel
        if not (token and channel):
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": channel, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        import aiohttp
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as sess:
                async with sess.post(url, json=payload) as resp:
                    return resp.status == 200
        except Exception as exc:  # noqa: BLE001
            logger.error("telegram request failed: %s", exc)
            return False

    # -- read ----------------------------------------------------------------
    async def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        unread_only: bool = False,
        severity: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        """Recent notifications, newest first. Never raises on a cold DB."""
        db = self.settings.clickhouse_database
        where: list[str] = []
        params: dict[str, Any] = {"lim": int(limit), "off": int(offset)}
        if unread_only:
            where.append("read = 0")
        if severity:
            where.append("severity = {sev:String}")
            params["sev"] = severity.upper()
        if category:
            where.append("category = {cat:String}")
            params["cat"] = category
        sql = f"SELECT id, category, severity, title, body, cve, source, read, created_at FROM {db}.notifications FINAL"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC, id DESC LIMIT {lim:UInt32} OFFSET {off:UInt32}"
        try:
            rows = await self.db.query(sql, parameters=params)
            items = []
            for r in rows.result_rows:
                items.append({
                    "id": r[0], "category": r[1], "severity": r[2], "title": r[3],
                    "body": r[4], "cve": r[5], "source": r[6], "read": int(r[7]),
                    "created_at": r[8].strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(r[8], "strftime") else str(r[8]),
                })
            return {"items": items, "total": len(items)}
        except Exception as exc:  # noqa: BLE001 - table may not exist yet
            logger.warning("notifications list failed: %s", exc)
            return {"items": [], "total": 0}

    async def unread_count(self) -> int:
        db = self.settings.clickhouse_database
        try:
            rows = await self.db.query(
                f"SELECT count() FROM {db}.notifications FINAL WHERE read = 0",
            )
            return int(rows.result_rows[0][0])
        except Exception:  # noqa: BLE001
            return 0

    async def mark_read(self, notif_id: str) -> bool:
        """Mark a single notification read (ReplacingMergeTree re-insert)."""
        db = self.settings.clickhouse_database
        try:
            rows = await self.db.query(
                f"SELECT category, severity, title, body, cve, source FROM {db}.notifications FINAL WHERE id = {{nid:String}}",
                parameters={"nid": notif_id},
            )
            if not rows.result_rows:
                return False
            r = rows.result_rows[0]
            await insert_rows(
                self.db, "notifications",
                [[notif_id, r[0], r[1], r[2], r[3], r[4], r[5], 1, _utcnow(), int(time.time() * 1_000_000)]],
                ["id", "category", "severity", "title", "body", "cve", "source", "read", "created_at", "version"],
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("mark_read failed for %s: %s", notif_id, exc)
            return False

    async def mark_all_read(self) -> int:
        db = self.settings.clickhouse_database
        try:
            rows = await self.db.query(
                f"SELECT id, category, severity, title, body, cve, source FROM {db}.notifications FINAL WHERE read = 0",
            )
            if not rows.result_rows:
                return 0
            now = int(time.time() * 1_000_000)
            await insert_rows(
                self.db, "notifications",
                [[r[0], r[1], r[2], r[3], r[4], r[5], r[6], 1, _utcnow(), now + i] for i, r in enumerate(rows.result_rows)],
                ["id", "category", "severity", "title", "body", "cve", "source", "read", "created_at", "version"],
            )
            return len(rows.result_rows)
        except Exception as exc:  # noqa: BLE001
            logger.error("mark_all_read failed: %s", exc)
            return 0
