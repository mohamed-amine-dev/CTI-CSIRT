# =============================================================================
# CTI Platform - IP geolocation enricher (Threat-origin choropleth)
# -----------------------------------------------------------------------------
# Background task that resolves every unseen IP from processed_iocs to a
# country (+lat/lon) through a FREE, no-key HTTPS provider (ipwho.is, 10k
# requests/month) and caches the result in `ip_geo_cache`.
#
# Guarantees:
#   * every IP is looked up at most once ever (cache dedup key = ip) — the free
#     quota is only ever spent on genuinely new addresses;
#   * failures (private/reserved/unresolvable) are negative-cached so they are
#     never re-queried;
#   * a monthly budget guard stops the task before the free tier is exhausted;
#   * exponential backoff on transport errors — a flaky network never crashes
#     the loop and never wastes quota on a provider that is down.
# =============================================================================

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from typing import Any

import aiohttp

from .db import insert_rows

logger = logging.getLogger(__name__)

_GEO_FIELDS = ["ip", "country_code", "country_name", "lat", "lon", "status", "ts", "version"]


def is_lookupable(ip: str) -> bool:
    """True only for global (public) addresses we should spend quota on.

    RFC1918, loopback, link-local, multicast, reserved and unspecified ranges
    (cloud-metadata 169.254.169.254 included) never hit the provider — they are
    negative-cached locally so the free quota is saved for real attacker hosts.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


class GeoEnricher:
    """Background geolocation enricher wired into the ingestion pipeline."""

    def __init__(
        self,
        db,
        settings,
        session: aiohttp.ClientSession,
        poll_interval: int | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.session = session
        self._poll_interval = poll_interval or settings.geo_poll_interval
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.last_run: dict[str, Any] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="geo-enricher")
        logger.info(
            "geo-enricher started (provider=%s, max/cycle=%d, budget/mo=%d)",
            self.settings.geo_provider_url,
            self.settings.geo_max_per_cycle,
            self.settings.geo_monthly_budget,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _run(self) -> None:
        try:
            await asyncio.sleep(self.settings.geo_first_delay)
            while not self._stop.is_set():
                try:
                    await self.geolocate_pending()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.exception("geo-enricher cycle failed: %s", exc)
                for _ in range(self._poll_interval):
                    if self._stop.is_set():
                        return
                    await asyncio.sleep(1)
        finally:
            logger.info("geo-enricher stopped")

    async def _used_this_month(self) -> int:
        rows = await self.db.query(
            """
            SELECT count()
            FROM {db:Identifier}.ip_geo_cache FINAL
            WHERE toYYYYMM(ts) = toYYYYMM(now())
            """,
            parameters={"db": self.settings.clickhouse_database},
        )
        return int(rows.result_rows[0][0]) if rows.result_rows else 0

    async def geolocate_pending(self) -> dict[str, Any]:
        """One full cycle: look up every unseen global IP up to the caps."""
        dbname = self.settings.clickhouse_database
        used = await self._used_this_month()
        budget_left = self.settings.geo_monthly_budget - used
        if budget_left <= 0:
            logger.warning("geo-enricher: monthly budget exhausted (%d/%d) — pausing",
                           used, self.settings.geo_monthly_budget)
            self.last_run = {"status": "budget_exhausted", "cached": used,
                             "budget": self.settings.geo_monthly_budget}
            return self.last_run

        rows = await self.db.query(
            f"""
            SELECT indicator AS ip
            FROM {dbname}.processed_iocs FINAL
            WHERE type IN ('ipv4', 'ipv6')
              AND indicator NOT IN (SELECT ip FROM {dbname}.ip_geo_cache FINAL)
            GROUP BY indicator
            LIMIT 5000
            """
        )
        candidates = [r[0] for r in rows.result_rows]
        global_ips = [ip for ip in candidates if is_lookupable(ip)]

        # The run cap guards against a multi-hour cycle on a cold database and
        # lets the monthly budget breathe: per-IP caching means we never re-pay.
        quota = min(budget_left, self.settings.geo_max_per_cycle, len(global_ips))
        if quota <= 0:
            self.last_run = {"status": "up_to_date", "cached": used,
                             "pending": len(global_ips)}
            return self.last_run

        target = global_ips[:quota]
        start = time.monotonic()
        ok = fail = 0
        rows_to_insert: list[list[Any]] = []
        backoff = 1.0
        consecutive_errors = 0

        for i, ip in enumerate(target):
            if self._stop.is_set():
                break
            try:
                async with self.session.get(
                    f"{self.settings.geo_provider_url}/{ip}",
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    data = json.loads(await resp.text())
                consecutive_errors = 0
                backoff = 1.0
                if data.get("success"):
                    ok += 1
                    rows_to_insert.append([
                        ip,
                        (data.get("country_code") or "").upper(),
                        data.get("country") or "",   # ipwho.is field is "country"
                        float(data.get("latitude") or 0),
                        float(data.get("longitude") or 0),
                        "ok",
                        int(time.time()),
                        int(time.time()),
                    ])
                else:
                    fail += 1
                    rows_to_insert.append([ip, "", "", 0.0, 0.0, "fail",
                                           int(time.time()), int(time.time())])
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                consecutive_errors += 1
                fail += 1
                # Negative-cache transport failures too: the address is saved
                # as fail so a flaky moment does not burn quota on retries.
                rows_to_insert.append([ip, "", "", 0.0, 0.0, "fail",
                                       int(time.time()), int(time.time())])
                logger.warning("geo lookup failed for %s (%s) — retry %d backoff %.0fs",
                               ip, exc, consecutive_errors, backoff)
                if consecutive_errors >= 5:
                    logger.error("geo-enricher: %d consecutive failures — aborting cycle",
                                 consecutive_errors)
                    break
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            # Polite pacing between lookups (free-tier courtesy).
            if i < len(target) - 1:
                await asyncio.sleep(self.settings.geo_request_interval)

        if rows_to_insert:
            await insert_rows(self.db, "ip_geo_cache", rows_to_insert, _GEO_FIELDS)

        duration = time.monotonic() - start
        self.last_run = {
            "status": "ok",
            "looked_up": len(rows_to_insert),
            "ok": ok,
            "fail": fail,
            "duration_s": round(duration, 1),
            "cached_total": used + len(rows_to_insert),
            "budget": self.settings.geo_monthly_budget,
            "pending": max(0, len(global_ips) - len(rows_to_insert)),
        }
        logger.info(
            "event=geo_run status=ok looked_up=%d ok=%d fail=%d duration=%.1fs cached_total=%d pending=%d",
            len(rows_to_insert), ok, fail, duration,
            self.last_run["cached_total"], self.last_run["pending"],
        )
        return self.last_run

    async def status(self) -> dict[str, Any]:
        """Summary for the /api/v1/geo/status endpoint (UI footer)."""
        used = await self._used_this_month()
        total = await self.db.query(
            """
            SELECT
                count(),
                sumIf(1, status = 'ok'),
                sumIf(1, status = 'fail'),
                uniqExact(country_code)
            FROM {db:Identifier}.ip_geo_cache FINAL
            """,
            parameters={"db": self.settings.clickhouse_database},
        )
        r = total.result_rows[0] if total.result_rows else (0, 0, 0, 0)
        return {
            "cached": int(r[0]),
            "ok": int(r[1]),
            "fail": int(r[2]),
            "countries": int(r[3]),
            "monthly_used": used,
            "monthly_budget": self.settings.geo_monthly_budget,
            "provider": self.settings.geo_provider_url,
            "last_run": self.last_run,
        }
