# =============================================================================
# Actor-IOC attribution (Brief #4 Phase 3)
# -----------------------------------------------------------------------------
# Attribution is stored in its own `ioc_actor_attribution` table rather than by
# mutating `processed_iocs` rows: re-inserting an existing (type, indicator)
# with a fresh `ts` can cross a monthly partition and leave a duplicate that
# ReplacingMergeTree never collapses. A dedicated table keeps writes purely
# additive and every row carries provenance (source, attributed_by, ts).
#
# Sources:
#   * "otx"     - feed attribution: the OTX pulse `adversary` field names a
#                 group, resolved (exactly, name or alias) against the KB.
#   * "analyst" - operator-tagged attribution on a real IOC from the corpus.
#   * "removed" - tombstone: a newer row with threat_actor_id='' shadows a
#                 prior attribution so reads (threat_actor_id != '') drop it.
# Never guessed: an adversary string that matches no KB actor is skipped.
# =============================================================================

from __future__ import annotations

import logging
import re
import time as _time
from typing import Any

from .db import insert_rows

logger = logging.getLogger(__name__)

#: Insert column order for `ioc_actor_attribution`.
ATTRIBUTION_COLUMNS = [
    "indicator",
    "type",
    "threat_actor_id",
    "source",
    "attributed_by",
    "version",
]

SOURCE_OTX = "otx"
SOURCE_ANALYST = "analyst"
SOURCE_REMOVED = "removed"


def _norm(value: str) -> str:
    """Lowercase and collapse non-alphanumerics for tolerant name matching."""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


class ActorAttribution:
    """Resolves feed/operator actor names to knowledge-base stix_ids and
    upserts per-IOC attribution rows."""

    def __init__(self, db: Any, db_name: str) -> None:
        self._db = db
        self._db_name = db_name
        self._index: dict[str, str] = {}
        self._loaded_at = 0.0
        self.stats = {"index_entries": 0, "resolved": 0, "unmatched": 0, "written": 0}

    async def load_index(self) -> dict[str, str]:
        """Lazy-cached map of normalised actor name/alias -> stix_id.

        Built once per process and refreshed hourly, so feed attribution never
        pays an index query per record during a batch.
        """
        now = _time.monotonic()
        if self._index and (now - self._loaded_at) < 3600:
            return self._index
        index: dict[str, str] = {}
        try:
            rows = await self._db.query(
                f"SELECT stix_id, name, aliases FROM {self._db_name}.threat_actors FINAL"
            )
            for stix_id, name, aliases in rows.result_rows:
                seen: set[str] = set()
                for raw in [name, *(aliases or [])]:
                    key = _norm(raw)
                    if key and key not in seen:
                        seen.add(key)
                        index.setdefault(key, stix_id)
            self._index = index
            self._loaded_at = now
            self.stats["index_entries"] = len(index)
        except Exception as exc:  # noqa: BLE001 - attribution must not break ingestion
            logger.warning("actor index load failed: %s", exc)
        return self._index

    async def resolve(self, raw_name: str) -> str:
        """Map a raw adversary name to a KB stix_id ('' when unmatched)."""
        key = _norm(raw_name)
        if not key:
            return ""
        index = await self.load_index()
        actor_id = index.get(key, "")
        self.stats["resolved" if actor_id else "unmatched"] += 1
        return actor_id

    async def attribute(
        self,
        indicator: str,
        ioc_type: str,
        actor_id: str,
        source: str,
        attributed_by: str = "",
    ) -> None:
        """Upsert one attribution row (dedup key `(indicator, type)`).

        An empty `actor_id` is a removal tombstone: the newest version shadows
        any prior attribution and reads filter on `threat_actor_id != ''`.
        """
        version = int(_time.time() * 1_000_000)
        await insert_rows(
            self._db,
            "ioc_actor_attribution",
            [[indicator, ioc_type, actor_id, source, attributed_by, version]],
            ATTRIBUTION_COLUMNS,
        )
        self.stats["written"] += 1