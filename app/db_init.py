# =============================================================================
# CTI Platform - ClickHouse database initialisation (one-shot bootstrap)
# -----------------------------------------------------------------------------
# Run once against a fresh ClickHouse instance:
#
#   docker compose up -d clickhouse        # start the DB
#   python -m app.db_init                  # create schema
#
# Design notes:
#   * Every table is a ReplacingMergeTree partitioned by month. The partition
#     key (toYYYYMM) enables cheap date-range pruning and trivial retention
#     (`ALTER TABLE ... DROP PARTITION`).
#   * ReplacingMergeTree gives us *idempotent upserts*: rows with the same
#     ORDER BY key are collapsed during background merges, keeping the row with
#     the highest `version`. This is exactly what implements the "do not insert
#     a duplicate; update the threat score instead" requirement:
#         - re-inserting the same CVE  -> threat_score is raised, one row stays
#         - re-inserting the same IOC  -> severity is refreshed, one row stays
#   * Queries that need the latest state use `SELECT ... FINAL` (the engine
#     applies the same dedup logic on read).
# =============================================================================

from __future__ import annotations

import logging
import time

import clickhouse_connect

from .db import get_admin_sync_client, get_sync_client
from .config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# `version` is a UInt64 microsecond epoch. Every re-insert of the same key gets
# a strictly larger version, so the latest observation always wins the merge.
_VERSION_SQL = "UInt64 DEFAULT 0"


# ---------------------------------------------------------------------------
# DDL definitions
# ---------------------------------------------------------------------------
DDL: dict[str, str] = {
    # -- 1. Raw intelligence -------------------------------------------------
    # One row per collected raw item (feed entry, bulletin, scrape). Keeps the
    # full original text so analysts can audit what the AI digested.
    "raw_threat_intel": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.raw_threat_intel
        (
            id          UUID DEFAULT generateUUIDv4(),
            source      LowCardinality(String),   -- CISA, CERT-FR, NVD, URLhaus...
            raw_text    String,                   -- original text / summary
            url         String,                   -- original item URL
            ts          DateTime DEFAULT now(),   -- ingestion time
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY (source, url)      -- dedup key: same source + url collapses
        SETTINGS index_granularity = 8192
    """,

    # -- 2. Processed indicators (IOCs) -------------------------------------
    # Normalised indicators extracted from raw intel (IP, hash, domain, CVE...).
    # The dedup key (type, indicator) means repeated sightings update the
    # severity instead of multiplying rows.
    "processed_iocs": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.processed_iocs
        (
            id          UUID DEFAULT generateUUIDv4(),
            indicator   String,                   -- "192.0.2.1", "ab12..." etc
            type        LowCardinality(String),   -- ipv4, ipv6, sha256, md5,
                                                  -- sha1, domain, cve, url, ja3
            severity    Float32 DEFAULT 1,        -- 0..10, raised on re-sighting
            ts          DateTime DEFAULT now(),
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY (type, indicator)
        SETTINGS index_granularity = 8192
    """,

    # -- 3. Vulnerability alerts (Fiche d'Alerte) -----------------------------
    # Mirrors the supervisor's exact 6-column requirement:
    #   vuln_cve, environmental_impact, risk_level, exploitation_status,
    #   remediation_solutions, ai_summary
    # PLUS a threat_score column (agreed with the supervisor) that the
    # ReplacingMergeTree upsert uses to express "seen again -> score += 1".
    # The structured fields (environmental_impact / remediation_solutions) are
    # stored as compact JSON strings produced by the Pydantic FicheAlerteModel.
    "vulnerability_alerts": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.vulnerability_alerts
        (
            id                      UUID DEFAULT generateUUIDv4(),
            vuln_cve                String,                   -- CVE-2024-1234
            environmental_impact    String,                   -- JSON (pt 1: is env affected?)
            -- risk_level stores the full RiskAssessment as JSON:
            -- {{"risk_level":"HIGH","exploit_paths":[...],"compromise_impact":"..."}}.
            -- Filter with jsonExtractString(risk_level,'risk_level') = 'HIGH'.
            risk_level              String,                   -- JSON (pt 2: severity+paths+impact)
            exploitation_status     String,                   -- JSON (pt 3: PoC availability)
            remediation_solutions   String,                   -- JSON (pt 4: patch/hardening/isolation/access)
            ai_summary              String,                   -- one-paragraph analyst summary
            threat_score            Float32 DEFAULT 1,        -- incremented on re-sighting
            ts                      DateTime DEFAULT now(),
            version                 {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY vuln_cve           -- dedup key: one row per CVE
        SETTINGS index_granularity = 8192
    """,

    # -- 4. Collector state (watermarks / last run) ----------------------------
    # Used for incremental sync (e.g. NVD lastModified date) and per-source
    # scheduling bookkeeping.
    "ingest_state": """
        CREATE TABLE IF NOT EXISTS {db}.ingest_state
        (
            source   LowCardinality(String),
            last_ts  DateTime,
            meta     String DEFAULT ''
        )
        ENGINE = ReplacingMergeTree()
        ORDER BY source
    """.format(db=settings.clickhouse_database),

    # -- 5. Fiche pipeline job queue -------------------------------------------
    # Durable status of the AI fiche generation for every CVE. This is the
    # source of truth for the "pending / processing / done / failed" states the
    # UI surfaces, and lets the scheduler retry failures after a restart.
    #   * enqueue  -> status=pending (before the CVE hits the in-memory queue)
    #   * worker   -> processing -> done | failed
    #   * failed   -> retried by the scheduler when retry_at <= now and
    #                 attempts < ai_max_attempts (then back to pending)
    "fiche_pending": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.fiche_pending
        (
            id          UUID DEFAULT generateUUIDv4(),
            cve         String,                   -- CVE-2024-1234
            status      LowCardinality(String),   -- pending|processing|done|failed
            source      LowCardinality(String),   -- feed family that found it
            raw_text    String,                   -- advisory text (needed to retry)
            attempts    UInt8 DEFAULT 0,          -- failed attempts so far
            last_error  String DEFAULT '',        -- most recent failure reason
            retry_at    DateTime DEFAULT now(),   -- earliest retry time
            updated_at  DateTime DEFAULT now(),
            version     UInt64
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(updated_at)
        ORDER BY cve                 -- one row per CVE, latest status wins
        SETTINGS index_granularity = 8192
    """,

    # -- 6. Real-time alerts (Phase 5) -----------------------------------------
    # Notification centre backing the top-bar bell. Rows are immutable once
    # written; the ReplacingMergeTree upsert is used only for the `read` flag
    # (re-insert the same id with read=1, newest version wins).
    "notifications": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.notifications
        (
            id          UUID DEFAULT generateUUIDv4(),
            category    LowCardinality(String),   -- NEW_FICHE|KEV|SYSTEM
            severity    LowCardinality(String),   -- CRITICAL|HIGH|MEDIUM|LOW|INFO
            title       String,                   -- one-line headline
            body        String,                   -- longer detail for the UI/Telegram
            cve         String DEFAULT '',        -- related CVE when applicable
            source      String DEFAULT '',        -- feed family (CISA-KEV, NVD, ...)
            read        UInt8 DEFAULT 0,          -- 0 = unread, 1 = read
            created_at  DateTime DEFAULT now(),
            version     UInt64
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(created_at)
        ORDER BY id
        SETTINGS index_granularity = 8192
    """,
}


def create_schema() -> None:
    """Create the database and every table. Idempotent (IF NOT EXISTS)."""
    # 1. Bootstrap: create the database using a no-default-DB connection.
    admin: clickhouse_connect.driver.Client = get_admin_sync_client()
    try:
        admin.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_database}")
    finally:
        admin.close()

    # 2. Create the tables using a client bound to the target database.
    client: clickhouse_connect.driver.Client = get_sync_client()
    try:
        for name, ddl in DDL.items():
            client.command(ddl)
            logger.info("created table %s.%s", settings.clickhouse_database, name)
    finally:
        client.close()


if __name__ == "__main__":
    logger.info("initialising schema on %s", settings.clickhouse_url)
    create_schema()
    logger.info("done. next: uvicorn app.main:app --reload")
