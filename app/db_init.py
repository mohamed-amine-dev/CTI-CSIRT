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

#: Content tables that gain a nullable `tlp` column (Phase 4). '' == unset,
#: which readers treat as CLEAR.
TLP_CONTENT_TABLES = (
    "threat_actors",
    "malware_tools",
    "attack_patterns",
    "processed_iocs",
    "raw_threat_intel",
    "vulnerability_alerts",
    "agent_triage_results",
)


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
            id              UUID DEFAULT generateUUIDv4(),
            source          LowCardinality(String),   -- CISA, CERT-FR, NVD, URLhaus...
            raw_text        String,                   -- original text / summary
            url             String,                   -- original item URL
            threat_category LowCardinality(String) DEFAULT 'Other',
                                                      -- Threat Landscape bucket
                                                      -- (classify_threat, app/threat_classify.py)
            tlp         String DEFAULT '',          -- Phase 4: TLP marking ('' = CLEAR)
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
            malware_id  String DEFAULT '',        -- nullable link to malware_tools.stix_id
                                                  -- (abuse.ch ThreatFox family match)
            tlp         String DEFAULT '',        -- Phase 4: TLP marking ('' = CLEAR)
            ts          DateTime DEFAULT now(),
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY (type, indicator)
        SETTINGS index_granularity = 8192
    """,

    # -- 3. Vulnerability alerts (Alert Sheet) -----------------------------
    # Mirrors the supervisor's exact 6-column requirement:
    #   vuln_cve, environmental_impact, risk_level, exploitation_status,
    #   remediation_solutions, ai_summary
    # PLUS a threat_score column (agreed with the supervisor) that the
    # ReplacingMergeTree upsert uses to express "seen again -> score += 1".
    # The structured fields (environmental_impact / remediation_solutions) are
    # stored as compact JSON strings produced by the Pydantic AlertSheetModel.
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
            tlp                         String DEFAULT '',        -- Phase 4: TLP marking ('' = CLEAR)
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

    # -- 5. Sheet pipeline job queue -------------------------------------------
    # Durable status of the AI sheet generation for every CVE. This is the
    # source of truth for the "pending / processing / done / failed" states the
    # UI surfaces, and lets the scheduler retry failures after a restart.
    #   * enqueue  -> status=pending (before the CVE hits the in-memory queue)
    #   * worker   -> processing -> done | failed
    #   * failed   -> retried by the scheduler when retry_at <= now and
    #                 attempts < ai_max_attempts (then back to pending)
    "alert_sheet_pending": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.alert_sheet_pending
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
            category    LowCardinality(String),   -- NEW_SHEET|KEV|SYSTEM
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

    # -- 7. IP geolocation cache (Threat-origin choropleth) ---------------------
    # One row per geolocated IP (dedup key `ip`), so a free provider's quota is
    # only ever spent once per address. `status='fail'` rows cache private /
    # reserved / unresolvable addresses so they are never re-queried. Feeds the
    # /api/v1/geo/summary choropleth and the country filter on /api/v1/iocs.
    "ip_geo_cache": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.ip_geo_cache
        (
            ip           String,                        -- IPv4 or IPv6 (dedup key)
            country_code LowCardinality(String) DEFAULT '',
            country_name String DEFAULT '',
            lat          Float64 DEFAULT 0,             -- 0 = unknown / failed
            lon          Float64 DEFAULT 0,
            status       LowCardinality(String) DEFAULT 'ok',  -- ok | fail
            ts           DateTime DEFAULT now(),        -- when it was geolocated
            version      UInt64 DEFAULT 0
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY ip
        SETTINGS index_granularity = 8192
    """,

    # -- 8. Agent triage audit trail --------------------------------------------
    # Append-only observability record for every autonomous triage run
    # (app/agent/graph.py -> _persist_triage). Stores the final risk score,
    # whether the sensor flagged the input as unsafe, the generated Sheet (JSON)
    # and the full execution_trace so an analyst can replay the agent's decisions.
    "agent_triage_results": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.agent_triage_results
        (
            id               UUID DEFAULT generateUUIDv4(),
            indicator        String,                   -- Ip / domain / hash / CVE
            indicator_type   LowCardinality(String),   -- ipv4|domain|hash|cve
            risk_score       UInt8 DEFAULT 0,          -- 0-100 final score
            is_flagged_unsafe UInt8 DEFAULT 0,         -- sensor flagged the input
            sheet_json       String DEFAULT '',        -- generated Alert Sheet (JSON)
            execution_trace  String DEFAULT '',        -- full node-by-node trace (JSON)
            tlp          String DEFAULT '',            -- Phase 4: TLP marking ('' = CLEAR)
            created_at       DateTime DEFAULT now(),
            version          {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(created_at)
        ORDER BY id
        SETTINGS index_granularity = 8192
    """,

    # -- 9. Threat Actors (ATT&CK Intrusion Sets) -------------------------------
    "threat_actors": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.threat_actors
        (
            id          UUID DEFAULT generateUUIDv4(),
            stix_id     String,                   -- intrusion-set--...
            name        String,
            description String,
            aliases     Array(String),
            first_seen  DateTime DEFAULT toDateTime('1970-01-01 00:00:00'),
            last_seen   DateTime DEFAULT toDateTime('1970-01-01 00:00:00'),
            url         String,
            -- Brief #4 (Phase 1): structured profile derived deterministically
            -- from the MITRE ATT&CK intrusion-set description. Never invented;
            -- empty/unknown when the source text does not state it.
            motivation            LowCardinality(String) DEFAULT 'unknown',
            attribution           String DEFAULT '',      -- originating country
            target_sectors        Array(String) DEFAULT [],
            target_countries      Array(String) DEFAULT [],
            tlp         String DEFAULT '',       -- Phase 4: TLP marking ('' = CLEAR)
            ts          DateTime DEFAULT now(),
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY stix_id
        SETTINGS index_granularity = 8192
    """,

    # -- 10. Malware & Tools (ATT&CK Malware/Tool) ------------------------------
    "malware_tools": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.malware_tools
        (
            id          UUID DEFAULT generateUUIDv4(),
            stix_id     String,                   -- malware--... or tool--...
            name        String,
            type        LowCardinality(String),   -- malware | tool
            description String,
            aliases     Array(String),
            url         String,
            category    LowCardinality(String) DEFAULT 'Other',
                                                  -- reuses threat_classify's 11-class
                                                  -- malware taxonomy (deterministic)
            tlp         String DEFAULT '',     -- Phase 4: TLP marking ('' = CLEAR)
            ts          DateTime DEFAULT now(),
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY stix_id
        SETTINGS index_granularity = 8192
    """,

    # -- 11. Attack Patterns (ATT&CK TTPs) --------------------------------------
    "attack_patterns": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.attack_patterns
        (
            id          UUID DEFAULT generateUUIDv4(),
            stix_id     String,                   -- attack-pattern--...
            x_mitre_id  String,                   -- T1548
            tactic      LowCardinality(String) DEFAULT 'unknown',
                                                  -- kill-chain phase (display label)
            name        String,
            description String,
            url         String,
            tlp         String DEFAULT '',     -- Phase 4: TLP marking ('' = CLEAR)
            ts          DateTime DEFAULT now(),
            version     {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY stix_id
        SETTINGS index_granularity = 8192
    """,

    # -- 12. STIX Relationships -------------------------------------------------
    "stix_relationships": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.stix_relationships
        (
            id                UUID DEFAULT generateUUIDv4(),
            stix_id           String,
            source_ref        String,
            target_ref        String,
            relationship_type LowCardinality(String),
            ts                DateTime DEFAULT now(),
            version           {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY (source_ref, target_ref, relationship_type)
        SETTINGS index_granularity = 8192
    """,

    # -- 13. Actor-IOC attribution (Brief #4 Phase 3) ---------------------------
    # One row per attributed (type, indicator) pair. Kept separate from
    # `processed_iocs` so late attribution is a purely additive write that can
    # never duplicate an existing IOC across monthly partitions. `source`
    # names the provenance (otx | analyst | removed); a `removed` tombstone
    # carries threat_actor_id='' and shadows prior rows at read time.
    "ioc_actor_attribution": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.ioc_actor_attribution
        (
            id               UUID DEFAULT generateUUIDv4(),
            indicator        String,                   -- same value as processed_iocs
            type             LowCardinality(String),   -- ipv4, domain, sha256, cve...
            threat_actor_id  String DEFAULT '',
            source           LowCardinality(String) DEFAULT 'otx',
            attributed_by    String DEFAULT '',        -- '' = feed; operator label
            ts               DateTime DEFAULT now(),
            version          {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY (indicator, type)
        SETTINGS index_granularity = 8192
    """,

    # -- 14. Users (Phase 4: RBAC + TLP clearance) ------------------------------
    # One row per login (dedup key `username`). Passwords are argon2id hashes,
    # never plaintext. `workspace_tags` may hold one or more of TI/CERT/DFIR;
    # `tlp_clearance` is the highest TLP tier this user may read
    # (CLEAR < GREEN < AMBER < AMBER+STRICT < RED). `is_disabled` is a soft
    # delete (ReplacingMergeTree cannot erase a row cleanly).
    "users": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.users
        (
            id              UUID DEFAULT generateUUIDv4(),
            username        String,
            password_hash   String,                   -- argon2id hash (never plaintext)
            totp_secret     String DEFAULT '',        -- base32 secret when 2FA set up
            totp_enabled    UInt8 DEFAULT 0,
            workspace_tags  Array(String) DEFAULT [],
            tlp_clearance   LowCardinality(String) DEFAULT 'CLEAR',
            is_admin        UInt8 DEFAULT 0,
            is_disabled     UInt8 DEFAULT 0,
            ts              DateTime DEFAULT now(),
            version         {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY username
        SETTINGS index_granularity = 8192
    """,

    # -- 15. Audit log (Phase 4: append-only observability) --------------------
    # Who did what, when. Every row has a fresh UUID as its ORDER BY key, so
    # ReplacingMergeTree never collapses anything — append-only by construction.
    # `event` ∈ login | login_failed | 2fa_* | view.* | export.* | modify.*
    "audit_log": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.audit_log
        (
            id       UUID DEFAULT generateUUIDv4(),
            event    LowCardinality(String),
            username String DEFAULT 'anonymous',
            resource String DEFAULT '',
            detail   String DEFAULT '',
            ts       DateTime DEFAULT now(),
            version  UInt64 DEFAULT 0
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(ts)
        ORDER BY id
        SETTINGS index_granularity = 8192
    """,

    # -- 16. Watchlist targets (Org Exposure monitoring) ------------------------
    # Persisted search targets registered by an analyst: type (domain / phone /
    # email / org) + value + optional label. Every ingestion loop re-checks new
    # dark-web/telegram rows against active targets and records real matches in
    # `watchlist_matches`. Soft delete = re-insert the same id with active=0 and
    # a newer version (ReplacingMergeTree collapses to the latest state).
    "watchlist_targets": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.watchlist_targets
        (
            id          UUID DEFAULT generateUUIDv4(),
            target_type LowCardinality(String),   -- domain | phone | email | org
            value       String,                   -- the raw search value as typed
            label       String DEFAULT '',        -- analyst label, e.g. "Our primary domain"
            active      UInt8 DEFAULT 1,          -- 1 active, 0 soft-deleted
            created_at  DateTime DEFAULT now(),
            version     UInt64 DEFAULT 0
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(created_at)
        ORDER BY id
        SETTINGS index_granularity = 8192
    """,

    # -- 17. Watchlist matches (Org Exposure monitoring) ------------------------
    # One row per real (target, item) match, dedup keyed so a re-sweep of the
    # same item never re-flags or re-notifies. `snippet` keeps a short context
    # window around the matched term for the UI / notification.
    "watchlist_matches": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.watchlist_matches
        (
            id           UUID DEFAULT generateUUIDv4(),
            target_id    UUID,
            source       LowCardinality(String),  -- DARKWEB-ONION | TELEGRAM
            url          String,
            matched_term String,                  -- actual term found in the content
            snippet      String DEFAULT '',
            created_at   DateTime DEFAULT now(),
            version      UInt64
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(created_at)
        ORDER BY (target_id, source, url)
        SETTINGS index_granularity = 8192
    """,

    # -- 18. Daily email digest recipients --------------------------------------
    # Admin-managed mailing list for the scheduled CSIRT digest. There is NO
    # public sign-up: rows are only ever written through the admin API
    # (/api/v1/digest, privileged ops-token / admin user) or the
    # tools/manage_digest_recipients.py CLI. Dedup key `email` means a cadence
    # or enable/disable change is a re-insert with a higher version; the
    # scheduler skips `enabled=0` rows entirely.
    "digest_recipients": f"""
        CREATE TABLE IF NOT EXISTS {settings.clickhouse_database}.digest_recipients
        (
            id           UUID DEFAULT generateUUIDv4(),
            email        String,                   -- recipient mailbox
            enabled      UInt8 DEFAULT 1,          -- 0 = fully stopped
            frequency    LowCardinality(String) DEFAULT 'daily',
                                                   -- daily | every_2_days
            added_by     String DEFAULT '',        -- ops-token / admin username
            created_at   DateTime DEFAULT now(),
            last_sent_at DateTime DEFAULT toDateTime('1970-01-01 00:00:00'),
                                                   -- updated ONLY after a
                                                   -- successful send
            version      {_VERSION_SQL}
        )
        ENGINE = ReplacingMergeTree(version)
        PARTITION BY toYYYYMM(created_at)
        ORDER BY email
        SETTINGS index_granularity = 8192
    """,
}


async def migrate_async(client: Any) -> None:
    """Idempotent Phase-4 TLP columns over an *async* live clickhouse_connect
    client (the one `main.py`'s lifespan holds).

    `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` is safe on every bootstrap:
    fresh installs get `tlp` from the CREATE TABLE DDL, pre-existing installs
    (whose tables predate Phase 4) get it right here. `ADD COLUMN IF NOT
    EXISTS` also mirrors the sync `_migrate()` below.
    """
    db = settings.clickhouse_database
    for tbl in TLP_CONTENT_TABLES:
        await client.command(
            f"ALTER TABLE {db}.{tbl} ADD COLUMN IF NOT EXISTS "
            "tlp String DEFAULT ''"
        )
    # Brief #5 (Malware & Tools): additive malware catalog columns.
    await client.command(
        f"ALTER TABLE {db}.malware_tools ADD COLUMN IF NOT EXISTS "
        "category LowCardinality(String) DEFAULT 'Other'"
    )
    await client.command(
        f"ALTER TABLE {db}.processed_iocs ADD COLUMN IF NOT EXISTS "
        "malware_id String DEFAULT ''"
    )


def _migrate(client: clickhouse_connect.driver.Client) -> None:
    """`ADD COLUMN IF NOT EXISTS` makes this safe to run on both fresh and
    existing databases on every bootstrap run.
    """
    db = settings.clickhouse_database
    client.command(
        f"ALTER TABLE {db}.raw_threat_intel ADD COLUMN IF NOT EXISTS "
        "threat_category LowCardinality(String) DEFAULT 'Other'"
    )
    client.command(
        f"ALTER TABLE {db}.processed_iocs ADD COLUMN IF NOT EXISTS "
        "threat_actor_id String DEFAULT ''"
    )
    client.command(
        f"ALTER TABLE {db}.attack_patterns ADD COLUMN IF NOT EXISTS "
        "tactic LowCardinality(String) DEFAULT 'unknown'"
    )
    # Brief #4 (Phase 1): additive threat-actor profile + IOC attribution link.
    client.command(
        f"ALTER TABLE {db}.threat_actors ADD COLUMN IF NOT EXISTS "
        "motivation LowCardinality(String) DEFAULT 'unknown'"
    )
    client.command(
        f"ALTER TABLE {db}.threat_actors ADD COLUMN IF NOT EXISTS "
        "attribution String DEFAULT ''"
    )
    client.command(
        f"ALTER TABLE {db}.threat_actors ADD COLUMN IF NOT EXISTS "
        "target_sectors Array(String) DEFAULT []"
    )
    client.command(
        f"ALTER TABLE {db}.threat_actors ADD COLUMN IF NOT EXISTS "
        "target_countries Array(String) DEFAULT []"
    )
    client.command(
        f"ALTER TABLE {db}.vulnerability_alerts ADD COLUMN IF NOT EXISTS "
        "threat_actor_id String DEFAULT ''"
    )
    # Phase 4: nullable TLP marking on every content table ('' == unset → CLEAR).
    for tbl in TLP_CONTENT_TABLES:
        client.command(f"ALTER TABLE {db}.{tbl} ADD COLUMN IF NOT EXISTS tlp String DEFAULT ''")
    # Brief #5 (Malware & Tools): additive malware catalog columns.
    client.command(
        f"ALTER TABLE {db}.malware_tools ADD COLUMN IF NOT EXISTS "
        "category LowCardinality(String) DEFAULT 'Other'"
    )
    client.command(
        f"ALTER TABLE {db}.processed_iocs ADD COLUMN IF NOT EXISTS "
        "malware_id String DEFAULT ''"
    )


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
        _migrate(client)
        logger.info("schema migrations applied")
    finally:
        client.close()


if __name__ == "__main__":
    logger.info("initialising schema on %s", settings.clickhouse_url)
    create_schema()
    logger.info("done. next: uvicorn app.main:app --reload")
