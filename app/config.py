# =============================================================================
# CTI Platform - configuration module
# -----------------------------------------------------------------------------
# Centralised settings. Every value can be overridden through a `.env` file
# (loaded via pydantic-settings) or real environment variables. All defaults
# point to free / open-source / local endpoints so the platform runs at $0.
# =============================================================================

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings, loaded from environment / `.env`.

    pydantic-settings performs validation and coercion, so a mistyped env var
    (e.g. CLICKHOUSE_PORT="abc") fails fast at startup instead of blowing up
    mid-ingestion.
    """

    # --- Pydantic-settings plumbing ---------------------------------------
    # env_file=".env" -> read local overrides; extra env vars are tolerated so
    # the process never crashes because a variable is unknown.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- ClickHouse --------------------------------------------------------
    clickhouse_host: str = "127.0.0.1"
    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    clickhouse_database: str = "cti"
    clickhouse_secure: bool = False  # HTTPS against ClickHouse, not local dev
    # Dedicated read-only account backing the Data Explorer (/explore). The
    # `cti_ro` user is created via clickhouse/users.d/ro.xml (mounted into the
    # container) with readonly=1, so the explore router can never write, ALTER
    # or DROP data — even if an ad-hoc query is let loose on the query box.
    clickhouse_readonly_user: str = "cti_ro"
    clickhouse_readonly_password: str = ""

    # --- AI Engine -----------------------------------------------------------
    # Provider resolution (LLM_PROVIDER=auto): Groq (free key) -> Gemini (free
    # key) -> Ollama (local). Set LLM_PROVIDER to force one of them.
    llm_provider: str = "auto"        # auto | groq | gemini | ollama

    # Groq free-tier first ...
    groq_api_key: str = ""            # free key: https://console.groq.com/keys
    groq_model: str = "llama-3.3-70b-versatile"

    # ... or Google Gemini (free tier via Google AI Studio):
    # https://aistudio.google.com/apikey  (they already have one of these)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

    # ... local Ollama fallback (used automatically when no cloud key exists).
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"

    # --- Dark Web / Tor ------------------------------------------------------
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    darkweb_enabled: bool = False
    # Onion search bases queried through Tor. The default is DuckDuckGo's public
    # onion search index: a stable, clean, non-offensive .onion that validates
    # the pipeline end-to-end. Analysts can point this list at their own
    # search-endpoint onions (an onion URL without a search path is treated as a
    # base and probed with "/lite/?q=<query>").
    darkweb_onion_urls: list[str] = [
        "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    ]
    # Threat-focused search queries run against each onion base. Scraping the
    # DDG homepage alone only yields boilerplate, so each query's result links +
    # snippets are parsed into individual intel items instead (dedup key
    # (source, url) collapses repeats between polls). Empty list falls back to
    # scraping the onion root page verbatim.
    darkweb_queries: list[str] = [
        "ransomware leak",
        "database leak",
        "stolen data dump",
        "credential dump",
    ]
    # Dedicated timeouts for the DarkWebCollector. Tor circuit build is slow
    # (30-90+ s for the first hop), so these are deliberately much longer than
    # the shared clearnet fetch default (http_fetch default 30s).
    darkweb_fetch_timeout: int = 120    # per-onion fetch through Tor
    darkweb_ready_timeout: int = 60     # Tor readiness probe (check.torproject.org)

    # --- Telegram scraping hook (free Bot API) --------------------------------
    telegram_bot_token: str = ""
    telegram_channel: str = ""        # e.g. "@my_threat_channel"

    # --- Real-time alerting (Phase 5) -----------------------------------------
    # Master switch for outbound notifications. When on, a notification is
    # created whenever a NEW sheet meets the thresholds below and stored in the
    # `notifications` table (in-app bell).
    alerting_enabled: bool = True
    # Minimum sheet risk level that triggers an alert (CRITICAL/HIGH default).
    alert_min_risk: str = "HIGH"
    # Always alert on CVEs from a KEV source (CISA-KEV / CISA-ADV) regardless
    # of the modelled risk level — a known-exploited CVE is inherently urgent.
    alert_kev_always: bool = True
    # Telegram push is DEFERRED to a future phase: the code path in
    # `notifications.py` is ready, but it is off until a real bot token +
    # channel are configured (see .env.example). When enabled it is still
    # best-effort — a failed push never touches the pipeline.
    alert_telegram: bool = False
    # Store alerts for the in-app notification centre (always kept in ClickHouse
    # when alerting is enabled; this flag only controls the UI surface).
    alert_inapp: bool = True
    # Notifications list page size default.
    notifications_page_size: int = 50

    # --- Optional free API keys ------------------------------------------------
    nvd_api_key: str = ""             # https://nvd.nist.gov/developers/request-an-api-key
    otx_api_key: str = ""             # https://otx.alienvault.com/api
    misp_url: str = ""
    misp_api_key: str = ""

    # --- API server ------------------------------------------------------------
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    # Bearer token protecting state-changing endpoints (POST /api/v1/ingest).
    api_access_token: str = "change-me-in-production"

    # --- Scheduler / polling ---------------------------------------------------
    poll_interval_rss: int = 600      # CERT / news RSS feeds
    poll_interval_json: int = 1800    # CISA KEV / abuse.ch JSON feeds
    poll_interval_nvd: int = 3600     # NVD incremental sync

    # --- IP geolocation (Threat-origin choropleth) ------------------------------
    # Free, no-key HTTPS provider. NOTE: ip-api.com (free tier) is HTTP-only and
    # this host blocks outbound HTTP, so ipwho.is is used instead — same
    # guarantees (no key, free quota, graceful backoff). Every IP is cached in
    # ClickHouse, so quota is spent at most once per address ever.
    geo_provider_url: str = "https://ipwho.is"
    geo_request_interval: float = 1.0    # seconds between lookups (polite pacing)
    geo_max_per_cycle: int = 1500        # hard cap per background cycle
    geo_monthly_budget: int = 9000       # leave margin under the free 10k/month
    geo_poll_interval: int = 900         # seconds between background cycles
    geo_first_delay: int = 120           # warmup after boot (let first sync land)

    # --- Feature flags ---------------------------------------------------------
    # Enables IOC enrichment through the free Shodan InternetDB API.
    enable_shodan_enrichment: bool = True

    # --- AI pipeline reliability ------------------------------------------------
    # A CVE that fails LLM generation is retried (with backoff) up to this many
    # attempts, then left as status=failed so the UI shows it honestly.
    ai_max_attempts: int = 3
    # Cooldown (minutes) before a failed CVE may be retried by the scheduler.
    ai_retry_cooldown_minutes: int = 30
    # Global minimum spacing between LLM calls (free-tier throttling: Gemini ~20
    # RPM). Applied to every engine so we never hammer a provider.
    ai_min_interval_seconds: float = 3.0
    # Bounded AI work queue. New work is deduplicated before enqueueing, so this
    # only ever holds genuinely new CVEs; a full queue never drops work (records
    # stay pending in `alert_sheet_pending` and the scheduler retries them).
    ai_queue_size: int = 1000
    # A pending/processing sheet untouched for this many minutes is treated as
    # orphaned (crash / full queue) and re-enqueued by the scheduler.
    ai_stale_processing_minutes: int = 5
    # Hard per-engine cap on a single LLM call (e.g. a stuck local Ollama model
    # fails over to Gemini promptly instead of stalling the whole request).
    ai_engine_timeout_seconds: float = 120.0

    # --- Derived convenience properties ----------------------------------------
    @property
    def clickhouse_url(self) -> str:
        """HTTP interface URL for the ClickHouse client (clickhouse-connect)."""
        scheme = "https" if self.clickhouse_secure else "http"
        return f"{scheme}://{self.clickhouse_host}:{self.clickhouse_port}"

    @property
    def active_provider(self) -> str:
        """Resolve which provider is active.

        Priority: explicit `LLM_PROVIDER` override, then the `auto` default:
        local Ollama is primary (health-checked before every sheet generation),
        with automatic failover to Gemini when Ollama is unreachable. The actual
        per-call engine is logged as `event=sheet_generated engine=…`.
        """
        if self.llm_provider != "auto":
            return self.llm_provider
        return "ollama"

    @property
    def tor_socks5(self) -> str:
        """Normalised socks5 URI accepted by aiohttp-socks ProxyConnector."""
        return self.tor_proxy if self.tor_proxy.startswith("socks5") else f"socks5://{self.tor_proxy}"


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    `lru_cache` makes repeated `get_settings()` calls cheap (no file re-reads)
    while still allowing tests to call `get_settings.cache_clear()`.
    """
    return Settings()


# Singleton instance: importable as `from app.config import settings`.
settings = get_settings()
