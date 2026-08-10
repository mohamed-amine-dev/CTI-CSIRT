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
    # Onion URLs scraped through Tor. The default is DuckDuckGo's public onion
    # search index: a stable, clean, non-offensive .onion that validates the
    # pipeline end-to-end. Analysts can point this list at their own targets.
    darkweb_onion_urls: list[str] = [
        "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    ]

    # --- Telegram scraping hook (free Bot API) --------------------------------
    telegram_bot_token: str = ""
    telegram_channel: str = ""        # e.g. "@my_threat_channel"

    # --- Real-time alerting (Phase 5) -----------------------------------------
    # Master switch for outbound notifications. When on, a notification is
    # created whenever a NEW fiche meets the thresholds below and stored in the
    # `notifications` table (in-app bell).
    alerting_enabled: bool = True
    # Minimum fiche risk level that triggers an alert (CRITICAL/HIGH default).
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
    # stay pending in `fiche_pending` and the scheduler retries them).
    ai_queue_size: int = 1000
    # A pending/processing fiche untouched for this many minutes is treated as
    # orphaned (crash / full queue) and re-enqueued by the scheduler.
    ai_stale_processing_minutes: int = 5

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
        local Ollama is primary (health-checked before every fiche generation),
        with automatic failover to Gemini when Ollama is unreachable. The actual
        per-call engine is logged as `event=fiche_generated engine=…`.
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
