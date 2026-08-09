# =============================================================================
# CTI Platform - asynchronous modular ingestion engine
# -----------------------------------------------------------------------------
# A collection of async collectors that pull intelligence from dozens of FREE
# feeds, normalise it into a common `IntelRecord` shape, store raw text into
# ClickHouse `raw_threat_intel`, extract indicators into `processed_iocs`, and
# hand CVEs over to the AI processor for Fiche d'Alerte generation.
#
# Architecture:
#   BaseCollector (abstract)
#     ├─ run()            : infinite polling loop with per-source backoff
#     ├─ collect_once()   : one full poll -> [IntelRecord, ...]
#     ├─ fetch()          : resilient HTTP GET (retries, backoff, timeout)
#     └─ store_record()   : persist raw text + IOCs, fan out to AI fiche worker
#   Concrete collectors (each = one feed family)
#     ├─ CisaCollector          CISA KEV catalog + advisories (JSON)
#     ├─ CertFRCollector        CERT-FR RSS/Atom
#     ├─ CertEUCollector        CERT-EU RSS/Atom
#     ├─ NewsCollector          The Hacker News + Cybercrime News RSS
#     ├─ NvdCollector           NIST NVD v2 API (incremental, rate-limited)
#     ├─ ShodanFreeCollector    internetdb.shodan.io enrichment (free, no key)
#     ├─ DarkWebCollector       Tor SOCKS5 scraping + Telegram Bot API hook
#     ├─ UrlhausCollector       abuse.ch URLhaus (CSV)
#     ├─ ThreatFoxCollector     abuse.ch ThreatFox (JSON)
#     ├─ FeodoTrackerCollector  abuse.ch botnet C2 IP blocklist (text)
#     ├─ SslblJa3Collector      abuse.ch SSLBL JA3 fingerprints (CSV)
#     ├─ BlocklistDeCollector   lists.blocklist.de (text)
#     ├─ SpamhausDropCollector  Spamhaus DROP/EDROP (text)
#     ├─ OpenPhishCollector     OpenPhish live feed (text)
#     ├─ AlienVaultOTXCollector OTX pulses (JSON, free key)
#     └─ MispCollector          MISP events (JSON, free self-hosted)
#
# Concurrency model: every collector runs as its own asyncio.Task. They share
# one aiohttp.ClientSession (connection pooling). feedparser and csv parsing
# are CPU/sync and therefore offloaded with asyncio.to_thread so the event loop
# never stalls.
# =============================================================================

from __future__ import annotations

import asyncio
import csv
import io
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

import aiohttp
import feedparser

from .config import Settings, settings as app_settings
from .db import insert_rows

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
IOC_TYPES = ("ipv4", "ipv6", "cidr", "domain", "url", "sha256", "sha1", "md5", "cve", "ja3", "email")


@dataclass(slots=True)
class IOC:
    """A single normalised indicator extracted from raw intelligence."""

    indicator: str
    type: str
    severity: float = 1.0


@dataclass(slots=True)
class IntelRecord:
    """Normalised unit of intelligence shared by every collector."""

    source: str                 # feed family label, e.g. "CISA-KEV"
    raw_text: str               # original text / summary of the item
    url: str = ""               # canonical link to the item
    cve: str | None = None      # optional pre-detected CVE
    indicators: list[IOC] = field(default_factory=list)


# ---------------------------------------------------------------------------
# IOC extraction (pure, unit-testable)
# ---------------------------------------------------------------------------
# Compiled once at import; each pattern maps to an IOC type.
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b"
    r"|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b"
    r"|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b",
)
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])\b")
_RE_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
# Domain (excludes IPs and TLD-less strings). Kept deliberately permissive.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|xyz|top|site|online|cc|me|"
    r"fr|eu|de|uk|ru|cn|in|it|es|nl|pl|se|ch|at|be|jp|kr|au|ca|br|mx|za|ng|tr|il|ae|sa|eg|gr|no|fi|dk|"
    r"cz|sk|hu|ro|bg|hr|rs|ua|lt|lv|ee|by|kz|md|ge|am|az|uz|pk|bd|lk|th|vn|my|ph|id|sg|tw|hk|cl|ar|co|"
    r"pe|ve|uy|py|bo|ec|gt|pa|do|cu|jm|tt|ht|sv|hn|ni|cr|gf|mq|gp|re|yt|pf|nc|wf|tf|onion)\b",
    re.IGNORECASE,
)
_RE_JA3 = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def extract_iocs(text: str) -> list[IOC]:
    """Extract, normalise and de-duplicate indicators from arbitrary text."""
    found: dict[str, IOC] = {}

    def _add(value: str, ioc_type: str) -> None:
        v = value.rstrip(".,;:)]}>\"'").lstrip("[(<\"'").lower()
        if len(v) < 4:
            return
        if v not in found:
            found[v] = IOC(indicator=v, type=ioc_type)

    for m in _RE_IPV4.finditer(text):
        _add(m.group(), "ipv4")
    for m in _RE_IPV6.finditer(text):
        _add(m.group(), "ipv6")
    for m in _RE_CVE.finditer(text):
        _add(m.group().upper(), "cve")
    for m in _RE_SHA256.finditer(text):
        _add(m.group().lower(), "sha256")
    for m in _RE_SHA1.finditer(text):
        _add(m.group().lower(), "sha1")
    for m in _RE_MD5.finditer(text):
        _add(m.group().lower(), "md5")
    for m in _RE_JA3.finditer(text):
        _add(m.group().lower(), "ja3")
    for m in _RE_EMAIL.finditer(text):
        _add(m.group(), "email")
    for m in _RE_URL.finditer(text):
        _add(m.group(), "url")
    for m in _RE_DOMAIN.finditer(text):
        # avoid classifying an IP-looking string as a domain
        if not _RE_IPV4.fullmatch(m.group()):
            _add(m.group(), "domain")
    return list(found.values())


def extract_cve(text: str) -> str | None:
    """Return the first CVE id found in text (uppercased), else None."""
    m = _RE_CVE.search(text)
    return m.group().upper() if m else None


# ---------------------------------------------------------------------------
# Resilient HTTP fetch helper (shared by all collectors)
# ---------------------------------------------------------------------------
async def http_fetch(
    session: aiohttp.ClientSession,
    url: str,
    *,
    proxy: str | None = None,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    max_retries: int = 3,
    semaphore: asyncio.Semaphore | None = None,
) -> bytes:
    """GET a URL with exponential backoff on transient failures.

    Respects an optional rate-limit semaphore and honours HTTP 429 / 5xx by
    backing off with jitter before retrying (important for free APIs like NVD).
    """
    async def _attempt() -> bytes:
        async with session.get(url, params=params, proxy=proxy, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            resp.raise_for_status()   # raises ClientResponseError for 4xx/5xx
            return await resp.read()

    attempt = 0
    while True:
        try:
            if semaphore:
                async with semaphore:
                    return await _attempt()
            return await _attempt()
        except aiohttp.ClientResponseError as exc:
            # Definitive client errors (404 = not found, 403 = forbidden, ...)
            # will NOT get better with retries -> fail fast. 429 (rate limit)
            # and 5xx (server hiccup) are transient -> retry with backoff.
            if exc.status < 500 and exc.status != 429:
                raise
            attempt += 1
            if attempt >= max_retries:
                logger.warning("fetch failed (%s) after %d tries: %s", url, max_retries, exc)
                raise
            delay = min(30.0, 2 ** (attempt - 1)) * (0.8 + 0.4 * ((time.time() * 7) % 1))
            logger.debug("retry %d/%d for %s in %.1fs", attempt, max_retries, url, delay)
            await asyncio.sleep(delay)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            attempt += 1
            if attempt >= max_retries:
                logger.warning("fetch failed (%s) after %d tries: %s", url, max_retries, exc)
                raise
            # Exponential backoff with jitter: 1s, 2s, 4s ... +- 20%
            delay = min(30.0, 2 ** (attempt - 1)) * (0.8 + 0.4 * ((time.time() * 7) % 1))
            logger.debug("retry %d/%d for %s in %.1fs", attempt, max_retries, url, delay)
            await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Base collector
# ---------------------------------------------------------------------------
class BaseCollector(ABC):
    """Abstract async collector.

    Subclasses implement `parse()` (bytes -> records) and optionally override
    `collect_once()`. `run()` drives the polling loop; `store_record()` handles
    persistence and fan-out.
    """

    #: Sub-class friendly name used in logs and as the DB `source` prefix.
    name: str = "base"
    #: Default poll interval (seconds). Overridden per-class.
    poll_interval: int = 1800

    def __init__(
        self,
        session: aiohttp.ClientSession,
        db: Any,
        settings: Settings = app_settings,
        *,
        enabled: bool = True,
        fiche_cb: Callable[[IntelRecord], Awaitable[None]] | None = None,
        ioc_cb: Callable[[list[IOC]], Awaitable[None]] | None = None,
    ) -> None:
        self.session = session
        self.db = db                     # clickhouse-connect AsyncClient
        self.settings = settings
        self.enabled = enabled
        self.fiche_cb = fiche_cb         # optional async hook -> AI fiche worker
        self.ioc_cb = ioc_cb             # optional async hook -> IOC enrichment
        self.rate_limit: asyncio.Semaphore | None = None
        self.last_run_ok = True
        self.stats: dict[str, int] = {"records": 0, "errors": 0}
        self._run_errors = 0

    # -- network -------------------------------------------------------------
    async def fetch(self, url: str, **kw: Any) -> bytes:
        """Convenience wrapper around http_fetch bound to this collector."""
        return await http_fetch(self.session, url, **kw)

    # -- parsing --------------------------------------------------------------
    def parse(self, data: bytes) -> list[IntelRecord]:
        """Turn raw feed bytes into normalised IntelRecords.

        Pull-based collectors override `collect_once` entirely and never reach
        this method; feed-based collectors implement it. Implementations run in
        a worker thread via collect_once (to_thread), so blocking libraries
        (feedparser, csv) are safe here.
        """
        raise NotImplementedError(f"{self.name} does not implement parse()")

    # -- collection -----------------------------------------------------------
    async def collect_once(self) -> list[IntelRecord]:
        """Fetch and parse the feed once. Called both by run() and the API."""
        urls = self.feed_urls()
        records: list[IntelRecord] = []
        self._run_errors = 0
        for url in urls:
            try:
                data = await self.fetch(url)
            except Exception as exc:  # noqa: BLE001 - a single feed must not kill the loop
                self.stats["errors"] += 1
                self._run_errors += 1
                self.last_run_ok = False
                logger.error("%s: fetch error %s -> %s", self.name, url, exc)
                continue
            try:
                # parse() is synchronous (feedparser/csv); keep the loop free.
                parsed = await asyncio.to_thread(self.parse, data)
                records.extend(parsed)
                logger.info("%s: +%d records from %s", self.name, len(parsed), url)
            except Exception as exc:  # noqa: BLE001
                self.stats["errors"] += 1
                self._run_errors += 1
                logger.error("%s: parse error %s -> %s", self.name, url, exc, exc_info=True)
        if self._run_errors == 0:
            self.last_run_ok = True
        return records

    def feed_urls(self) -> list[str]:
        """Return the URLs to poll. Defaults to a single `self.url`."""
        return [self.url]

    # -- persistence ----------------------------------------------------------
    async def store_record(self, record: IntelRecord) -> None:
        """Persist one record: raw text + indicators, then fan out to the AI worker.

        All inserts are idempotent thanks to ReplacingMergeTree:
          * raw_threat_intel  dedup key (source, url)
          * processed_iocs    dedup key (type, indicator)
        """
        now = int(time.time() * 1_000_000)
        await insert_rows(
            self.db,
            "raw_threat_intel",
            [[record.source, record.raw_text, record.url, now]],
            ["source", "raw_text", "url", "version"],
        )
        self.stats["records"] += 1

        # Combine explicitly attached indicators with regex extraction.
        indicators = list(record.indicators)
        if record.raw_text:
            indicators.extend(extract_iocs(record.raw_text))
        if record.cve and not any(i.type == "cve" and i.indicator == record.cve for i in indicators):
            indicators.append(IOC(record.cve, "cve"))

        if indicators:
            await insert_rows(
                self.db,
                "processed_iocs",
                [[i.indicator, i.type, i.severity, now] for i in indicators],
                ["indicator", "type", "severity", "version"],
            )

        # Fan out to the AI fiche worker only when a CVE is present.
        cve = record.cve or extract_cve(record.raw_text or "")
        if cve and self.fiche_cb is not None:
            record.cve = cve
            try:
                await self.fiche_cb(record)
            except Exception as exc:  # noqa: BLE001 - AI failure must not break ingestion
                logger.error("%s: fiche callback failed for %s: %s", self.name, cve, exc)

        # Fan out new indicators to enrichment (e.g. Shodan InternetDB).
        if indicators and self.ioc_cb is not None:
            try:
                await self.ioc_cb(indicators)
            except Exception as exc:  # noqa: BLE001
                logger.debug("%s: ioc callback failed: %s", self.name, exc)

    async def process(self, records: Iterable[IntelRecord]) -> int:
        """Persist a batch of records, returning how many were stored.

        Inserts are batched (one ClickHouse round-trip per ~1000 records instead
        of one per record) — a collector like URLHAUS can yield 15k+ rows and a
        per-record round-trip would stall a sync for many minutes. The per-record
        fan-out to the AI fiche worker and IOC enrichment is kept as-is; those
        only enqueue to bounded queues and do not block on the workers.
        """
        n = 0
        raw_rows: list[list[Any]] = []
        ioc_rows: list[list[Any]] = []

        async def flush() -> None:
            if raw_rows:
                await insert_rows(
                    self.db, "raw_threat_intel", raw_rows,
                    ["source", "raw_text", "url", "version"],
                )
                raw_rows.clear()
            if ioc_rows:
                await insert_rows(
                    self.db, "processed_iocs", ioc_rows,
                    ["indicator", "type", "severity", "version"],
                )
                ioc_rows.clear()

        try:
            for rec in records:
                now = int(time.time() * 1_000_000)
                raw_rows.append([rec.source, rec.raw_text, rec.url, now])
                self.stats["records"] += 1

                # Combine explicitly attached indicators with regex extraction.
                indicators = list(rec.indicators)
                if rec.raw_text:
                    indicators.extend(extract_iocs(rec.raw_text))
                if rec.cve and not any(i.type == "cve" and i.indicator == rec.cve for i in indicators):
                    indicators.append(IOC(rec.cve, "cve"))

                for i in indicators:
                    ioc_rows.append([i.indicator, i.type, i.severity, now])

                # Fan out to the AI fiche worker only when a CVE is present.
                cve = rec.cve or extract_cve(rec.raw_text or "")
                if cve and self.fiche_cb is not None:
                    rec.cve = cve
                    try:
                        await self.fiche_cb(rec)
                    except Exception as exc:  # noqa: BLE001 - AI failure must not break ingestion
                        logger.error("%s: fiche callback failed for %s: %s", self.name, cve, exc)

                # Fan out new indicators to enrichment (e.g. Shodan InternetDB).
                if indicators and self.ioc_cb is not None:
                    try:
                        await self.ioc_cb(indicators)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("%s: ioc callback failed: %s", self.name, exc)

                n += 1
                if len(raw_rows) >= 1000:
                    await flush()
        finally:
            await flush()
        return n

    # -- scheduler loop --------------------------------------------------------
    async def run(self, stop_event: asyncio.Event) -> None:
        """Infinite polling loop until `stop_event` is set."""
        if not self.enabled:
            logger.info("%s: disabled, not starting", self.name)
            return
        logger.info("%s: collector started (poll=%ds)", self.name, self.poll_interval)
        while not stop_event.is_set():
            try:
                records = await self.collect_once()
                if records:
                    await self.process(records)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("%s: collector loop error: %s", self.name, exc)
            # Sleep in small slices so shutdown (stop_event) is responsive.
            for _ in range(max(1, self.poll_interval // 5)):
                if stop_event.is_set():
                    break
                await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# 1. CISA - Known Exploited Vulnerabilities + advisories (JSON)
# ---------------------------------------------------------------------------
class CisaCollector(BaseCollector):
    name = "CISA"
    poll_interval = 1800
    # KEV catalog = the authoritative list of *known exploited* CVEs.
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    advisory_url = "https://www.cisa.gov/sites/default/files/feeds/advisories.json"

    def feed_urls(self) -> list[str]:
        return [self.url, self.advisory_url]

    def parse(self, data: bytes) -> list[IntelRecord]:
        import json
        doc = json.loads(data)
        records: list[IntelRecord] = []
        for vuln in doc.get("vulnerabilities", []):
            cve = vuln.get("cveID", "")
            if not cve:
                continue
            text = (
                f"{vuln.get('vulnerabilityName', cve)} ({cve}) affects "
                f"{vuln.get('vendorProject')} {vuln.get('product')}. "
                f"Added {vuln.get('dateAdded')}, due {vuln.get('dueDate')}. "
                f"Ransomware campaign use: {vuln.get('knownRansomwareCampaignUse')}. "
                f"Notes: {vuln.get('notes', '')} Required action: {vuln.get('requiredAction', '')}"
            )
            rec = IntelRecord(source="CISA-KEV", raw_text=text, cve=cve)
            rec.url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            records.append(rec)
        for adv in doc.get("advisories", []):
            title = adv.get("title", "")
            text = f"{title} published {adv.get('releaseDate', '')}: {adv.get('summary', '')}"
            records.append(IntelRecord(source="CISA-ADV", raw_text=text, url=adv.get("url", "")))
        return records


# ---------------------------------------------------------------------------
# 2/3. European CERTs - RSS/Atom feeds
# ---------------------------------------------------------------------------
class _RssCollector(BaseCollector):
    """Shared feedparser logic for RSS/Atom based collectors."""

    def parse(self, data: bytes) -> list[IntelRecord]:
        # feedparser is not async-safe; run()/collect_once call us via to_thread.
        feed = feedparser.parse(data)
        records: list[IntelRecord] = []
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary") or entry.get("description") or ""
            # strip HTML tags to keep raw_text clean for the LLM
            clean = re.sub(r"<[^>]+>", " ", summary)
            records.append(IntelRecord(
                source=self.source_label,
                raw_text=f"{title}\n{clean}".strip(),
                url=entry.get("link", ""),
            ))
        return records


class CertFRCollector(_RssCollector):
    name = "CERT-FR"
    source_label = "CERT-FR"
    poll_interval = 600
    # CERT-FR publishes multiple feeds; main alert + advisory RSS below.
    url = "https://www.cert.ssi.gouv.fr/feed/"

    def feed_urls(self) -> list[str]:
        return [
            "https://www.cert.ssi.gouv.fr/feed/",
            "https://www.cert.ssi.gouv.fr/avis/feed/",
        ]


class CertEUCollector(_RssCollector):
    name = "CERT-EU"
    source_label = "CERT-EU"
    poll_interval = 600
    # CERT-EU security advisories RSS (URL is configurable at runtime).
    url = "https://cert.europa.eu/publications/security-advisories-rss"


# ---------------------------------------------------------------------------
# 4. News feeds - The Hacker News + Cybercrime News
# ---------------------------------------------------------------------------
class NewsCollector(_RssCollector):
    name = "NEWS"
    source_label = "NEWS"
    poll_interval = 600

    def feed_urls(self) -> list[str]:
        return [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.cybercrimenews.com/feed",
        ]


# ---------------------------------------------------------------------------
# 5. NIST NVD - free v2 API, incremental + rate-limit aware
# ---------------------------------------------------------------------------
class NvdCollector(BaseCollector):
    """Incremental CVE sync from the NVD v2 API.

    Free API key (optional) raises the quota from 5 to 50 requests / 30 s.
    We store a `lastModStartDate` watermark in ingest_state so every poll only
    pulls records modified since the previous run (cheap + polite).
    """

    name = "NVD"
    poll_interval = 3600
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # NVD caps resultsPerPage at 2000; we throttle ourselves to be nice.
        self.rate_limit = asyncio.Semaphore(2)

    @staticmethod
    def _utc_str(ts: float | None = None) -> str:
        """ISO-8601 UTC timestamp accepted by the NVD API (numeric offset)."""
        import datetime as _dt
        moment = _dt.datetime.fromtimestamp(ts or time.time(), tz=_dt.timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    async def _load_watermark(self) -> str:
        rows = await self.db.query(
            "SELECT last_ts FROM {db:Identifier}.ingest_state FINAL WHERE source = {s:String}",
            parameters={"db": self.settings.clickhouse_database, "s": "nvd"},
        )
        if rows.result_rows:
            last = rows.result_rows[0][0]
            # stored as a naive UTC datetime -> re-format with numeric offset
            return last.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
        # First run: look back 30 days to warm the database.
        return self._utc_str(time.time() - 30 * 86400)

    async def _save_watermark(self, ts: str) -> None:
        import datetime as _dt
        dt = _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S+00:00")
        await insert_rows(
            self.db, "ingest_state",
            [["nvd", dt, ""]],
            ["source", "last_ts", "meta"],
        )

    async def collect_once(self) -> list[IntelRecord]:
        """Incremental NVD sync, guarded so a rate-limit / API error is logged
        and the collector survives until the next cycle."""
        try:
            return await self._collect_once()
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            self.last_run_ok = False
            logger.error("%s: sync failed (%s) — will retry next cycle", self.name, exc, exc_info=True)
            return []

    async def _collect_once(self) -> list[IntelRecord]:
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        start = await self._load_watermark()
        end = self._utc_str()

        records: list[IntelRecord] = []
        index = 0
        per_page = 2000
        while True:
            params = {
                "lastModStartDate": start,
                "lastModEndDate": end,
                "resultsPerPage": per_page,
                "startIndex": index,
            }
            data = await self.fetch(self.url, params=params, headers=headers)
            doc = await asyncio.to_thread(_json_loads, data)
            for item in doc.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                desc = next(
                    (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                )
                score = _cvss_score(cve)
                rec = IntelRecord(source="NVD", raw_text=desc, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", cve=cve_id)
                if score:
                    rec.indicators = [IOC(cve_id, "cve", severity=score)]
                records.append(rec)
            total = doc.get("totalResults", 0)
            index += per_page
            if index >= total:
                break
            # be polite between pages
            await asyncio.sleep(1.0)

        await self._save_watermark(end)
        logger.info("%s: synced %d CVEs modified since %s", self.name, len(records), start)
        return records


def _json_loads(data: bytes) -> dict[str, Any]:
    import json
    return json.loads(data)


def _cvss_score(cve: dict[str, Any]) -> float | None:
    """Best-effort CVSS base score from NVD metrics (v4 -> v3.1 -> v3.0)."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


# ---------------------------------------------------------------------------
# 6. Shodan Free - internetdb.shodan.io enrichment (no API key needed)
# ---------------------------------------------------------------------------
class ShodanFreeCollector(BaseCollector):
    """Enriches discovered IPs using Shodan's free InternetDB API.

    Push model: the pipeline calls `enrich(ips)` whenever new IP IOCs appear.
    The API returns ports, hostnames, CVEs and tags for a given IP; anything
    we find is recorded as an IntelRecord so it lands in raw_threat_intel and
    the enrichment raises the IOC severity in processed_iocs.
    """

    name = "SHODAN"
    poll_interval = 0               # pull model; no scheduled poll needed
    url = "https://internetdb.shodan.io/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.rate_limit = asyncio.Semaphore(5)
        self._cache: set[str] = set()

    async def collect_once(self) -> list[IntelRecord]:
        """Pull model: nothing to poll — enrichment is driven by `enrich()`."""
        return []

    async def enrich(self, ips: list[str]) -> list[IntelRecord]:
        """Query InternetDB for each IP; return enrichment records."""
        records: list[IntelRecord] = []
        for ip in ips:
            # Only bare IPv4 addresses are indexable by InternetDB: skip CIDR
            # blocks and host:port strings so we don't waste free-tier calls.
            if ip in self._cache or "/" in ip or ":" in ip:
                continue
            self._cache.add(ip)
            try:
                data = await self.fetch(f"{self.url}{ip}")
                info = await asyncio.to_thread(_json_loads, data)
            except aiohttp.ClientError as exc:
                # 404 = "not indexed", perfectly normal; 429 = slow down.
                logger.debug("%s: %s -> %s", self.name, ip, exc)
                continue
            text = (
                f"InternetDB enrichment for {info.get('ip')}: ports={info.get('ports')}, "
                f"hostnames={info.get('hostnames')}, tags={info.get('tags')}, "
                f"vulns={info.get('vulns')}, cpes={info.get('cpes')}"
            )
            rec = IntelRecord(source="SHODAN-INTERNETDB", raw_text=text, url=f"{self.url}{ip}")
            rec.indicators = [IOC(ip, "ipv4", severity=5.0)]
            for v in info.get("vulns", []):
                rec.indicators.append(IOC(v.upper(), "cve", severity=8.0))
            records.append(rec)
        return records


# ---------------------------------------------------------------------------
# 7. Dark Web - Tor SOCKS5 scraping + Telegram hook
# ---------------------------------------------------------------------------
class DarkWebCollector(BaseCollector):
    """Scrapes onion sites through a Tor SOCKS5 proxy and optionally polls a
    Telegram channel via the free Bot API.

    Network path: aiohttp_socks.ProxyConnector with `socks5h://` so the DNS
    resolution happens inside Tor (never leaks to the resolver). Everything is
    best-effort: a dead onion node or a revoked Telegram token must never crash
    the ingestion loop.
    """

    name = "DARKWEB"
    poll_interval = 3600

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Separate session whose connector routes through Tor.
        # NOTE: python-socks only understands socks4/socks5/http schemes, so the
        # curl-style "h" suffix (socks5h) is stripped. Hostname resolution still
        # happens THROUGH the proxy (remote DNS), which is exactly the anonymity
        # property "socks5h" guarantees — it never leaks to a local resolver.
        from aiohttp_socks import ProxyConnector
        proxy_url = self.settings.tor_socks5.replace("socks5h://", "socks5://", 1)
        self._connector = ProxyConnector.from_url(proxy_url, limit=5)
        self.tor_session: aiohttp.ClientSession | None = None

    async def _ensure_tor_session(self) -> aiohttp.ClientSession:
        if self.tor_session is None or self.tor_session.closed:
            self.tor_session = aiohttp.ClientSession(connector=self._connector)
        return self.tor_session

    async def _tor_ready(self) -> bool:
        """Return True when Tor is reachable through the proxy."""
        try:
            sess = await self._ensure_tor_session()
            data = await http_fetch(sess, "http://check.torproject.org", timeout=15, max_retries=1)
            return b"Congratulations" in data or b"is configured" in data
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s: Tor not reachable: %s", self.name, exc)
            return False

    async def collect_once(self) -> list[IntelRecord]:
        if not self.settings.darkweb_enabled:
            return []
        try:
            return await self._collect_once()
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            self.last_run_ok = False
            logger.error("%s: sync failed (%s) — will retry next cycle", self.name, exc, exc_info=True)
            return []

    async def _collect_once(self) -> list[IntelRecord]:
        if not await self._tor_ready():
            return []

        records: list[IntelRecord] = []
        sess = await self._ensure_tor_session()
        for onion in self.settings.darkweb_onion_urls:
            try:
                data = await http_fetch(sess, onion, timeout=20, max_retries=2)
                text = data.decode("utf-8", errors="replace")
                # strip tags; keep text small enough for the LLM but rich enough
                clean = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))[:4000]
                records.append(IntelRecord(source="DARKWEB-ONION", raw_text=clean, url=onion))
            except Exception as exc:  # noqa: BLE001
                logger.debug("%s: %s failed: %s", self.name, onion, exc)

        if self.settings.telegram_bot_token:
            records.extend(await self._telegram_updates())

        return records

    async def _telegram_updates(self) -> list[IntelRecord]:
        """Pull the latest messages from a Telegram channel via Bot API.

        Uses `getUpdates` (long polling). This is a hook: analysts point it at
        their own threat-sharing channel. Zero cost, no paid API.
        """
        token = self.settings.telegram_bot_token
        channel = self.settings.telegram_channel
        records: list[IntelRecord] = []
        try:
            sess = await self._ensure_tor_session()
            url = f"https://api.telegram.org/bot{token}/getUpdates"
            data = await http_fetch(sess, url, timeout=25, max_retries=1)
            doc = await asyncio.to_thread(_json_loads, data)
            for result in doc.get("result", []):
                msg = result.get("message", {}) or result.get("channel_post", {})
                text = msg.get("text") or msg.get("caption") or ""
                chat = msg.get("chat", {})
                if channel and chat.get("username") != channel.lstrip("@"):
                    continue
                if text:
                    records.append(IntelRecord(source="TELEGRAM", raw_text=text[:4000]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s: telegram hook failed: %s", self.name, exc)
        return records

    async def close(self) -> None:
        if self.tor_session and not self.tor_session.closed:
            await self.tor_session.close()
        await self._connector.close()


# ---------------------------------------------------------------------------
# 8..14. Additional free IOC feeds (professional enrichment layer)
# ---------------------------------------------------------------------------
class UrlhausCollector(BaseCollector):
    """abuse.ch URLhaus - URLs spreading malware (CSV)."""

    name = "URLHAUS"
    poll_interval = 1800
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        text = data.decode("utf-8", errors="replace")
        for row in csv.reader(io.StringIO(text)):
            if not row or row[0].startswith("#"):
                continue
            # id, dateadded, url, url_status, threat, tags, urlhaus_link, ...
            url = row[2]
            threat = row[4] if len(row) > 4 else ""
            tags = row[5] if len(row) > 5 else ""
            rec = IntelRecord(
                source="URLHAUS",
                raw_text=f"Malicious URL: {url} threat={threat} tags={tags}",
                url=url,
                indicators=[IOC(url, "url", severity=6.0)],
            )
            records.append(rec)
        return records


class ThreatFoxCollector(BaseCollector):
    """abuse.ch ThreatFox - recent malware IOCs (JSON)."""

    name = "THREATFOX"
    poll_interval = 1800
    url = "https://threatfox.abuse.ch/export/json/recent/"

    def parse(self, data: bytes) -> list[IntelRecord]:
        doc = _json_loads(data)
        records: list[IntelRecord] = []
        for item in doc if isinstance(doc, list) else []:
            ioc_value = item.get("ioc", "")
            ioc_type = item.get("ioc_type", "")
            threat = item.get("threat_type", "")
            malware = item.get("malware_printable", "")
            typ = {"ip:port": "ipv4", "url": "url", "md5_hash": "md5", "sha256_hash": "sha256", "domain": "domain"}.get(ioc_type, ioc_type or "ipv4")
            rec = IntelRecord(
                source="THREATFOX",
                raw_text=f"IOC {ioc_value} type={ioc_type} malware={malware} threat_type={threat}",
                url=f"https://threatfox.abuse.ch/browse.php?search={ioc_value}",
            )
            rec.indicators = [IOC(ioc_value, typ, severity=7.0)]
            records.append(rec)
        return records


class FeodoTrackerCollector(BaseCollector):
    """abuse.ch Feodo Tracker - botnet C2 IP blocklist (text, one IP/line)."""

    name = "FEODO"
    poll_interval = 1800
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        for line in data.decode().splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            records.append(IntelRecord(
                source="FEODO-C2",
                raw_text=f"Botnet C2 IP: {ip}",
                url=f"https://feodotracker.abuse.ch/host/{ip}/",
                indicators=[IOC(ip, "ipv4", severity=8.0)],
            ))
        return records


class SslblJa3Collector(BaseCollector):
    """abuse.ch SSL Blacklist - malicious JA3 TLS fingerprints (CSV)."""

    name = "SSLBL"
    poll_interval = 1800
    url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        for row in csv.reader(io.StringIO(data.decode(errors="replace"))):
            if not row or row[0].startswith("#") or row[0].lower() == "ja3":
                continue
            ja3, desc = row[0], (row[1] if len(row) > 1 else "")
            records.append(IntelRecord(
                source="SSLBL-JA3",
                raw_text=f"Malicious JA3 {ja3}: {desc}",
                indicators=[IOC(ja3, "ja3", severity=7.0)],
            ))
        return records


class BlocklistDeCollector(BaseCollector):
    """lists.blocklist.de - aggregated SSH/brute-force attacker IPs (text)."""

    name = "BLOCKLISTDE"
    poll_interval = 1800
    url = "https://lists.blocklist.de/lists/all.txt"

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        for line in data.decode().splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            records.append(IntelRecord(
                source="BLOCKLISTDE",
                raw_text=f"Brute-force attacker IP: {ip}",
                indicators=[IOC(ip, "ipv4", severity=5.0)],
            ))
        return records


class SpamhausDropCollector(BaseCollector):
    """Spamhaus DROP/EDROP - hijacked netblocks (text)."""

    name = "SPAMHAUS"
    poll_interval = 3600

    def feed_urls(self) -> list[str]:
        return [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt",
        ]

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        for line in data.decode().splitlines():
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            cidr = line.split(";")[0].strip()
            if cidr:
                records.append(IntelRecord(
                    source="SPAMHAUS-DROP",
                    raw_text=f"Hijacked netblock: {cidr}",
                    indicators=[IOC(cidr, "cidr", severity=6.0)],  # cidr != ipv4: never queued for Shodan
                ))
        return records


class OpenPhishCollector(BaseCollector):
    """OpenPhish - live phishing URL feed (free, text)."""

    name = "OPENPHISH"
    poll_interval = 1800
    url = "https://openphish.com/feed.txt"

    def parse(self, data: bytes) -> list[IntelRecord]:
        records: list[IntelRecord] = []
        for line in data.decode().splitlines():
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            records.append(IntelRecord(
                source="OPENPHISH",
                raw_text=f"Phishing URL: {u}",
                url=u,
                indicators=[IOC(u, "url", severity=7.0)],
            ))
        return records


class AlienVaultOTXCollector(BaseCollector):
    """AlienVault OTX - subscribed threat pulses (JSON, free API key).

    Disabled unless OTX_API_KEY is set. Enrichment via /pulses/ indicators is
    extremely valuable for a CSIRT because pulses bundle IOCs + targeted CVEs.
    """

    name = "OTX"
    poll_interval = 3600
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.enabled = bool(self.settings.otx_api_key)

    async def collect_once(self) -> list[IntelRecord]:
        if not self.settings.otx_api_key:
            return []
        try:
            return await self._collect_once()
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            self.last_run_ok = False
            logger.error("%s: sync failed (%s) — will retry next cycle", self.name, exc, exc_info=True)
            return []

    async def _collect_once(self) -> list[IntelRecord]:
        headers = {"X-OTX-API-KEY": self.settings.otx_api_key}
        data = await self.fetch(self.url, headers=headers)
        doc = await asyncio.to_thread(_json_loads, data)
        records: list[IntelRecord] = []
        for pulse in doc.get("results", []):
            name = pulse.get("name", "")
            desc = pulse.get("description", "")
            text = f"OTX pulse '{name}': {desc}"
            rec = IntelRecord(source="OTX", raw_text=text, url=pulse.get("url", ""))
            for ind in pulse.get("indicators", []):
                ioc = ind.get("indicator", "")
                ind_type = ind.get("type", "").lower()
                if ioc:
                    rec.indicators.append(IOC(ioc, ind_type, severity=6.0))
            records.append(rec)
        return records

    async def run(self, stop_event: asyncio.Event) -> None:  # type: ignore[override]
        if not self.settings.otx_api_key:
            logger.info("%s: OTX_API_KEY not set, disabled", self.name)
            return
        await super().run(stop_event)


class MispCollector(BaseCollector):
    """MISP - pull events from a free self-hosted MISP instance.

    Generic JSON: you can adapt the endpoint to /attributes/restSearch later;
    the default keeps the module free and simple (recent events).
    """

    name = "MISP"
    poll_interval = 3600

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.enabled = bool(self.settings.misp_url and self.settings.misp_api_key)

    async def collect_once(self) -> list[IntelRecord]:
        if not (self.settings.misp_url and self.settings.misp_api_key):
            return []
        try:
            return await self._collect_once()
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            self.last_run_ok = False
            logger.error("%s: sync failed (%s) — will retry next cycle", self.name, exc, exc_info=True)
            return []

    async def _collect_once(self) -> list[IntelRecord]:
        url = self.settings.misp_url.rstrip("/") + "/events/index/limit:50"
        headers = {"Authorization": self.settings.misp_api_key, "Accept": "application/json"}
        data = await self.fetch(url, headers=headers)
        doc = await asyncio.to_thread(_json_loads, data)
        records: list[IntelRecord] = []
        events = doc if isinstance(doc, list) else doc.get("response", [])
        for evt in events:
            info = evt.get("Event", evt).get("info", "") if isinstance(evt, dict) else ""
            if info:
                records.append(IntelRecord(source="MISP", raw_text=info, url=url))
        return records


# ---------------------------------------------------------------------------
# Orchestrator pipeline
# ---------------------------------------------------------------------------
class ThreatIntelPipeline:
    """Owns the shared HTTP session, all collectors, and the AI worker queue."""

    def __init__(self, db: Any, settings: Settings = app_settings) -> None:
        self.db = db
        self.settings = settings
        self.session: aiohttp.ClientSession | None = None
        self.collectors: list[BaseCollector] = []
        self.ai_queue: asyncio.Queue[IntelRecord] = asyncio.Queue(maxsize=200)
        self.shodan_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
        self.stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._shodan: ShodanFreeCollector | None = None
        self._recent_ips: set[str] = set()
        #: monotonic clock of the last run per collector (drives `run_due()`).
        self._last_run: dict[str, float] = {}
        #: Serialises heavy syncs (scheduler tick vs. manual force-sync) so a
        #: full run never overlaps another full run on a cold / empty database.
        self._sync_lock = asyncio.Lock()
        #: Background force-sync bookkeeping (see start_sync / sync_status).
        self._sync_task: asyncio.Task | None = None
        self._sync_active = False
        self.last_sync: dict[str, Any] | None = None

    async def build(self) -> "ThreatIntelPipeline":
        """Create the shared session and instantiate every enabled collector."""
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": "CSIRT-CTI/1.0 (+internal)"},
            timeout=aiohttp.ClientTimeout(total=30),
        )
        try:
            return await self._build_collectors()
        except Exception:
            await self.session.close()
            raise

    async def _build_collectors(self) -> "ThreatIntelPipeline":
        fiche_cb = self._enqueue_fiche
        ioc_cb = self._enqueue_iocs

        enabled = (
            CisaCollector,
            CertFRCollector,
            CertEUCollector,
            NewsCollector,
            NvdCollector,
            UrlhausCollector,
            ThreatFoxCollector,
            FeodoTrackerCollector,
            SslblJa3Collector,
            BlocklistDeCollector,
            SpamhausDropCollector,
            OpenPhishCollector,
            AlienVaultOTXCollector,
            MispCollector,
        )
        self.collectors = [
            c(self.session, self.db, self.settings, fiche_cb=fiche_cb, ioc_cb=ioc_cb)
            for c in enabled
        ]

        if self.settings.enable_shodan_enrichment:
            self._shodan = ShodanFreeCollector(self.session, self.db, self.settings)
            self.collectors.append(self._shodan)

        dark = DarkWebCollector(self.session, self.db, self.settings)
        self.collectors.append(dark)
        logger.info("pipeline built with %d collectors", len(self.collectors))
        return self

    def _enqueue_fiche(self, record: IntelRecord) -> Awaitable[None]:
        """Callback: push a CVE-bearing record to the AI worker queue."""
        async def _push() -> None:
            try:
                self.ai_queue.put_nowait(record)
            except asyncio.QueueFull:
                logger.warning("AI queue full, dropping %s", record.cve)
        return _push()

    def _enqueue_iocs(self, iocs: list[IOC]) -> Awaitable[None]:
        """Callback: push fresh IPv4s to the Shodan enrichment queue."""
        async def _push() -> None:
            for i in iocs:
                if i.type == "ipv4" and i.indicator not in self._recent_ips:
                    self._recent_ips.add(i.indicator)
                    try:
                        self.shodan_queue.put_nowait(i.indicator)
                    except asyncio.QueueFull:
                        self._recent_ips.discard(i.indicator)
        return _push()

    # -- Shodan enrichment worker ---------------------------------------------
    async def _shodan_worker(self) -> None:
        """Consume queued IPs and enrich them via internetdb.shodan.io."""
        while not self.stop_event.is_set():
            ip = await self.shodan_queue.get()
            try:
                if self._shodan:
                    enriched = await self._shodan.enrich([ip])
                    for rec in enriched:
                        await self._shodan.store_record(rec)
            except Exception as exc:  # noqa: BLE001
                logger.debug("shodan enrich failed for %s: %s", ip, exc)
            finally:
                self.shodan_queue.task_done()

    # -- lifecycle -------------------------------------------------------------
    async def start(self) -> None:
        """Launch the AI worker, the enrichment worker and the central ingestion
        scheduler. The scheduler performs an immediate first sync (so ClickHouse
        is populated right after boot) and then re-runs each collector whenever
        its own `poll_interval` elapses (RSS ~10 min, JSON ~30 min, NVD 1 h)."""
        self._tasks.append(asyncio.create_task(self._ai_worker(), name="ai-worker"))
        if self._shodan:
            self._tasks.append(asyncio.create_task(self._shodan_worker(), name="shodan-worker"))
        self._tasks.append(asyncio.create_task(self._scheduler(), name="ingestion-scheduler"))
        logger.info("ingestion scheduler started (%d collectors, first sync immediately)",
                    len(self.collectors))

    async def _scheduler(self) -> None:
        """Central background scheduler loop.

        Every 60 s it checks which collectors are *due* (their `poll_interval`
        has elapsed since their last run) and syncs them. Any collector failure
        is caught by `run_collectors` and logged — it never kills the loop.
        """
        while not self.stop_event.is_set():
            try:
                result = await self.run_due()
                if result["collected"]:
                    logger.info("scheduler: +%d records this cycle", result["collected"])
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("ingestion scheduler error: %s", exc)
            # Tick every second in small slices so shutdown stays responsive.
            for _ in range(60):
                if self.stop_event.is_set():
                    return
                await asyncio.sleep(1)

    def _due(self) -> list[BaseCollector]:
        """Return every enabled, poll-based collector whose interval elapsed."""
        now = time.monotonic()
        due = [
            c for c in self.collectors
            if getattr(c, "enabled", True)
            and getattr(c, "poll_interval", 0) > 0
            and now - self._last_run.get(c.name, 0.0) >= c.poll_interval
        ]
        for c in due:
            self._last_run[c.name] = now
        return due

    async def run_due(self) -> dict[str, Any]:
        """Sync every collector whose poll interval has elapsed."""
        async with self._sync_lock:
            return await self.run_collectors(self._due())

    async def run_once(self) -> dict[str, Any]:
        """Force an immediate sync of ALL enabled collectors (API-triggered).

        Collectors run in parallel; a failure in one feed is logged loudly and
        does not abort the others. Returns aggregate + per-source stats.
        """
        enabled = [
            c for c in self.collectors
            if getattr(c, "enabled", True) and getattr(c, "poll_interval", 0) > 0
        ]
        now = time.monotonic()
        for c in enabled:
            self._last_run[c.name] = now
        async with self._sync_lock:
            return await self.run_collectors(enabled)

    # -- background force-sync (admin "Sync now") ----------------------------
    def start_sync(self) -> bool:
        """Launch a full sync in the background.

        Returns True when a new sync was started, False when one is already
        running (a scheduled tick or a previous force-sync). The outcome is
        stored in `self.last_sync` and surfaced through `sync_status()` so the
        frontend can poll for completion instead of blocking the HTTP request
        for the whole (slow) run. When one is already running we just watch it.
        """
        if self._sync_active or (self._sync_task is not None and not self._sync_task.done()):
            self.last_sync = {"status": "running"}
            return False
        self.last_sync = {"status": "running"}
        self._sync_task = asyncio.create_task(self._run_sync_task(), name="force-sync")
        return True

    async def _run_sync_task(self) -> None:
        try:
            result = await self.run_once()
            logger.info("force-sync finished: +%d records", result.get("collected", 0))
        except asyncio.CancelledError:
            self.last_sync = {"status": "cancelled"}
            raise
        except Exception as exc:  # noqa: BLE001
            self.last_sync = {"status": "error", "error": str(exc)}
            logger.exception("force-sync failed: %s", exc)

    def sync_status(self) -> dict[str, Any]:
        """Report whether a sync is running and the outcome of the last one."""
        running = self._sync_active or (self._sync_task is not None and not self._sync_task.done())
        return {"running": running, "last": self.last_sync}

    async def run_collectors(self, collectors: Iterable[BaseCollector]) -> dict[str, Any]:
        """Run a batch of collectors concurrently, isolating failures.

        Each collector is wrapped in its own try/except: if one feed raises
        (timeout, bad XML, rate-limit), we log a clear ERROR and continue with
        the remaining feeds instead of crashing the whole pipeline.
        """
        self._sync_active = True
        try:
            results: dict[str, dict[str, Any]] = {}

            async def _safe(c: BaseCollector) -> None:
                try:
                    records = await c.collect_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - one bad feed must not kill the sync
                    c.stats["errors"] += 1
                    results[c.name] = {"collected": 0, "errors": c.stats["errors"], "failed": True}
                    logger.exception("%s: collector crashed (%s) — continuing with other feeds", c.name, exc)
                    return
                stored = 0
                if records:
                    try:
                        stored = await c.process(records)
                    except Exception as exc:  # noqa: BLE001
                        c.stats["errors"] += 1
                        logger.exception("%s: persist failed after fetch (%s)", c.name, exc)
                results[c.name] = {"collected": stored, "errors": c.stats["errors"], "failed": False}
                if stored:
                    logger.info("%s: +%d records persisted", c.name, stored)

            await asyncio.gather(*(_safe(c) for c in collectors), return_exceptions=True)
            total = sum(r["collected"] for r in results.values())
            result = {"collected": total, "sources": results}
            self.last_sync = {"status": "finished", **result}
            return result
        finally:
            self._sync_active = False

    async def _ai_worker(self) -> None:
        """Consume the queue and generate Fiches d'Alerte (dedup handled in AI)."""
        from .ai_processor import generate_fiche_d_alerte  # lazy: heavy imports
        while not self.stop_event.is_set():
            record = await self.ai_queue.get()
            try:
                await generate_fiche_d_alerte(record.raw_text, self.db, self.settings, source=record.source)
            except Exception as exc:  # noqa: BLE001
                logger.error("AI worker failed for %s: %s", record.cve, exc, exc_info=True)
            finally:
                self.ai_queue.task_done()

    async def shutdown(self) -> None:
        """Signal all loops to stop and clean up connections."""
        self.stop_event.set()
        if self._sync_task is not None and not self._sync_task.done():
            self._sync_task.cancel()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._sync_task is not None:
            try:
                await self._sync_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self.session and not self.session.closed:
            await self.session.close()
