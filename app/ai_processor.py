# =============================================================================
# CTI Platform - AI engine & structured extraction (Fiche d'Alerte)
# -----------------------------------------------------------------------------
# Turns raw vulnerability text into a strictly typed "Fiche d'Alerte" using
# LangChain's `with_structured_output` against a FREE LLM backend:
#   * Ollama local model  (primary in `auto` mode: health-checked every call)
#   * Gemini free-tier    (automatic failover when Ollama is unreachable)
#   * Groq free-tier      (available via LLM_PROVIDER=groq if a key is set)
#
# Engine choice is logged per generated report (event=fiche_generated engine=…).
# Every provider call is retried with backoff; if all engines fail the CVE is
# left without a fiche (never fabricated) so the UI can surface a pending state.
#
# The output schema (`FicheAlerteModel`) mirrors the supervisor's 4-point
# template EXACTLY and is enforced by Pydantic v2:
#   1. environmental_impact  -> is the environment affected? (versions/modules)
#   2. risk_level            -> severity + exploitability paths + compromise impact
#   3. exploitation_status   -> is a public exploit/PoC available & under what conditions
#   4. remediation_solutions -> patch + hardening + isolation + access restriction
# Plus the CVE identifier and a concise analyst-ready ai_summary.
#
# Deduplication rule (see ADR 0002):
#   * If the CVE already exists in vulnerability_alerts, we do NOT burn another
#     LLM call. We re-insert the full row with threat_score + 1; the
#     ReplacingMergeTree collapses the key back to one row (latest wins).
#   * Only genuinely new CVEs trigger an extraction call.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from .config import Settings, settings as app_settings
from .db import insert_rows
from .ingestion_engine import extract_cve

logger = logging.getLogger(__name__)

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ---------------------------------------------------------------------------
# Deterministic severity (Bug: all-CRITICAL wall)
# ---------------------------------------------------------------------------
# The Fiche risk_level is the only thing feeding the dashboard severity chart.
# When a real CVSS base score exists for the CVE, the LLM's free-form risk pick
# is overridden with this fixed bucket — a local model that reflexively answers
# "CRITICAL" can no longer skew the whole dashboard. Applied per-item from the
# actual score; a score is only trusted when it is > 1.0, because 1.0 is the
# `processed_iocs` DEFAULT that collectors write when no score was parsed.
def _cvss_to_risk(score: float) -> RiskLevel:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


async def _fetch_cvss_score(db: Any, settings: Settings, cve: str) -> float | None:
    """Look up the real CVSS base score for `cve` from the processed IOC store.

    The dedup key is (type, indicator), so multiple sightings of the same CVE
    collapse via ReplacingMergeTree; max() over FINAL is used to dodge the 1.0
    DEFAULT rows that regex extraction inserts for the same CVE.
    """
    rows = await db.query(
        """
        SELECT max(severity)
        FROM {db:Identifier}.processed_iocs FINAL
        WHERE type = 'cve' AND indicator = {cve:String}
        """,
        parameters={"db": settings.clickhouse_database, "cve": cve},
    )
    score = rows.result_rows[0][0] if rows.result_rows else None
    if score is None or float(score) <= 1.0:  # 1.0 = "no real score parsed"
        return None
    return float(score)


# ---------------------------------------------------------------------------
# Language guard (Bug: French fiches)
# ---------------------------------------------------------------------------
# Cheap heuristic used to detect a model that ignored the English-only rule:
# French diacritics (é à ç ...) or distinctive French function words. Advisory
# languages in this pipeline are essentially French (CERT-FR) and English, so
# the signal is reliable enough to justify a bounded Gemini re-run.
_FR_STOPWORDS = (
    "les", "des", "dans", "avec", "pour", "une", "sur", "afin", "notamment",
    "cette", "entre", "être", "lorsque", "sont", "composant", "vulnérabilité",
    "déjà", "exploitation", "contre-mesure", "mesures",
)
_FR_ACCENTS = "éèàçâêîôûùïë"


def _contains_french(fiche: FicheAlerteModel) -> bool:
    """True when the extracted fiche text looks French (model ignored the rule)."""
    parts: list[str] = []
    text = fiche.environmental_impact.model_dump_json() + " " + fiche.risk_level.model_dump_json()
    text += " " + fiche.exploitation_status.model_dump_json()
    text += " " + fiche.remediation_solutions.model_dump_json() + " " + (fiche.ai_summary or "")
    lower = text.lower()
    accents = sum(1 for ch in lower if ch in _FR_ACCENTS)
    words = set(re.findall(r"[a-zà-ÿ]+", lower))
    stopword_hits = sum(1 for w in _FR_STOPWORDS if w in words)
    return accents >= 3 or stopword_hits >= 2


# ---------------------------------------------------------------------------
# Strict Pydantic schema (the "Fiche d'Alerte" contract)
# ---------------------------------------------------------------------------
class EnvironmentalImpact(BaseModel):
    """Point 1 of the supervisor template: is OUR environment affected?"""

    affected_versions: list[str] = Field(
        description="List of affected software versions / modules taken from the advisory."
    )
    check_procedure: str = Field(
        description="Concrete, step-by-step procedure for an analyst to verify whether the "
        "local environment is impacted (version comparison commands, registry/package checks)."
    )
    evidence: str = Field(
        description="Evidence found in the raw advisory supporting the impact assessment."
    )


class RiskAssessment(BaseModel):
    """Point 2 of the supervisor template: risk level + exploit paths + impact."""

    risk_level: RiskLevel = Field(description="Overall risk level of the vulnerability.")
    exploit_paths: list[str] = Field(
        description="Concrete attack vectors / paths that could be exploited in a real environment."
    )
    compromise_impact: str = Field(
        description="Impact on confidentiality, integrity and availability in case of compromise."
    )


class ExploitationStatus(BaseModel):
    """Point 3 of the supervisor template: public exploit / PoC availability."""

    public_poc_available: bool = Field(
        description="Whether a public proof-of-concept or exploit code is available."
    )
    poc_url: str | None = Field(
        default=None, description="Link to the PoC / exploit if public."
    )
    conditions: str = Field(
        description="Conditions under which the exploit is usable (auth required, special "
        "configuration, default creds, etc.) and any mitigations that block it."
    )


class RemediationPlan(BaseModel):
    """Point 4 of the supervisor template: comprehensive remediation."""

    patch: str = Field(
        description="Official patch / upgrade to a fixed version, with version numbers."
    )
    hardening: str = Field(
        description="Hardening measures (WAF rules, SIGSEGV hardening, memory protections, "
        "compiler flags, feature disabling) that reduce exploitability."
    )
    isolation: str = Field(
        description="Network isolation / micro-segmentation / sandboxing measures."
    )
    access_restriction: str = Field(
        description="Access restriction measures (principle of least privilege, network ACLs, "
        "authentication requirements)."
    )


class FicheAlerteModel(BaseModel):
    """The complete Fiche d'Alerte. Field names map 1:1 to the
    `vulnerability_alerts` table columns (the supervisor's contract)."""

    vuln_cve: str = Field(description="CVE identifier, e.g. CVE-2024-3400.")
    environmental_impact: EnvironmentalImpact
    # Serialized as JSON into the DB `risk_level` column: the scalar enum
    # (for SQL filtering) plus exploit_paths and compromise_impact (for the UI).
    risk_level: RiskAssessment
    exploitation_status: ExploitationStatus
    remediation_solutions: RemediationPlan
    ai_summary: str = Field(
        description="One concise paragraph (max ~200 words) summarising the fiche for "
        "non-specialist stakeholders."
    )


# ---------------------------------------------------------------------------
# LLM provider resolution (zero-cost rule)
# ---------------------------------------------------------------------------
# Global free-tier throttle: a single in-process limiter that spaces EVERY LLM
# call by `ai_min_interval_seconds`, so a burst of new CVEs (e.g. a cold KEV
# sync) can never 429 the free Gemini tier or swamp a local Ollama.
_ai_throttle_lock = asyncio.Lock()
_last_llm_call_ts = 0.0


async def _throttle_llm(settings: Settings) -> None:
    """Space provider calls globally; the retry loop calls this per attempt."""
    global _last_llm_call_ts
    async with _ai_throttle_lock:
        wait = settings.ai_min_interval_seconds - (time.monotonic() - _last_llm_call_ts)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_llm_call_ts = time.monotonic()


# Ollama health-probe result is cached briefly (TTL 30s) so a 1,600-CVE cold
# sync does not open a fresh 2s-timeout HTTP session for every single CVE.
_ollama_cache_ts = 0.0
_ollama_cache_result = False


async def _ollama_healthy(settings: Settings, ttl: float = 30.0) -> bool:
    """Short-timeout health probe of the local Ollama server, cached for `ttl`.

    Called *before every* Fiche d'Alerte generation when the provider is
    `auto`: if Ollama is down (or times out in 2s), we fail over to Gemini and
    log which engine actually produced the report.
    """
    global _ollama_cache_ts, _ollama_cache_result
    if time.monotonic() - _ollama_cache_ts < ttl:
        return _ollama_cache_result
    import aiohttp
    url = settings.ollama_base_url.rstrip("/") + "/api/tags"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as sess:
            async with sess.get(url) as resp:
                _ollama_cache_result = resp.status < 400
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        _ollama_cache_result = False
    _ollama_cache_ts = time.monotonic()
    return _ollama_cache_result


async def _engine_candidates(settings: Settings) -> list[str]:
    """Ordered list of providers to try for a single fiche generation.

    Explicit `LLM_PROVIDER` wins and is used alone (no silent fallback).
    In `auto` mode, per the operating directive: prefer the local Ollama when it
    answers the health probe, otherwise fail over to Gemini when a key exists.
    """
    if settings.llm_provider != "auto":
        return [settings.llm_provider]
    if await _ollama_healthy(settings):
        return ["ollama", "gemini"] if settings.gemini_api_key else ["ollama"]
    if settings.gemini_api_key:
        logger.warning("Ollama unreachable at %s — failing over to Gemini", settings.ollama_base_url)
        return ["gemini"]
    return ["ollama"]


def get_llm(settings: Settings = app_settings, engine: str | None = None):
    """Return the configured free-tier LLM for structured extraction.

    `engine` overrides the auto resolution when supplied (e.g. the health-checked
    candidate from `_engine_candidates`). Imports are deferred so that importing
    this module never requires the (heavy) LangChain provider packages unless
    extraction actually runs.
    """
    provider = engine or settings.active_provider

    if provider == "groq":
        from langchain_groq import ChatGroq  # free-tier provider

        logger.info("using Groq (%s)", settings.groq_model)
        return ChatGroq(model=settings.groq_model, api_key=settings.groq_api_key, temperature=0)

    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        logger.info("using Gemini (%s)", settings.gemini_model)
        return ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0,
        )

    from langchain_ollama import ChatOllama  # local fallback

    logger.info("using Ollama (%s @ %s)", settings.ollama_model, settings.ollama_base_url)
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0,
    )


# ---------------------------------------------------------------------------
# Prompt engineering: keep the model anchored on the 4-point template
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are a senior CSIRT vulnerability analyst. Produce a strictly structured \
Fiche d'Alerte for the raw advisory text provided. Follow this EXACT 4-point template:

1. Environmental impact: determine whether an environment is affected (list the affected versions \
and modules from the advisory, and give a concrete analyst check procedure).
2. Risk level: assign CRITICAL/HIGH/MEDIUM/LOW/INFO, list exploitability paths, and describe the \
compromise impact on confidentiality/integrity/availability.
3. Exploitation status: state whether a public PoC/exploit is available, give the URL if any, and the \
conditions under which it is usable.
4. Remediation: give not only the patch but also hardening, isolation and access-restriction measures.

Only fill fields that are supported by evidence in the raw text. For missing information, write \
"Not specified in the advisory" rather than inventing facts.

LANGUAGE RULE (mandatory): Answer entirely in English. Every field — the check procedure, exploit \
paths, compromise impact, remediation, and the summary — must be written in English. Even when the \
raw advisory is in French or another language (for example a CERT-FR bulletin, or a German NVD \
description), translate the content into English. Never write a field in French, German, Spanish or \
any other language, and never paste untranslated quotes from a foreign-language advisory."""


def _build_prompt(raw_text: str, cvss_score: float | None = None) -> list[dict[str, str]]:
    score_note = ""
    if cvss_score is not None:
        score_note = (
            f"\nKnown CVSS base score for this CVE: {cvss_score:.1f}.\n"
            "Anchor your risk level to this score (9.0+ CRITICAL, 7.0-8.9 HIGH, "
            "4.0-6.9 MEDIUM, 0.1-3.9 LOW, 0.0 INFO) and write the exploit paths / "
            "impact consistently with it."
        )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": f"Raw advisory text:\n\n{raw_text}{score_note}"},
    ]


# ---------------------------------------------------------------------------
# Core extraction (one strict, typed LLM call with engine fallback + backoff)
# ---------------------------------------------------------------------------
async def _invoke_engine(
    engine: str,
    raw_text: str,
    settings: Settings,
    attempt: int,
    cvss_score: float | None = None,
) -> FicheAlerteModel:
    """One typed extraction attempt against a single provider."""
    llm = get_llm(settings, engine)
    structured = llm.with_structured_output(FicheAlerteModel)  # provider-native JSON schema
    try:
        # Hard per-engine timeout so a stuck model (e.g. Ollama busy on another
        # inference) fails over to the next engine instead of hanging the queue.
        result = await asyncio.wait_for(
            structured.ainvoke(_build_prompt(raw_text, cvss_score)),
            timeout=settings.ai_engine_timeout_seconds,
        )
        # function_calling mode returns the instance; json_mode returns a dict.
        if isinstance(result, FicheAlerteModel):
            return result
        return FicheAlerteModel.model_validate(result)
    except Exception as exc:  # noqa: BLE001 - any provider error is retried below
        logger.warning("engine=%s attempt=%d failed: %s", engine, attempt, exc)
        raise


async def _extract_fiche(
    raw_text: str,
    settings: Settings,
    cvss_score: float | None = None,
) -> tuple[FicheAlerteModel, str]:
    """Run strict structured extraction, retrying each engine with backoff and
    falling over to the next engine (Ollama <-> Gemini) on persistent failure.

    Returns `(fiche, engine)` so the caller can log which engine produced it.
    """
    engines = await _engine_candidates(settings)
    last_error: Exception | None = None

    for engine in engines:
        for attempt in range(1, 4):  # bounded retries per engine (backoff)
            await _throttle_llm(settings)  # global free-tier rate limiter
            try:
                fiche = await _invoke_engine(engine, raw_text, settings, attempt, cvss_score)
                # Language recovery: a local model can finish inside the timeout
                # while still producing French. Re-run once through Gemini (which
                # honours the English-only rule) instead of persisting the junk.
                if _contains_french(fiche) and engine != "gemini" and settings.gemini_api_key:
                    logger.warning(
                        "engine=%s produced a French fiche — recovering via Gemini", engine)
                    await _throttle_llm(settings)
                    fiche = await _invoke_engine("gemini", raw_text, settings, 1, cvss_score)
                    engine = "gemini"
                return fiche, engine
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt < 3:
                    # Exponential backoff with jitter: 1.5s, 3s (up to 6s for
                    # a repeated 429/5xx). Long enough to ride out a free-tier
                    # rate window, short enough to stay responsive.
                    await asyncio.sleep(min(30.0, 1.5 * (2 ** (attempt - 1))) * (0.8 + 0.4 * ((time.time() * 7) % 1)))

    raise RuntimeError(f"LLM structured extraction failed on all engines: {last_error}")


# ---------------------------------------------------------------------------
# Deduplication + persistence
# ---------------------------------------------------------------------------
async def _fetch_existing(
    db: Any, settings: Settings, cve: str
) -> dict[str, Any] | None:
    """Return the current row for `cve` (with FINAL to apply ReplacingMergeTree)
    or None when the CVE has never been seen before."""
    rows = await db.query(
        """
        SELECT vuln_cve, environmental_impact, risk_level, exploitation_status,
               remediation_solutions, ai_summary, threat_score
        FROM {db:Identifier}.vulnerability_alerts FINAL
        WHERE vuln_cve = {cve:String}
        LIMIT 1
        """,
        parameters={"db": settings.clickhouse_database, "cve": cve},
    )
    if not rows.result_rows:
        return None
    r = rows.result_rows[0]
    return {
        "vuln_cve": r[0],
        "environmental_impact": r[1],
        "risk_level": r[2],
        "exploitation_status": r[3],
        "remediation_solutions": r[4],
        "ai_summary": r[5],
        "threat_score": r[6],
    }


async def _insert_fiche(
    db: Any,
    settings: Settings,
    fiche: FicheAlerteModel,
    *,
    threat_score: float = 1.0,
) -> None:
    """Insert (or re-insert) a fiche row. Re-inserting the same CVE with a
    higher threat_score is how ReplacingMergeTree implements 'update in place'."""
    now = int(time.time() * 1_000_000)
    await insert_rows(
        db,
        "vulnerability_alerts",
        [[
            fiche.vuln_cve,
            fiche.environmental_impact.model_dump_json(),  # column: JSON string
            fiche.risk_level.model_dump_json(),            # column: JSON string (severity+paths+impact)
            fiche.exploitation_status.model_dump_json(),   # column: JSON string
            fiche.remediation_solutions.model_dump_json(), # column: JSON string
            fiche.ai_summary,
            threat_score,
            now,                                           # version (microsecond epoch)
        ]],
        [
            "vuln_cve", "environmental_impact", "risk_level", "exploitation_status",
            "remediation_solutions", "ai_summary", "threat_score", "version",
        ],
    )


async def _upsert_score(db: Any, settings: Settings, existing: dict[str, Any]) -> float:
    """Re-insert an existing CVE with threat_score + 1 (no LLM call burned)."""
    new_score = float(existing["threat_score"]) + 1.0
    # Rebuild the model so persistence logic is shared. The content columns are
    # preserved verbatim; only the score (and the ReplacingMergeTree version)
    # change. This prevents the merge from collapsing into an empty row.
    fiche = FicheAlerteModel(
        vuln_cve=existing["vuln_cve"],
        environmental_impact=EnvironmentalImpact.model_validate_json(existing["environmental_impact"]),
        risk_level=RiskAssessment.model_validate_json(existing["risk_level"]),
        exploitation_status=ExploitationStatus.model_validate_json(existing["exploitation_status"]),
        remediation_solutions=RemediationPlan.model_validate_json(existing["remediation_solutions"]),
        ai_summary=existing["ai_summary"],
    )
    await _insert_fiche(db, settings, fiche, threat_score=new_score)
    return new_score


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def generate_fiche_d_alerte(
    raw_text: str,
    db: Any = None,
    settings: Settings = app_settings,
    *,
    source: str = "UNKNOWN",
    cve: str | None = None,
    cvss_score: float | None = None,
) -> FicheAlerteModel | dict[str, Any] | None:
    """Main entry point: raw text -> structured Fiche d'Alerte, with dedup.

    Args:
        raw_text: the advisory text the fiche is extracted from.
        cve: an optional explicit CVE identifier. When supplied and valid it is
             used instead of scanning `raw_text` (lets the UI pass the CVE it
             already detected in a feed item).
        cvss_score: an optional known CVSS base score. When omitted, it is
             looked up from `processed_iocs`; if a real score exists it
             deterministically overrides the model's risk_level bucket.

    Returns:
      * a `FicheAlerteModel` when a new fiche was generated,
      * a `dict` describing the deduplicated update (existing CVE, score bumped),
      * `None` when the text contains no CVE identifier.
    """
    if cve is not None and re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve.strip(), re.IGNORECASE):
        cve = cve.strip().upper()
    else:
        cve = None
    if cve is None:
        cve = extract_cve(raw_text)
    if not cve:
        logger.debug("no CVE in %s record, skipping fiche", source)
        return None

    # Lazy import keeps the module importable without a live DB handle.
    if db is None:
        from .db import get_async_client
        db = await get_async_client()

    existing = await _fetch_existing(db, settings, cve)
    if existing is not None:
        # --- DEDUPLICATION PATH --------------------------------------------
        new_score = await _upsert_score(db, settings, existing)
        logger.info("CVE %s already known (score %.0f -> %.0f), skipping LLM call",
                    cve, existing["threat_score"], new_score)
        return {
            "deduplicated": True,
            "cve": cve,
            "threat_score": new_score,
            "source": source,
        }

    # --- GENERATION PATH -----------------------------------------------------
    if cvss_score is None:
        cvss_score = await _fetch_cvss_score(db, settings, cve)
    try:
        fiche, engine = await _extract_fiche(raw_text, settings, cvss_score)
    except Exception as exc:  # noqa: BLE001
        logger.error("fiche generation failed for %s: %s", cve, exc)
        return None

    # Ground truth wins: if the model hallucinated a different CVE, keep the one
    # that was actually extracted from the raw advisory text.
    if fiche.vuln_cve != cve:
        logger.warning("LLM returned %s, correcting to %s", fiche.vuln_cve, cve)
        fiche.vuln_cve = cve

    # Deterministic severity wins over the free-form model pick: the dashboard
    # chart is only as honest as the risk_level bucket, so a real CVSS score is
    # mapped through the fixed thresholds instead of trusting the model.
    if cvss_score is not None:
        bucket = _cvss_to_risk(cvss_score)
        if fiche.risk_level.risk_level != bucket:
            logger.info(
                "CVE %s: override risk %s -> %s (CVSS %.1f)",
                cve, fiche.risk_level.risk_level, bucket, cvss_score)
        fiche.risk_level.risk_level = bucket

    await _insert_fiche(db, settings, fiche, threat_score=1.0)
    logger.info("event=fiche_generated engine=%s cve=%s source=%s", engine, cve, source)
    return fiche
