# =============================================================================
# CTI Platform - AI engine & structured extraction (Fiche d'Alerte)
# -----------------------------------------------------------------------------
# Turns raw vulnerability text into a strictly typed "Fiche d'Alerte" using
# LangChain's `with_structured_output` against a FREE LLM backend:
#   * Groq free-tier API  (preferred: fast + free key)
#   * Ollama local model  (automatic fallback, fully offline)
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
import time
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from .config import Settings, settings as app_settings
from .db import insert_rows
from .ingestion_engine import extract_cve

logger = logging.getLogger(__name__)

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


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
def get_llm(settings: Settings = app_settings):
    """Return the configured free-tier LLM for structured extraction.

    Provider priority (see Settings.active_provider):
      1. Groq   - fast free-tier API (requires GROQ_API_KEY)
      2. Gemini - Google free tier (requires GEMINI_API_KEY, e.g. AI Studio)
      3. Ollama - local model, fully offline (always available)

    Imports are deferred so that importing this module never requires the
    (heavy) LangChain provider packages unless extraction actually runs.
    """
    provider = settings.active_provider

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
"Not specified in the advisory" rather than inventing facts."""


def _build_prompt(raw_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": f"Raw advisory text:\n\n{raw_text}"},
    ]


# ---------------------------------------------------------------------------
# Core extraction (one strict, typed LLM call)
# ---------------------------------------------------------------------------
async def _extract_fiche(raw_text: str, settings: Settings) -> FicheAlerteModel:
    """Run LangChain with_structured_output(FicheAlerteModel) once, with retry."""
    llm = get_llm(settings)
    structured = llm.with_structured_output(FicheAlerteModel)  # provider-native JSON schema

    last_error: Exception | None = None
    for attempt in range(3):  # bounded retries on validation failure
        try:
            result = await structured.ainvoke(_build_prompt(raw_text))
            # function_calling mode returns the instance; json_mode returns a dict.
            if isinstance(result, FicheAlerteModel):
                return result
            return FicheAlerteModel.model_validate(result)
        except (ValidationError, ValueError) as exc:
            last_error = exc
            logger.warning("LLM output failed validation (attempt %d): %s", attempt + 1, exc)
            await asyncio.sleep(1.5)
    raise RuntimeError(f"LLM structured extraction failed after 3 attempts: {last_error}")


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
) -> FicheAlerteModel | dict[str, Any] | None:
    """Main entry point: raw text -> structured Fiche d'Alerte, with dedup.

    Returns:
      * a `FicheAlerteModel` when a new fiche was generated,
      * a `dict` describing the deduplicated update (existing CVE, score bumped),
      * `None` when the text contains no CVE identifier.
    """
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
    try:
        fiche = await _extract_fiche(raw_text, settings)
    except Exception as exc:  # noqa: BLE001
        logger.error("fiche generation failed for %s: %s", cve, exc)
        return None

    # Ground truth wins: if the model hallucinated a different CVE, keep the one
    # that was actually extracted from the raw advisory text.
    if fiche.vuln_cve != cve:
        logger.warning("LLM returned %s, correcting to %s", fiche.vuln_cve, cve)
        fiche.vuln_cve = cve

    await _insert_fiche(db, settings, fiche, threat_score=1.0)
    logger.info("new fiche generated for %s (score 1.0)", cve)
    return fiche
