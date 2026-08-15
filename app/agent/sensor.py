# =============================================================================
# CTI Platform - Agent sensor layer (Uber ADR-inspired)
# -----------------------------------------------------------------------------
# The first node of the triage graph is the "sensor": before any LLM or tool
# touches the input, we inspect it for adversarial content and control
# characters. This is the ADR Observability + Detection idea applied to our
# agent:
#
#   * sanitize_text()          - strip control characters, bound length
#   * detect_prompt_injection() - deterministic heuristic scan (returns reasons)
#   * trace_step() / append_trace() - structured execution trace for
#                                     observability / audit / telemetry
#
# The detection is deliberately conservative and rule-based: it only flags
# well-known instruction-override / role-escape / credential-exfiltration
# phrasing and raw control characters. It is a heuristic, not a guarantee —
# the trace records exactly what was detected so an analyst can review it.
# =============================================================================

from __future__ import annotations

import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

# Maximum length of context we will ever forward to tools/LLM.
MAX_CONTEXT_CHARS = 8000

# Control characters that are never legitimate in a threat snippet (NUL, ESC,
# other C0, DEL). Tab/newline/CR are allowed.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Token delimiters used by chat-template / system-role injection tricks.
_ANTHROPIC_TOKENS = (
    "<|im_start|>", "<|im_end|>", "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>",
    "<system>", "</system>", "<s>", "</s>",
)

# Deterministic prompt-injection heuristics. Each entry is (label, regex).
# Matching is done case-insensitively on the sanitised (control-stripped)
# lowercase text. Labels are what end up in the execution trace.
_INJECTION_RULES: tuple[tuple[str, str], ...] = (
    # --- instruction override -------------------------------------------------
    ("instruction-override", r"ignore (all|any|the|your)? ?(previous|prior|above|earlier)? ?instructions"),
    ("instruction-override", r"disregard (all|the|any|your)? ?(previous|prior|above)? ?(instructions|prompts)"),
    ("instruction-override", r"forget (all|the|your)? ?(previous|prior|above)? ?instructions"),
    ("instruction-override", r"override (your|the)? ?(instructions|system prompt|prompt)"),
    ("instruction-override", r"don'?t (follow|obey) (your|the) (instructions|rules)"),
    ("instruction-override", r"do not (follow|obey) (your|the) (instructions|rules)"),
    ("instruction-override", r"ignore the rules"),
    ("instruction-override", r"pretend (you|the model) (never|didn'?t)"),
    # --- role escape / jailbreak ----------------------------------------------
    ("role-escape", r"you are now (a|an|the)? ?(\w+ ){0,4}(assistant|model|agent|gpt|claude)"),
    ("role-escape", r"act as (a|an)? ?(different|new)? ?(ai|assistant|model|bot|agent)"),
    ("role-escape", r"jailbreak"),
    ("role-escape", r"dan mode"),
    ("role-escape", r"developer mode"),
    ("role-escape", r"no restrictions"),
    ("role-escape", r"without (any )?restrictions"),
    ("role-escape", r"unrestricted mode"),
    ("role-escape", r"do anything now"),
    ("role-escape", r"you can do anything"),
    ("role-escape", r"simulate (a|an) (different|new|unrestricted)"),
    # --- prompt / system-exfiltration ------------------------------------------
    ("system-exfil", r"(print|show|reveal|repeat|display|output) your (system )?prompt"),
    ("system-exfil", r"(print|show|reveal|repeat|display|output) your instructions"),
    ("system-exfil", r"what (are|is) your (system )?(prompt|instructions|rules)"),
    ("system-exfil", r"what is your initial prompt"),
    ("system-exfil", r"system prompt:"),
    ("system-exfil", r"developer message"),
    # --- structured prompt-injection markers -----------------------------------
    ("delimiter-injection", re.escape("<|im_start|>")),
    ("delimiter-injection", re.escape("<|im_end|>")),
    ("delimiter-injection", re.escape("[INST]")),
    ("delimiter-injection", re.escape("<<SYS>>")),
)

# A long base64-ish blob is a weak signal of an encoded payload dump.
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{80,}")


def sanitize_text(text: str | None) -> str:
    """Return a bounded, control-character-free copy of the raw context.

    This is the input that every downstream node receives. Stripping C0
    control characters prevents terminal/token-smuggling tricks; the length
    cap bounds the context an LLM is asked to parse.
    """
    if not text:
        return ""
    cleaned = _CTRL_RE.sub("", text)
    if len(cleaned) > MAX_CONTEXT_CHARS:
        cleaned = cleaned[:MAX_CONTEXT_CHARS]
    return cleaned


def detect_prompt_injection(text: str | None) -> list[str]:
    """Deterministic scan for prompt-injection / suspicious input.

    Returns a list of detection labels; an empty list means "no signal found".
    The scan runs on the sanitised (control-stripped) text so raw escape
    sequences can't hide phrasing from the regexes.
    """
    if not text:
        return []
    clean = _CTRL_RE.sub("", text)
    lower = clean.lower()
    reasons: list[str] = []

    if _ANTHROPIC_TOKENS and any(tok.lower() in lower for tok in _ANTHROPIC_TOKENS):
        reasons.append("delimiter-injection")

    for label, pattern in _INJECTION_RULES:
        if re.search(pattern, lower):
            if label not in reasons:
                reasons.append(label)

    if _BASE64_BLOB_RE.search(lower):
        reasons.append("encoded-blob")

    # Tab/newline-heavy text is a common way to smuggle a second instruction.
    if clean.count("\n") > 40 and len(clean) > 500:
        reasons.append("excessive-newlines")

    return reasons


# ---------------------------------------------------------------------------
# Execution trace (ADR Observability)
# ---------------------------------------------------------------------------
def trace_step(
    node: str,
    action: str,
    inputs: Any,
    outputs: Any,
    note: str = "",
) -> dict[str, Any]:
    """Build one immutable trace record for a graph step.

    `inputs` / `outputs` should be JSON-safe primitives (strings, numbers,
    lists, dicts) so the whole trace can be stored/exported without
    serialisation surprises.
    """
    return {
        "node": node,
        "action": action,
        "inputs": inputs,
        "outputs": outputs,
        "note": note,
        "ts": int(time.time() * 1_000_000),  # microsecond epoch (matches DB version)
    }


def append_trace(state: dict[str, Any], step: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a new execution_trace list with `step` appended (immutable style)."""
    return list(state.get("execution_trace") or []) + [step]
