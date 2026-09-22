# =============================================================================
# CTI Platform - Org Exposure / Watchlist matching engine
# -----------------------------------------------------------------------------
# Deterministic matcher used BOTH by the immediate search (Step 1) and the
# saved-watchlist sweep (Steps 2-3). Every match is derived from real text in
# raw_threat_intel (dark web + telegram rows):
#
#   * domain : exact match against the already-extracted domain entities
#              (darkweb_analytics.extract_signals) PLUS a boundary regex over
#              the raw content so subdomains (mail.example.com vs example.com)
#              are caught. Never matches "notexample.com".
#   * phone  : input and candidates are normalised (strip spaces, dashes,
#              parens, dots, slashes, leading +/-country code) before any
#              comparison — raw string matching would miss almost everything.
#   * email  : case-insensitive substring (not a structured extraction).
#   * org    : case-insensitive substring/keyword.
#
# Output spans are character offsets into the ORIGINAL raw_text so the UI can
# highlight the matched term; `term` is the actual matched text (for phone it
# is the digit part found in the content). The engine is stdlib-only so a
# verification script can import it standalone and cross-check it against the
# live API without the app package.
# =============================================================================

from __future__ import annotations

import re
import time
from typing import Any

TARGET_TYPES = ("domain", "phone", "email", "org")

# Characters stripped while normalising phone numbers (formatting only).
_PHONE_SKIP = " \t()+-._/"
_MAX_SPANS_PER_MATCH = 5
_MIN_PHONE_DIGITS = 7
_MAX_PHONE_DIGITS = 15


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def normalize_domain(value: str) -> str:
    """Lowercase, strip scheme/path/query and a trailing dot."""
    s = (value or "").strip().lower()
    if "//" in s:
        s = s.split("//", 1)[1]
    for sep in "/?#":
        if sep in s:
            s = s.split(sep, 1)[0]
    return s.rstrip(".")


def domain_valid(value: str) -> bool:
    v = normalize_domain(value)
    if not v or "." not in v:
        return False
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", v))


def phone_candidates(value: str) -> list[str]:
    """Normalised digit candidates for one phone-number search value.

    The base candidate is the digits-only form. When the input carries an
    explicit country code (`+...` or `00...`) the national part is offered
    too; a long bare international-form number (11-13 digits) also gets the
    first digit dropped. Candidates are sorted longest-first so the most
    specific (most discriminatory) match wins the span.
    """
    digits = re.sub(r"[^\d]", "", value or "")
    if not digits:
        return []
    out = [digits]
    v = (value or "").strip()
    if v.startswith("+") or v.startswith("00"):
        for drop in (1, 2, 3):
            if len(digits) - drop >= _MIN_PHONE_DIGITS:
                out.append(digits[drop:])
    if 11 <= len(digits) <= 13:
        out.append(digits[1:])
    return sorted(set(out), key=len, reverse=True)


# ---------------------------------------------------------------------------
# Span finders (offsets into the ORIGINAL text)
# ---------------------------------------------------------------------------
def _find_caseless(t_low: str, v_low: str) -> list[tuple[int, int]]:
    """All case-insensitive substring spans, capped."""
    spans: list[tuple[int, int]] = []
    start = 0
    while len(spans) < _MAX_SPANS_PER_MATCH:
        i = t_low.find(v_low, start)
        if i < 0:
            break
        spans.append((i, i + len(v_low)))
        start = i + 1
    return spans


def _domain_spans_entity(t_low: str, value: str, domains: list[str]) -> list[tuple[int, int]]:
    """Exact match against the already-extracted domain entities (+ subdomains)."""
    spans: list[tuple[int, int]] = []
    for d in domains or []:
        d = (d or "").strip().lower().rstrip(".")
        if d == value or d.endswith("." + value):
            i = t_low.find(d)
            if i >= 0:
                spans.append((i, i + len(d)))
    return spans


def _domain_spans_raw(t_low: str, value: str) -> list[tuple[int, int]]:
    """Boundary regex over raw content: catches sub.example.com, not
    not-<value> and not a different domain that merely embeds the label."""
    pat = re.compile(r"(?<![a-z0-9])(?:[a-z0-9-]+\.)*" + re.escape(value) + r"(?![a-z0-9-])")
    return [(m.start(), m.end()) for m in pat.finditer(t_low)][:_MAX_SPANS_PER_MATCH]


def _phone_spans(text: str, candidates: list[str]) -> list[tuple[int, int]]:
    """Scan the compressed text for each digit candidate; map indices back."""
    kept: list[str] = []
    i_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in _PHONE_SKIP:
            continue
        kept.append(ch)
        i_map.append(i)
    comp = "".join(kept)
    out: list[tuple[int, int]] = []
    for cand in candidates:
        if not (_MIN_PHONE_DIGITS <= len(cand) <= _MAX_PHONE_DIGITS):
            continue
        idx = comp.find(cand)
        while idx != -1 and len(out) < _MAX_SPANS_PER_MATCH:
            start = i_map[idx]
            end = i_map[idx + len(cand) - 1] + 1
            if not any(start < e and s < end for (s, e) in out):  # no overlap
                out.append((start, end))
                out.sort()
            idx = comp.find(cand, idx + 1)
        if len(out) >= _MAX_SPANS_PER_MATCH:
            break
    return out


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    spans = sorted(spans)
    merged: list[tuple[int, int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged[: _MAX_SPANS_PER_MATCH]


# ---------------------------------------------------------------------------
# Public matcher
# ---------------------------------------------------------------------------
def match_item(
    text: str,
    target_type: str,
    value: str,
    domains: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return all real matches of one target inside `text`.

    Each match: {"type", "value", "term", "start", "end"} where start/end are
    offsets into `text` (for highlighting) and `term` is the actual matched
    text found in the content.
    """
    if target_type not in TARGET_TYPES:
        raise ValueError(f"target_type must be one of {TARGET_TYPES}")
    if not text or not value:
        return []
    text = text or ""
    t_low = text.lower()

    if target_type == "domain":
        value = normalize_domain(value)
        spans = _merge(
            _domain_spans_entity(t_low, value, domains or [])
            + _domain_spans_raw(t_low, value)
        )
    elif target_type == "phone":
        spans = _phone_spans(text, phone_candidates(value))
    else:  # email | org -> case-insensitive substring
        v_low = (value or "").strip().lower()
        spans = _find_caseless(t_low, v_low)

    return [
        {"type": target_type, "value": value, "term": text[s:e], "start": s, "end": e}
        for (s, e) in spans
    ]


def match_row(
    raw_text: str,
    domains: list[str],
    targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run a list of saved targets against one raw text row.

    Returns per-target match lists; a target can match zero or more spans.
    """
    out: list[dict[str, Any]] = []
    for t in targets:
        ms = match_item(raw_text, t["target_type"], t["value"],
                        domains if t["target_type"] == "domain" else None)
        if ms:
            out.append({"target_id": t.get("id"), **ms[0]})
    return out


def _utcnow_naive_timestamp() -> float:
    return time.time()