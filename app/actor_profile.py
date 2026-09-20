from __future__ import annotations

import re

# =============================================================================
# Deterministic threat-actor profile extraction (Brief #4, Phase 1)
# -----------------------------------------------------------------------------
# Everything here is derived EXCLUSIVELY from the text MITRE ATT&CK actually
# publishes in each intrusion-set description. No field is invented: when a
# description does not name a motivation, origin, sector or country, the field
# is left empty / "unknown". That honesty is the whole point — an "unknown"
# is real signal that the primary source never said.
#
# The token sets below mirror the vocabulary ATT&CK uses (verified against the
# real enterprise-attack dataset), e.g. "Russian state-sponsored",
# "financially motivated group", "aviation and energy industries".
#
# Tokens are deliberately conservative: only terms that reliably indicate a
# sector / country / motivation are kept, so the extraction trades a little
# recall for a low false-positive rate. All matches are word-boundary, so
# "media" never fires inside "beMediate" and "spy" never fires inside "spyware".
# =============================================================================

# ---- Matching helpers (plural/suffix tolerant, word-boundary) ----------------
def _variants(token: str) -> list[str]:
    """Inflection variants of a token so ATT&CK prose like "governments",
    "industries" and "universities" still matches their singular keys."""
    t = token.lower()
    out = [t, f"{t}s", f"{t}es"]
    if len(t) > 3 and t.endswith("y"):
        out.append(f"{t[:-1]}ies")
    return out


_TOKEN_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _token_re(token: str) -> re.Pattern[str]:
    cached = _TOKEN_RE_CACHE.get(token)
    if cached is not None:
        return cached
    # Hyphen/space-insensitive comparison: "financially-motivated" and
    # "financially motivated" (or "state-sponsored"/"state sponsored") are the
    # same token to us.
    norm = " ".join(token.lower().replace("-", " ").split())
    alts = "|".join(re.escape(v) for v in _variants(norm))
    pat = re.compile(rf"(?<![a-z])(?:{alts})(?![a-z])")
    _TOKEN_RE_CACHE[token] = pat
    return pat


def _has_token(low: str, token: str) -> bool:
    low_norm = " ".join(low.replace("-", " ").split())
    return _token_re(token).search(low_norm) is not None


def _matched_tokens(low: str, tokens) -> list[str]:
    return [t for t in tokens if _has_token(low, t)]


# ---- Primary motivation ------------------------------------------------------
# Ordered by how ATT&CK writers lead a description; ties resolve to the first
# category with the highest keyword score.
_MOTIVATION_TYPES: list[tuple[str, tuple[str, ...]]] = [
    (
        "espionage",
        (
            "espionage",
            "cyber espionage",
            "spy on",
            "spying",
            "steal information",
            "stealing information",
            "theft of information",
            "collect intelligence",
            "gathering intelligence",
            "intelligence gathering",
            "intelligence collection",
            "intelligence gathering operations",
            "exfiltrate",
            "gain intelligence",
            "acquire intelligence",
            "theft of classified",
        ),
    ),
    (
        "financial",
        (
            "financially motivated",
            "financial gain",
            "financial motives",
            "for financial",
            "theft of funds",
            "theft of money",
            "steal money",
            "stealing money",
            "monetary",
            "extort",
            "extortion",
            "extortion schemes",
            "ransomware",
            "fraud",
            "fraudulent",
            "payment card",
            "credit card",
            "initial access broker",
            "sell stolen",
            "money",
            "profit-driven",
            "profit motive",
            "profit motivated",
        ),
    ),
    (
        "destructive",
        (
            "wiper",
            "wipers",
            "destructive",
            "destructive attacks",
            "sabotage",
            "disruption",
            "disrupting",
            "disruptive",
            "disrupt",
            "disruption of",
            "denial of service",
            "denial-of-service",
            "damage to",
            "defacement",
            "impact operations",
            "destruction",
        ),
    ),
    (
        "hacktivism",
        (
            "hacktivist",
            "hacktivism",
            "ideological",
            "ideology",
            "politically motivated",
            "protest movement",
            "activism",
            "political activism",
            "civil society",
        ),
    ),
]


def _motivation(text: str) -> str:
    low = text.lower()
    best_mot = "unknown"
    best_score = 0
    for mot, tokens in _MOTIVATION_TYPES:
        score = len(_matched_tokens(low, tokens))
        if score > best_score:
            best_score = score
            best_mot = mot
    return best_mot if best_score > 0 else "unknown"


# ---- Origin attribution (country) -------------------------------------------
# BROAD country name map — includes noun forms ("russia", "iran") and extra
# countries that only ever appear as *targets*. This feeds target_countries and
# the assistant's country facet. It is deliberately broader than origin detection.
_ATTRIBUTION: list[tuple[str, tuple[str, ...]]] = [
    ("Russia", (
        "russia", "russian", "moscow", "kremlin", "gru", "fsb", "svr",
        "main intelligence directorate", "general staff",
    )),
    ("China", (
        "china", "chinese", "beijing", "pla", "ministry of state security",
        "state security", "people's liberation", "peoples liberation",
    )),
    ("Iran", (
        "iran", "iranian", "tehran", "revolutionary guard", "irgc",
        "ministry of intelligence",
    )),
    ("North Korea", (
        "north korea", "north korean", "dprk", "pyongyang",
        "reconnaissance general bureau",
    )),
    ("Pakistan", ("pakistan", "pakistani", "islamabad")),
    ("India", ("india", "indian", "new delhi")),
    ("Lebanon", ("lebanon", "lebanese", "beirut", "hezbollah")),
    ("Vietnam", ("vietnam", "vietnamese", "hanoi")),
    ("Palestine", (
        "palestinian", "palestine", "hamas", "martyrs", "gaza",
    )),
    ("Turkey", ("turkey", "turkish", "ankara")),
    ("Syria", ("syria", "syrian", "damascus")),
    ("Georgia", ("georgia", "georgian", "tbilisi")),
    ("Saudi Arabia", ("saudi", "riyadh")),
    ("UAE", ("united arab emirates", "uae", "dubai", "abu dhabi")),
    ("Egypt", ("egypt", "egyptian", "cairo")),
    ("United Kingdom", ("united kingdom", "u.k.", "british", "london")),
    ("France", ("france", "french", "paris")),
    ("Germany", ("germany", "german", "berlin")),
    ("United States", (
        "united states", "u.s.", "u.s. government", "u.s. department", "us-",
    )),
    ("Czech Republic", ("czech", "prague")),
    ("Ukraine", ("ukraine", "ukrainian", "kyiv")),
    ("Belarus", ("belarus", "belarusian")),
    ("Moldova", ("moldova", "moldovan", "chisinau")),
    ("Israel", ("israel", "israeli", "tel aviv")),
    ("Italy", ("italy", "italian", "rome")),
    ("Spain", ("spain", "spanish", "madrid")),
    ("Portugal", ("portugal", "portuguese", "lisbon")),
    ("Netherlands", ("netherlands", "dutch", "amsterdam")),
    ("Poland", ("poland", "polish", "warsaw")),
    ("Sweden", ("sweden", "swedish", "stockholm")),
    ("Belgium", ("belgium", "belgian", "brussels")),
    ("Austria", ("austria", "austrian", "vienna")),
    ("Switzerland", ("switzerland", "swiss", "zurich")),
    ("Japan", ("japan", "japanese", "tokyo")),
    ("South Korea", ("south korea", "south korean", "seoul")),
    ("Australia", ("australia", "australian", "canberra")),
    ("Canada", ("canada", "canadian", "ottawa")),
    ("Brazil", ("brazil", "brazilian", "são paulo", "sao paulo")),
    ("Mexico", ("mexico", "mexican", "mexico city")),
    ("Chile", ("chile", "chilean")),
    ("Argentina", ("argentina", "argentine", "buenos aires")),
    ("Singapore", ("singapore", "singaporean")),
    ("Malaysia", ("malaysia", "malaysian")),
    ("Indonesia", ("indonesia", "indonesian", "jakarta")),
    ("Philippines", ("philippines", "filipino", "manila")),
    ("Thailand", ("thailand", "thai", "bangkok")),
    ("South Africa", ("south africa", "south african", "johannesburg")),
    ("Nigeria", ("nigeria", "nigerian", "lagos")),
    # Non-state / regional framings are deliberately NOT mapped to a country
    # ("Middle East", "South Asia") — we only claim a country when one is named.
]

# STRICT origin markers — demonyms and explicit attribution phrases only. These
# are what a description says about WHERE the group is from ("Iranian",
# "Russian state-sponsored", "based in China", "assessed to operate on behalf
# of Iran's MOIS"). Bare country nouns ("in the United States") are targets, not
# origins, and deliberately do not appear here.
_ORIGIN: list[tuple[str, tuple[str, ...]]] = [
    ("Iran", (
        "iranian", "iran-based", "based in iran", "iranian-state-sponsored",
        "iranian sponsored", "iran's ministry", "iran's government",
        "government of iran", "on behalf of iran", "affiliated with iran",
        "operate on behalf of iran", "iranian nexus", "operating out of iran",
        "suspected iranian", "iran-backed",
    )),
    ("Russia", (
        "russian", "russia-based", "based in russia", "russian-state-sponsored",
        "russian state-sponsored", "russian-speaking", "russia's general staff",
        "government of russia", "in support of the russian", "federation",
        "associated with russia", "operations in support of russian",
    )),
    ("China", (
        "chinese", "china-based", "based in china", "china-aligned", "chinese-state",
        "said to be based in china", "suspected chinese", "chinese-speaking",
    )),
    ("North Korea", (
        "north korean", "north korea-based", "dprk", "reconnaissance general bureau",
        "based in north korea", "north korea-aligned", "in support of north korea",
    )),
    ("Lebanon", ("lebanese", "lebanon-based", "based in lebanon")),
    ("Pakistan", ("pakistani", "pakistan-based")),
    ("India", ("indian", "india-based")),
    ("Vietnam", ("vietnamese", "vietnam-based")),
    ("Palestine", ("palestinian",)),
    ("Turkey", ("turkish", "turkey-based")),
    ("Syria", ("syrian",)),
    ("Georgia", ("georgian",)),
    ("Saudi Arabia", ("saudi",)),
    ("UAE", ("based in the uae", "uae-based")),
    ("Egypt", ("egyptian",)),
    ("United Kingdom", ("british", "united kingdom-based", "based in the uk")),
    ("France", ("french", "france-based")),
    ("Germany", ("german", "germany-based")),
    ("United States", ("u.s. government", "u.s.-based", "based in the united states")),
    ("Czech Republic", ("czech",)),
    ("Ukraine", ("ukrainian",)),
    ("Belarus", ("belarusian",)),
    ("Israel", ("israeli", "israel-based")),
]


# ---- Target Sectors ----------------------------------------------------------
# Conservative, specific tokens. Generic words that appear constantly in
# ATT&CK prose regardless of sector ("software", "infrastructure", "media",
# "technology") are only used inside explicit multi-word phrases.
_SECTOR_MAP: list[tuple[str, tuple[str, ...]]] = [
    ("Energy", (
        "energy sector", "energy industry", "energy companies", "energy organizations",
        "oil and gas", "oil and gas sector", "petroleum", "oil sector",
        "power grid", "electric grid", "electrical grid", "utilities sector",
        "utility companies", "electricity", "nuclear",
    )),
    ("Aviation & Aerospace", (
        "aviation", "aerospace", "aerospace and defense", "airlines", "airline industry",
        "aircraft", "flight",
    )),
    ("Government", (
        "government", "governmental", "public sector", "government institutions",
        "government networks", "government departments", "government agencies",
        "state institutions", "ministries",
    )),
    ("Defense & Military", (
        "military", "defense contractors", "defense industry", "defence industry",
        "defense and aerospace", "armed forces", "ministry of defense",
        "ministry of defence", "national security agencies",
    )),
    ("Financial Services", (
        "financial", "finance", "banking", "banks", "banking sector", "financial sector",
        "financial services", "fintech", "brokerage", "credit unions", "payment card",
        "payments industry", "remittance",
    )),
    ("Retail & Hospitality", (
        "retail", "hospitality", "restaurant", "restaurants", "hotels", "hotel",
        "food and beverage", "e-commerce", "ecommerce",
    )),
    ("Healthcare", (
        "healthcare", "health care", "medical", "pharmaceutical", "pharmaceuticals",
        "pharma", "hospitals", "biotech", "health sector",
    )),
    ("Media & Journalism", (
        "news", "news media", "journalism", "journalists", "press", "broadcast media",
        "publishing", "newspapers",
    )),
    ("Education & Research", (
        "education", "universities", "university", "academic", "academia",
        "think tanks", "research institutions", "research centers", "laboratories",
        "scientific",
    )),
    ("Technology", (
        "technology companies", "technology sector", "tech companies", "semiconductor",
        "chip manufacturers", "chipmakers", "data centers", "cloud providers",
        "telecommunication", "telecoms", "telecom operators", "mobile operators",
    )),
    ("Industrial & Critical Infrastructure", (
        "critical infrastructure", "industrial", "industrial control", "manufacturing",
        "manufacturers", "chemical", "chemical sector", "automotive", "water sector",
        "water treatment", "ics", "scada", "industrial control systems",
    )),
    ("Shipping, Maritime & Logistics", (
        "shipping", "shipping industry", "maritime", "logistics", "logistics companies",
        "ports", "transportation", "container shipping", "cargo",
    )),
    ("Mining", ("mining", "mineral")),
    ("Legal & Professional Services", (
        "legal", "law firms", "law firm", "attorney", "accounting",
    )),
    ("Non-profit & Activism", (
        "non-profit", "nonprofit", "human rights", "ngos", "activist", "activists",
        "non-governmental",
    )),
    ("Religious Organizations", (
        "religious", "church", "mosque", "faith-based",
    )),
    ("Gaming & Gambling", (
        "gaming", "gambling", "casinos", "casino", "video game",
    )),
]


def _sectors(text: str) -> list[str]:
    low = text.lower()
    found: list[str] = []
    for canonical, tokens in _SECTOR_MAP:
        for token in tokens:
            if _has_token(low, token):
                found.append(canonical)
                break
    return found


def _countries(text: str) -> list[str]:
    low = text.lower()
    found: list[str] = []
    for canonical, tokens in _ATTRIBUTION:
        for token in tokens:
            if _has_token(low, token):
                found.append(canonical)
                break
    return found


# ---- Public API --------------------------------------------------------------

MOTIVATION_LABELS: tuple[str, ...] = tuple(m for m, _ in _MOTIVATION_TYPES)
SECTOR_LABELS: list[str] = [s for s, _ in _SECTOR_MAP]


def profile_from_description(description: str | None) -> dict[str, object]:
    """Extract a structured, description-grounded actor profile.

    Returns:
        {
          "motivation":       str                  (or "unknown"),
          "attribution":      str                  (originating country, or ""),
          "target_sectors":   list[str],
          "target_countries": list[str],
          "sourced_from":     "MITRE ATT&CK intrusion-set description",
        }
    """
    text = " ".join((description or "").split())
    if not text:
        return {
            "motivation": "unknown",
            "attribution": "",
            "target_sectors": [],
            "target_countries": [],
        }
    attribution = _attribute(text)
    countries = _countries(text)
    # An explicitly named origin is *not* also a "target country" — remove it so
    # the two fields stay cleanly separated (same country can still be listed as
    # a target elsewhere in the description, e.g. domestic espionage).
    if attribution in countries:
        countries.remove(attribution)
    return {
        "motivation": _motivation(text),
        "attribution": attribution,
        "target_sectors": _sectors(text),
        "target_countries": countries,
    }


def _attribute(text: str) -> str:
    """Origin country, matched ONLY from strict origin markers (demonyms and
    explicit attribution phrases) — bare country nouns are targets, not origin."""
    low = text.lower()
    for canonical, tokens in _ORIGIN:
        for token in tokens:
            if _has_token(low, token):
                return canonical
    return ""


def detect_facet(query: str) -> tuple[str, str] | None:
    """Classify a user query as a sector / country / motivation facet, exact
    value drawn from the canonical vocabulary. Returns (kind, value) or None.

    Used by the assistant to answer "which actors target <sector/country>"
    strictly from the stored structured columns — never from speculation."""
    low = query.lower()
    for kind, table in (
        ("sector", _SECTOR_MAP),
        ("country", _ATTRIBUTION),
        ("motivation", _MOTIVATION_TYPES),
    ):
        for canonical, tokens in table:
            if _matched_tokens(low, tokens):
                return kind, canonical
    return None