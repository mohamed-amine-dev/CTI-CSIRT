# =============================================================================
# CTI Platform - threat category -> MITRE ATT&CK tactic mapping (Threat
# Landscape "By Technique" heatmap)
# -----------------------------------------------------------------------------
# EXPLICIT mapping table owned by the analysts (from the project brief).
# Mapping is deliberate and NEVER guessed: any category absent from
# CATEGORY_TO_TACTICS (or the literal "Other") falls into the "Unclassified"
# column so the heatmap never fabricates an attribution.
#
# Tactics follow the MITRE ATT&CK tactic ordering (rev ~v15), with
# "Unclassified" appended as the always-present last column.
# =============================================================================

from __future__ import annotations

#: Analyst-approved mapping (verbatim from the brief).
CATEGORY_TO_TACTICS: dict[str, list[str]] = {
    "Ransomware": ["Impact"],
    "Worm": ["Lateral Movement", "Initial Access"],
    "Phishing Kit": ["Initial Access"],
    "Botnet": ["Command and Control"],
    "Infostealer": ["Credential Access", "Collection"],
    "Wiper": ["Impact"],
    "Backdoor": ["Persistence"],
    "DDoS Tool": ["Impact"],
    "Exploit/PoC": ["Initial Access", "Execution"],
    # "Other" is intentionally NOT mapped -> Unclassified column.
}

#: Display order of the tactics grid columns (MITRE order).
TACTIC_ORDER: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unclassified",
]


def map_category(category: str | None) -> list[str]:
    """Tactics for a category; empty/unknown -> ["Unclassified"] (never guessed)."""
    return CATEGORY_TO_TACTICS.get(category or "", ["Unclassified"])
