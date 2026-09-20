// -----------------------------------------------------------------------------
// MITRE ATT&CK tactic visual system (Threat Actors module).
// Keys are the canonical enterprise phase_name slugs; colors are distinct hues
// so kill-chain chips / charts stay scannable on the dark theme.
// -----------------------------------------------------------------------------

export const TACTIC_COLORS = {
  reconnaissance: '#38bdf8',
  'resource-development': '#818cf8',
  'initial-access': '#f472b6',
  execution: '#fb923c',
  persistence: '#fbbf24',
  'privilege-escalation': '#f97316',
  'defense-evasion': '#a78bfa',
  'credential-access': '#eab308',
  discovery: '#34d399',
  'lateral-movement': '#f87171',
  collection: '#2dd4bf',
  'command-and-control': '#c084fc',
  exfiltration: '#60a5fa',
  impact: '#ef4444',
};

const FALLBACK = '#64748b'; // slate — unmapped / unknown

export function tacticColor(tactic) {
  if (!tactic) return FALLBACK;
  const slug = String(tactic).trim().toLowerCase().replace(/\s+/g, '-');
  return TACTIC_COLORS[slug] || FALLBACK;
}

/** Human label fallback for raw phase names ("command-and-control" -> "Command and Control"). */
export function tacticLabel(tactic) {
  if (!tactic || tactic === 'unknown') return 'Unmapped';
  return String(tactic)
    .trim()
    .toLowerCase()
    .replace(/-/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}