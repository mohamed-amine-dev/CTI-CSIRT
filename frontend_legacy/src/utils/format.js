// -----------------------------------------------------------------------------
// Formatting helpers shared across the dashboard.
// -----------------------------------------------------------------------------

/** Relative time ("3m ago") from an ISO timestamp. */
export function timeAgo(iso) {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return String(iso);
  const diff = Date.now() - then;
  const sec = Math.round(diff / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  return `${day}d ago`;
}

/** Local readable date-time. */
export function formatDate(iso, { withSeconds = false } = {}) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const opts = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
  if (withSeconds) opts.second = '2-digit';
  return d.toLocaleString(undefined, opts);
}

/** 1234 -> "1.2k", 1_200_000 -> "1.2M". */
export function compactNumber(n) {
  if (n === null || n === undefined) return '—';
  const v = Number(n);
  if (Number.isNaN(v)) return '—';
  if (Math.abs(v) >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (Math.abs(v) >= 1e3) return `${(v / 1e3).toFixed(1)}k`;
  return String(Math.round(v));
}

/** Uppercase first letter of a label ("cve" -> "Cve"). */
export function titleCase(s) {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// -----------------------------------------------------------------------------
// Severity / category visual system (high-contrast badges for dark theme).
// -----------------------------------------------------------------------------
export const SEVERITY = {
  CRITICAL: { label: 'CRITICAL', badge: 'bg-red-500/10 text-red-400 border-red-500/40', dot: 'bg-red-500', hex: '#ef4444' },
  HIGH: { label: 'HIGH', badge: 'bg-orange-500/10 text-orange-400 border-orange-500/40', dot: 'bg-orange-500', hex: '#f97316' },
  MEDIUM: { label: 'MEDIUM', badge: 'bg-amber-500/10 text-amber-400 border-amber-500/40', dot: 'bg-amber-500', hex: '#f59e0b' },
  LOW: { label: 'LOW', badge: 'bg-blue-500/10 text-blue-400 border-blue-500/40', dot: 'bg-blue-500', hex: '#3b82f6' },
  INFO: { label: 'INFO', badge: 'bg-slate-500/10 text-slate-400 border-slate-500/40', dot: 'bg-slate-500', hex: '#64748b' },
};

export const severityStyle = (label) => SEVERITY[(label || '').toUpperCase()] || SEVERITY.INFO;

/** Map a numeric 0..10 score to a severity bucket (used by IOC results). */
export function severityFromScore(score) {
  if (score >= 9) return SEVERITY.CRITICAL;
  if (score >= 7) return SEVERITY.HIGH;
  if (score >= 4) return SEVERITY.MEDIUM;
  if (score > 0) return SEVERITY.LOW;
  return SEVERITY.INFO;
}

/** Category -> colour used by charts and badges on the feeds view. */
export const CATEGORY_COLORS = {
  Ransomware: '#ef4444',
  Exploit: '#f97316',
  Malware: '#a855f7',
  Phishing: '#eab308',
  Vulnerability: '#3b82f6',
  Other: '#64748b',
};

export const categoryColor = (c) => CATEGORY_COLORS[c] || CATEGORY_COLORS.Other;

/** Approximate severity bucket for a feed category (feeds carry no own score). */
export const CATEGORY_SEVERITY = {
  Ransomware: 'CRITICAL',
  Exploit: 'HIGH',
  Malware: 'HIGH',
  Phishing: 'MEDIUM',
  Vulnerability: 'MEDIUM',
  Other: 'INFO',
};

export const categorySeverity = (c) => CATEGORY_SEVERITY[c] || 'INFO';

/** Threat Landscape taxonomy -> colour (matches app/threat_classify.py). */
export const THREAT_COLORS = {
  Ransomware: '#ef4444',
  Worm: '#84cc16',
  'Trojan/RAT': '#a855f7',
  Botnet: '#eab308',
  Infostealer: '#f97316',
  Wiper: '#dc2626',
  'Phishing Kit': '#f472b6',
  'DDoS Tool': '#06b6d4',
  'Exploit/PoC': '#3b82f6',
  Backdoor: '#8b5cf6',
  Other: '#64748b',
};

export const threatColor = (c) => THREAT_COLORS[c] || THREAT_COLORS.Other;
