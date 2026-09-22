// src/pages/stream/aggregate.ts — shared severity/theme helpers for the
// monitoring views. Mirrors app/darkweb_analytics.py semantics.

export type SeverityBand = "Critical" | "High" | "Medium" | "Low";

export const SEVERITY_ORDER: SeverityBand[] = ["Critical", "High", "Medium", "Low"];

export const SEVERITY_COLORS: Record<SeverityBand, string> = {
  Critical: "#dc2626",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#94a3b8",
};

/** band -> numeric weight, same mapping as the backend risk score. */
export const SEVERITY_BAND_SCORE: Record<SeverityBand, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

const THEME_COLORS: Record<string, string> = {
  credential: "#f59e0b",
  ransomware: "#dc2626",
  breach: "#a855f7",
  carding: "#f43f5e",
  malware: "#8b5cf6",
  phishing: "#38bdf8",
  darkweb: "#22d3ee",
  other: "#64748b",
};

/** deterministic theme colour keyed by theme id. */
export function themeColor(id: string): string {
  return THEME_COLORS[id] ?? THEME_COLORS.other;
}