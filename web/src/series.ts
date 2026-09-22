// src/series.ts — pure time-binning helpers over f_datetime ISO strings.

export type Win = "24h" | "7d" | "30d" | "60d";
export const WINS: { k: Win; l: string; sec: number }[] = [
  { k: "24h", l: "24h", sec: 86400 },
  { k: "7d", l: "7d", sec: 86400 * 7 },
  { k: "30d", l: "30d", sec: 86400 * 30 },
  { k: "60d", l: "60d", sec: 86400 * 60 },
];

export function e2s(iso?: string): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

export function fmtT(s: number): string {
  return new Date(s * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function dayLabel(s: number): string {
  return new Date(s * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
}

/** bucket count chosen so a window yields ~48-90 dots (SVG path stays cheap). */
export function bucketFor(w: Win): number {
  return w === "24h" ? 1800 : w === "7d" ? 10800 : 86400;
}
