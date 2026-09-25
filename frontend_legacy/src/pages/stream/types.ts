// Types for the Dark Web monitoring stream.
//
// Mirrors app/darkweb_analytics.py: every field is derived deterministically
// from the item's own raw_text by the backend — nothing here is invented.

export type SeverityBand = "Critical" | "High" | "Medium" | "Low";

export interface SeverityReason {
  band: SeverityBand;
  label: string;
  kw: string;
}

export interface Severity {
  band: SeverityBand;
  score: number;
  reasons: SeverityReason[];
}

export interface ThemeHit {
  id: string;
  label: string;
  keywords: string[];
}

export interface Signals {
  counts: Record<string, number>;
  domains: string[];
  urls: string[];
  ips: string[];
  onions: string[];
  handles: string[];
  emails: string[];
  cves: string[];
}

export interface Briefing {
  headline: string;
  summary: string[];
  check_next: string[];
  recency: string;
}

export interface Analysis {
  severity: Severity;
  themes: ThemeHit[];
  signals: Signals;
  briefing: Briefing;
}

/** One stream row as consumed by the monitoring view. */
export interface Row {
  f_datetime: string; // backend `ts` (ISO string)
  sas: string;        // backend `source` (DARKWEB-ONION | TELEGRAM)
  raw_text: string;
  url: string;
  title: string;
  analysis?: Analysis;
}

export const SEVERITY_COLORS: Record<SeverityBand, string> = {
  Critical: "#dc2626",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#94a3b8",
};

export const SEVERITY_ORDER: SeverityBand[] = ["Critical", "High", "Medium", "Low"];

const toStr = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

/** Map one backend monitor item onto the Row shape. */
export function toRow(item: Record<string, unknown>): Row {
  return {
    f_datetime: toStr(item.ts),
    sas: toStr(item.source) || "unknown",
    raw_text: toStr(item.raw_text),
    url: toStr(item.url),
    title: toStr(item.title),
    analysis: (item.analysis as Analysis | undefined) ?? undefined,
  };
}

/** deterministic theme colour keyed by theme id. */
export function themeColor(id: string): string {
  switch (id) {
    case "credential": return "#f59e0b";
    case "ransomware": return "#dc2626";
    case "breach": return "#a855f7";
    case "carding": return "#f43f5e";
    case "malware": return "#8b5cf6";
    case "phishing": return "#38bdf8";
    case "darkweb": return "#22d3ee";
    default: return "#64748b";
  }
}