// src/api.ts — REAL client against the live-verified Phase-1 endpoints.
// Only endpoints that returned HTTP 200 with a real JSON array are used.
export interface Row {
  f_datetime: string;
  th_score: number;
  raw_text: string;
  sas: string; // source agg → "DARKWEB-ONION" | "TELEGRAM"
  cat: string; // threat_category real value
  url: string;
  payload: string;
}
