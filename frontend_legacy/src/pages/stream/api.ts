// src/api.ts — thin contract for the Dark Web / Telegram monitoring stream.
// The backend's real item shape is:
//   { source, category, url, raw_text, ts, title, summary, structured }
// Consumed via the shared service layer (services/api.js -> GET /api/v1/feeds),
// which already carries `channel` (darkweb | telegram) and a truthful `total`.
export interface Row {
  f_datetime: string; // backend `ts` (ISO string)
  sas: string;        // backend `source` (e.g. DARKWEB-ONION | TELEGRAM)
  cat: string;        // backend computed `category`
  raw_text: string;
  url: string;
  th_score: number;
  payload?: string;
}

const toStr = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

/** Map one backend feed item onto the Row shape the stream view computes with. */
export function toRow(item: Record<string, unknown>): Row {
  return {
    f_datetime: toStr(item.ts),
    sas: toStr(item.source) || "unknown",
    cat: toStr(item.category),
    raw_text: toStr(item.raw_text),
    url: toStr(item.url),
    th_score: typeof item.th_score === "number" ? item.th_score : 0,
    payload: toStr(item.structured) || undefined,
  };
}