// src/pages/stream/StreamPage.tsx — Dark Web / Telegram monitoring workspace.
//
// DRPS-flavoured monitoring view. Data comes from the backend monitor endpoint
// (app/darkweb_analytics.py): every item carries a deterministic severity band
// (+ the exact keyword that fired), theme grouping, extracted signals and a
// "why it matters" briefing bound to those signals. This view ONLY aggregates
// and renders that payload — no analytic is invented client-side.
//
// Layout ("visual hierarchy"): risk strip -> KPIs -> activity + severity ->
// themes + signals -> priority items -> searchable list with per-item briefing.
import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, ListFilter, RefreshCw, Search, ShieldAlert, Sparkles } from "lucide-react";

import Button from "../../components/ui/Button";
import ErrorState from "../../components/ui/ErrorState";
import { api, errorText, unwrap } from "../../services/api";
import { Sparkline } from "./charts";
import { WINS, bucketFor, e2s } from "./series";
import type { Win } from "./series";
import {
  SEVERITY_COLORS,
  SEVERITY_ORDER,
  SEVERITY_BAND_SCORE,
  themeColor,
} from "./aggregate";

type SeverityBand = "Critical" | "High" | "Medium" | "Low";

export type Kind = "darkweb" | "telegram";

/** Load the whole stream (channels are low-volume); 500 is the API cap. */
const LIMIT = 500;

interface Row {
  f_datetime: string;
  sas: string;
  raw_text: string;
  url: string;
  title: string;
  sources: RowSource;
  briefing: RowBrief | null;
}

interface RowSource {
  domains: string[];
  urls: string[];
  ips: string[];
  onions: string[];
  handles: string[];
  emails: string[];
  cves: string[];
}

interface RowBrief {
  band: SeverityBand;
  themes: { id: string; label: string; keywords: string[] }[];
  summary: string[];
  check_next: string[];
  recency: string;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function windowRows(rows: Row[], sec: number): Row[] {
  const now = nowSec();
  const from = now - sec;
  return rows.filter((r) => {
    const e = e2s(r.f_datetime);
    return e !== null && e >= from && e <= now;
  });
}

function line(rows: Row[], sec: number, buck: number): { t: number; n: number }[] {
  const now = nowSec();
  const from = now - sec;
  const m = new Map<number, number>();
  for (const r of rows) {
    const e = e2s(r.f_datetime);
    if (e === null) continue;
    const b = Math.floor((e - from) / buck) * buck;
    m.set(b, (m.get(b) ?? 0) + 1);
  }
  const out: { t: number; n: number }[] = [];
  for (let b = 0; b < sec; b += buck) out.push({ t: from + b, n: m.get(b) ?? 0 });
  return out;
}

function srcOf(r: Row): string {
  return r.sas || "unknown";
}

const toStr = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));
const toNum = (v: unknown): number => (typeof v === "number" ? v : 0);
const toStrings = (v: unknown): string[] => (Array.isArray(v) ? v.map(toStr).filter(Boolean) : []);

/** Map one backend monitor item (app/routers/darkweb.py) onto the view rows. */
function toRow(item: Record<string, unknown>): Row {
  const a = (item.analysis ?? {}) as Record<string, unknown>;
  const sev = (a.severity ?? {}) as Record<string, unknown>;
  const themes = (a.themes ?? []) as Record<string, unknown>[];
  const sig = (a.signals ?? {}) as Record<string, unknown>;
  const brief = (a.briefing ?? {}) as Record<string, unknown> | null;
  return {
    f_datetime: toStr(item.ts),
    sas: toStr(item.source) || "unknown",
    raw_text: toStr(item.raw_text),
    url: toStr(item.url),
    title: toStr(item.title),
    sources: {
      domains: toStrings(sig.domains),
      urls: toStrings(sig.urls),
      ips: toStrings(sig.ips),
      onions: toStrings(sig.onions),
      handles: toStrings(sig.handles),
      emails: toStrings(sig.emails),
      cves: toStrings(sig.cves),
    },
    briefing: {
      band: (SEVERITY_ORDER as string[]).includes(String(sev.band))
        ? (sev.band as SeverityBand)
        : "Low",
      themes: themes.map((t) => ({
        id: toStr(t.id),
        label: toStr(t.label),
        keywords: toStrings(t.keywords),
      })),
      summary: toStrings(brief?.summary),
      check_next: toStrings(brief?.check_next),
      recency: toStr(brief?.recency),
    },
  };
}

export function StreamPage({ kind }: { kind: Kind }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState(0);
  const [win, setWin] = useState<Win>("24h");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Row | null>(null);
  const [err, setErr] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let on = true;
    const ch = kind === "telegram" ? "telegram" : "darkweb";
    unwrap(api.getDarkWebMonitor(ch, LIMIT))
      .then((body: { items?: unknown[]; total?: unknown }) => {
        if (!on) return;
        setRows(Array.isArray(body?.items) ? body.items.map(toRow) : []);
        setTotal(typeof body?.total === "number" ? body.total : 0);
        setErr("");
      })
      .catch((e: unknown) => {
        if (on) setErr(errorText(e));
      });
    return () => {
      on = false;
    };
  }, [kind, reloadKey]);

  const sec = WINS.find((w) => w.k === win)?.sec ?? 86400;
  const buck = bucketFor(win);
  const inWin = useMemo(() => windowRows(rows, sec), [rows, sec]);
  const pts = useMemo(() => line(inWin, sec, buck), [inWin, sec, buck]);
  const max = Math.max(1, ...pts.map((p) => p.n));

  // --- Analytics (pure aggregation of the backend's per-item analysis) ------
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const r of inWin) c[r.briefing?.band ?? "Low"] += 1;
    return c;
  }, [inWin]);

  const riskScore = useMemo(() => {
    if (inWin.length === 0) return 0;
    let s = 0;
    for (const r of inWin) s += SEVERITY_BAND_SCORE[r.briefing?.band ?? "Low"] ?? 0;
    return Math.round((s / inWin.length) * 10) / 10;
  }, [inWin]);

  const themes = useMemo(() => {
    const c = new Map<string, { label: string; n: number }>();
    for (const r of inWin) {
      const primary = r.briefing?.themes?.[0];
      if (!primary) continue;
      const prev = c.get(primary.id) ?? { label: primary.label, n: 0 };
      c.set(primary.id, { label: primary.label, n: prev.n + 1 });
    }
    const totalN = inWin.length || 1;
    return [...c.entries()]
      .map(([id, v]) => ({ id, ...v, share: Math.round((v.n / totalN) * 100) }))
      .sort((a, b) => b.n - a.n);
  }, [inWin]);

  const signalAgg = useMemo(() => {
    const union = (key: keyof RowSource) => {
      const seen = new Set<string>();
      const out: string[] = [];
      for (const r of inWin) for (const s of r.sources[key]) {
        const k = s.toLowerCase();
        if (!seen.has(k)) { seen.add(k); out.push(s); }
      }
      return out;
    };
    return {
      domains: union("domains"),
      urls: union("urls"),
      ips: union("ips"),
      onions: union("onions"),
      handles: union("handles"),
      emails: union("emails"),
      cves: union("cves"),
    };
  }, [inWin]);

  const signalTotal = useMemo(
    () =>
      signalAgg.domains.length + signalAgg.urls.length + signalAgg.ips.length +
      signalAgg.onions.length + signalAgg.handles.length + signalAgg.emails.length +
      signalAgg.cves.length,
    [signalAgg],
  );

  const grp = useMemo(() => {
    const c = new Map<string, number>();
    for (const r of inWin) {
      const s = srcOf(r);
      c.set(s, (c.get(s) ?? 0) + 1);
    }
    return [...c].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [inWin]);

  const priority = useMemo(
    () => inWin.filter((r) => (r.briefing?.band === "Critical" || r.briefing?.band === "High") || r.sources.cves.length > 0),
    [inWin],
  );

  const ql = q.toLowerCase();
  const flt = inWin.filter((r) =>
    ql === "" || (r.raw_text + " " + r.url).toLowerCase().includes(ql),
  );

  const btnBase =
    "rounded-lg border border-line bg-raised px-3 py-1.5 text-xs font-medium text-dim transition-colors hover:text-ink";
  const btnActive = "border-primary/40 bg-primary/15 text-primary";

  return (
    <div className="space-y-4">
      {/* Row 1 — window + refresh */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1">
          {WINS.map((w) => (
            <button key={w.k} type="button" className={`${btnBase} ${win === w.k ? btnActive : ""}`} onClick={() => setWin(w.k)}>
              {w.l}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-dim">
            <span className="font-mono font-semibold text-ink">{total}</span> rows in the source
          </span>
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => setReloadKey((k) => k + 1)}>Refresh</Button>
        </div>
      </div>

      {/* Row 2 — risk strip: severity counts + window risk score */}
      <div className="rounded-xl border border-line bg-surface p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-faint">
            <ShieldAlert size={14} className="text-primary/70" /> Window risk
          </div>
          <span className="inline-flex items-center gap-2 rounded-lg border border-line bg-base/60 px-3 py-1.5">
            <span className="text-[11px] uppercase tracking-wider text-faint">Risk score</span>
            <span className="font-mono text-lg font-bold leading-none text-ink">{riskScore.toFixed(1)}</span>
            <span className="font-mono text-[11px] text-faint">/4</span>
          </span>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {SEVERITY_ORDER.map((band) => (
            <div key={band} className="flex items-center gap-2 rounded-lg border border-line bg-raised px-3 py-2">
              <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: SEVERITY_COLORS[band] }} />
              <span className="text-xs text-dim">{band}</span>
              <span className="ml-auto font-mono text-lg font-bold leading-none text-ink">{sevCounts[band]}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Row 3 — KPI row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi label="In window" value={inWin.length} />
        <Kpi label="All rows" value={total} sub="true source total" />
        <Kpi label="Sources" value={grp.length} />
        <Kpi label="Signals found" value={signalTotal} sub="unique across window" />
      </div>

      {err && <ErrorState title="Failed to load stream" message={err} onRetry={() => setReloadKey((k) => k + 1)} />}

      {/* Row 4 — activity + severity distribution */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-5">
        <div className="rounded-xl border border-line bg-surface text-ink shadow-sm lg:col-span-3">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5">
            <Activity size={15} className="shrink-0 text-primary/80" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-ink">Activity — last {win}</h3>
            <span className="ml-auto rounded-md border border-line bg-raised px-1.5 py-px font-mono text-[10px] text-dim">
              peak {max}/bin
            </span>
          </div>
          <div className="flex h-28 w-full items-stretch p-4 text-sky-400">
            {pts.length > 1 ? (
              <Sparkline data={pts} />
            ) : (
              <div className="flex w-full items-center justify-center text-sm text-faint">Not enough points</div>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface text-ink shadow-sm lg:col-span-2">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5">
            <AlertTriangle size={15} className="shrink-0 text-primary/80" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-ink">Severity distribution</h3>
          </div>
          <div className="space-y-2.5 p-4">
            {SEVERITY_ORDER.map((band) => {
              const n = sevCounts[band];
              const share = inWin.length ? Math.round((n / inWin.length) * 100) : 0;
              return (
                <div key={band} className="flex items-center gap-2">
                  <span className="w-16 shrink-0 text-[11px] font-medium text-dim">{band}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-base">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{ width: `${share}%`, background: SEVERITY_COLORS[band] }}
                    />
                  </div>
                  <span className="w-8 shrink-0 text-right font-mono text-[11px] text-dim">{n}</span>
                </div>
              );
            })}
            <p className="pt-1 text-[11px] text-faint">
              Averaged weighted risk on the window’s items (4 = worst).
            </p>
          </div>
        </div>
      </div>

      {/* Row 5 — themes + signals */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="rounded-xl border border-line bg-surface text-ink shadow-sm">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5">
            <ListFilter size={15} className="shrink-0 text-primary/80" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-ink">Themes in window</h3>
            <span className="ml-auto rounded-md border border-line bg-raised px-1.5 py-px font-mono text-[10px] text-dim">
              primary grouping
            </span>
          </div>
          <div className="space-y-2.5 p-4">
            {themes.length === 0 ? (
              <p className="text-sm text-faint">No items in this window.</p>
            ) : (
              themes.slice(0, 6).map((t) => (
                <div key={t.id} className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: themeColor(t.id) }} />
                  <span className="w-40 min-w-0 truncate text-xs text-dim sm:w-48">{t.label}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-base">
                    <div className="h-full rounded-full" style={{ width: `${t.share}%`, background: themeColor(t.id) }} />
                  </div>
                  <span className="w-12 shrink-0 text-right font-mono text-[11px] text-dim">{t.n} · {t.share}%</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface text-ink shadow-sm">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5">
            <Sparkles size={15} className="shrink-0 text-primary/80" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-ink">Signals in text</h3>
            <span className="ml-auto rounded-md border border-line bg-raised px-1.5 py-px font-mono text-[10px] text-dim">
              extracted, not guessed
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5 p-4">
            {signalTotal === 0 ? (
              <p className="text-sm text-faint">No domains, URLs, IPs, .onion, handles or CVEs extracted in this window.</p>
            ) : (
              <>
                {signalAgg.onions.slice(0, 6).map((s) => <SigChip key={"o-" + s} label="onion" value={s} />)}
                {signalAgg.cves.slice(0, 8).map((s) => <SigChip key={"c-" + s} label="cve" value={s} />)}
                {signalAgg.ips.slice(0, 8).map((s) => <SigChip key={"i-" + s} label="ip" value={s} />)}
                {signalAgg.domains.slice(0, 10).map((s) => <SigChip key={"d-" + s} label="domain" value={s} />)}
                {signalAgg.urls.slice(0, 6).map((s) => <SigChip key={"u-" + s} label="url" value={s} />)}
                {signalAgg.handles.slice(0, 6).map((s) => <SigChip key={"h-" + s} label="handle" value={s} />)}
                {signalAgg.emails.slice(0, 6).map((s) => <SigChip key={"e-" + s} label="email" value={s} />)}
                <span className="ml-auto self-center text-[11px] text-faint">
                  {(signalAgg.domains.length + signalAgg.urls.length + signalAgg.ips.length + signalAgg.onions.length + signalAgg.handles.length + signalAgg.emails.length + signalAgg.cves.length) > 50
                    ? "showing a sample — top types only"
                    : `${signalTotal} unique in window`}
                </span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Row 6 — priority strip */}
      {priority.length > 0 && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/5 p-3.5">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="shrink-0 text-red-400" />
            <span className="text-xs font-semibold uppercase tracking-widest text-dim">
              Priority in window
            </span>
            <span className="rounded-md border border-red-500/30 bg-red-500/10 px-1.5 py-px font-mono text-[10px] font-bold text-red-400">
              {priority.length}
            </span>
            <span className="ml-auto text-[11px] text-faint">click to brief</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {priority.slice(0, 6).map((r, idx) => (
              <button
                key={`${r.f_datetime}|${idx}`}
                type="button"
                onClick={() => setSel(sel?.f_datetime === r.f_datetime && sel?.sas === r.sas ? null : r)}
                className="max-w-[320px] truncate rounded-md border border-line bg-raised px-2.5 py-1 text-xs text-ink transition-colors hover:border-red-500/40"
                title={r.raw_text}
              >
                <span
                  className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full"
                  style={{ background: SEVERITY_COLORS[r.briefing?.band ?? "Low"] }}
                />
                {r.title || r.raw_text.slice(0, 60)}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Row 7 — searchable list + per-item briefing */}
      <div className="rounded-xl border border-line bg-surface text-ink shadow-sm">
        <div className="border-b border-line px-5 py-3.5">
          <div className="relative">
            <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search raw text / url…"
              className="w-full rounded-lg border border-line bg-base py-2.5 pl-9 pr-3 text-sm text-ink placeholder:text-faint focus:border-primary focus:outline-none"
            />
          </div>
        </div>
        <div className="divide-y divide-line">
          {flt.slice(0, 60).map((r, idx) => {
            const e = e2s(r.f_datetime);
            const key = `${r.f_datetime}|${r.sas}|${idx}`;
            const active = sel?.f_datetime === r.f_datetime && sel?.sas === r.sas;
            const band = r.briefing?.band ?? "Low";
            const bThemes = r.briefing?.themes ?? [];
            const nSignals =
              r.sources.onions.length + r.sources.cves.length + r.sources.ips.length +
              r.sources.domains.length + r.sources.urls.length + r.sources.handles.length +
              r.sources.emails.length;
            return (
              <div key={key}>
                <div
                  className={`cursor-pointer px-5 py-2.5 transition-colors hover:bg-raised/60 ${active ? "bg-raised/60" : ""}`}
                  onClick={() => setSel(active ? null : r)}
                >
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_COLORS[band] }} title={band} />
                    <span className="shrink-0 font-mono text-[11px] text-faint">
                      {e === null ? "?" : new Date(e * 1000).toLocaleTimeString()}
                    </span>
                    <span className="shrink-0 truncate rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[11px] text-dim">
                      {srcOf(r)}
                    </span>
                    <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-faint">{band}</span>
                    <span className="ml-auto flex shrink-0 items-center gap-1.5">
                      {bThemes.slice(0, 2).map((t) => (
                        <span key={t.id} className="hidden items-center gap-1 rounded-full border border-line bg-raised px-2 py-0.5 text-[10px] text-dim sm:inline-flex">
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: themeColor(t.id) }} />
                          {t.label}
                        </span>
                      ))}
                      {nSignals > 0 && (
                        <span className="rounded-md border border-line bg-base/60 px-1.5 py-0.5 font-mono text-[10px] text-dim">
                          {nSignals} signal{nSignals === 1 ? "" : "s"}
                        </span>
                      )}
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-sm text-ink">{r.raw_text}</p>
                  {r.url ? (
                    <a
                      className="mt-0.5 block truncate text-xs text-primary hover:underline"
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(ev) => ev.stopPropagation()}
                    >
                      {r.url}
                    </a>
                  ) : null}
                </div>
                {active ? <WhyItMatters r={r} /> : null}
              </div>
            );
          })}
          {flt.length === 0 && (
            <div className="px-5 py-8 text-center text-sm text-faint">
              {rows.length === 0 ? "No items for this channel yet" : "No matches for this search"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, sub }: { label: string; value: number; sub?: string }) {
  return (
    <div className="rounded-xl border border-line bg-surface px-5 py-4 text-ink shadow-sm">
      <div className="text-[11px] font-semibold uppercase tracking-widest text-faint">{label}</div>
      <div className="mt-1 text-2xl font-semibold leading-none">{value}</div>
      {sub && <div className="mt-1 text-[11px] text-faint">{sub}</div>}
    </div>
  );
}

function SigChip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-1">
      <span className="font-mono text-[10px] font-bold uppercase text-primary/70">{label}</span>
      <span className="max-w-[220px] truncate font-mono text-[11px] text-dim" title={value}>{value}</span>
    </span>
  );
}

function WhyItMatters({ r }: { r: Row }) {
  const b = r.briefing;
  if (!b) return null;
  const e = e2s(r.f_datetime);
  const signals = [
    ...r.sources.cves.map((s) => ["cve", s] as const),
    ...r.sources.onions.map((s) => ["onion", s] as const),
    ...r.sources.ips.map((s) => ["ip", s] as const),
    ...r.sources.domains.map((s) => ["domain", s] as const),
    ...r.sources.urls.map((s) => ["url", s] as const),
    ...r.sources.handles.map((s) => ["handle", s] as const),
    ...r.sources.emails.map((s) => ["email", s] as const),
  ].slice(0, 12);
  return (
    <div className="border-t border-line bg-base/40 px-5 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <Sparkles size={14} className="text-primary" />
        <span className="text-xs font-semibold uppercase tracking-widest text-dim">Why it matters</span>
        <span className="rounded-md border border-line bg-raised px-2 py-0.5 text-[11px] text-dim">
          {srcOf(r)} · {e === null ? "?" : new Date(e * 1000).toLocaleString()} · {b.recency}
        </span>
        <span
          className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-1 text-[11px] font-semibold"
          style={{ color: SEVERITY_COLORS[b.band] }}
        >
          <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_COLORS[b.band] }} />
          {b.band}
        </span>
      </div>
      {b.summary.length > 0 && (
        <ul className="mt-2.5 space-y-1">
          {b.summary.map((s, i) => (
            <li key={i} className="flex gap-2 text-xs leading-relaxed text-dim">
              <span className="mt-1 shrink-0 text-primary/60">•</span>
              <span>{s}</span>
            </li>
          ))}
        </ul>
      )}
      {signals.length > 0 && (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {signals.map(([label, value]) => <SigChip key={label + value} label={label} value={value} />)}
        </div>
      )}
      <p className="mt-3 text-[11px] font-semibold uppercase tracking-widest text-faint">Suggested next steps</p>
      <ol className="mt-1.5 space-y-1">
        {b.check_next.map((c, i) => (
          <li key={i} className="flex gap-2 text-xs leading-relaxed text-dim">
            <span className="shrink-0 font-mono text-[11px] font-bold text-primary">{i + 1}.</span>
            <span>{c}</span>
          </li>
        ))}
      </ol>
      {r.url ? (
        <a className="mt-2.5 inline-block break-all text-xs text-primary hover:underline" href={r.url} target="_blank" rel="noreferrer">
          {r.url}
        </a>
      ) : null}
    </div>
  );
}