import { useEffect, useMemo, useState } from "react";
import type { Row } from "./api";

declare const __API_OSS__: string;

export type Kind = "darkweb" | "telegram";

const WINS: { k: string; l: string }[] = [
  { k: "24h", l: "24h" },
  { k: "7d", l: "7d" },
  { k: "30d", l: "30d" },
  { k: "60d", l: "60d" },
];

const CATS: { id: string; accent: string }[] = [
  { id: "malware", accent: "#f43f5e" },
  { id: "ransomware", accent: "#dc2626" },
  { id: "cred", accent: "#f59e0b" },
  { id: "exploit", accent: "#fb923c" },
];

function e2s(iso?: string): number | null {
  if (!iso) return null;
  const n = Date.parse(iso);
  return Number.isFinite(n) ? Math.floor(n / 1000) : null;
}

function srcOf(r: Row): string {
  return r.sas || "unknown";
}

function windowRows(rows: Row[], sec: number): Row[] {
  const now = Math.floor(Date.now() / 1000);
  const from = now - sec;
  return rows.filter((r) => {
    const e = e2s(r.f_datetime);
    return e !== null && e >= from && e <= now;
  });
}

function line(rows: Row[], sec: number, buck: number) {
  const now = Math.floor(Date.now() / 1000);
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

export function StreamPage({ kind }: { kind: Kind }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [win, setWin] = useState("24h");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Row | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let on = true;
    const ch = kind === "telegram" ? "telegram" : "darkweb";
    fetch(`/api/v1/feeds?channel=${ch}`, { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))))
      .then((d) => {
        if (on) setRows(Array.isArray(d) ? d : []);
      })
      .catch((e) => {
        if (on) setErr(String(e));
      });
    return () => {
      on = false;
    };
  }, [kind]);

  const sec = win === "24h" ? 86400 : win === "7d" ? 86400 * 7 : win === "30d" ? 86400 * 30 : 86400 * 60;
  const buck = win === "24h" ? 1800 : win === "7d" ? 10800 : 86400;
  const inWin = useMemo(() => windowRows(rows, sec), [rows, sec]);
  const pts = useMemo(() => line(inWin, sec, buck), [inWin, sec, buck]);
  const max = Math.max(1, ...pts.map((p) => p.n));

  const grp = useMemo(() => {
    const c = new Map<string, number>();
    for (const r of inWin) {
      const s = srcOf(r);
      c.set(s, (c.get(s) ?? 0) + 1);
    }
    return [...c].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [inWin]);

  const cats = useMemo(() => {
    const c = new Map<string, number>();
    for (const r of inWin) {
      const cx = r.cat || e2s(r.f_datetime) === null ? "other" : String(r.cat || "other");
      c.set(CATS.find((x) => x.id === cx) ? cx : "other", (c.get(cx) ?? 0) + 1);
    }
    return [...c].sort((a, b) => b[1] - a[1]);
  }, [inWin]);

  const ql = q.toLowerCase();
  const flt = inWin.filter((r) => (ql === "" || (r.raw_text + " " + r.url).toLowerCase().includes(ql)));

  return (
    <div className="mx-auto max-w-6xl space-y-3">
      <div>
        {WINS.map((w) => (
          <button key={w.k} className={`btn ${win === w.k ? "on" : ""}`} onClick={() => setWin(w.k)}>
            {w.l}
          </button>
        ))}
      </div>
      <div className="grid grid-cols-4 gap-3">
        <Kpi label="In window" v={inWin.length} />
        <Kpi label="All rows" v={rows.length} />
        <Kpi label="Sources" v={grp.length} />
        <Kpi label="Peak bin" v={max} />
      </div>
      {err && <div className="card text-sm text-rose-300">load error: {err}</div>}
      <div className="card">
        <div className="mb-1 text-xs uppercase text-slate-400">Activity</div>
        <svg viewBox="0 0 560 110" className="h-28 w-full text-sky-400" preserveAspectRatio="none">
          {pts.length > 1 && (
            <polyline
              points={pts.map((p, i) => `${(i / (pts.length - 1)) * 560},${110 - 8 - (p.n / max) * 88}`).join(" ")}
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
          )}
        </svg>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {grp.map(([s, n]) => (
          <div key={s} className="card flex items-center justify-between">
            <span className="text-sm">{s}</span>
            <span className="text-lg font-semibold">{n}</span>
          </div>
        ))}
      </div>
      <div className="card">
        <input
          className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none"
          placeholder="Search raw text / urlâ€¦"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <table className="list mt-3 w-full">
          <tbody>
            {flt.slice(0, 40).map((r) => (
              <tr key={r.f_datetime} className="cursor-pointer hover:bg-slate-800/60" onClick={() => setSel(sel?.f_datetime === r.f_datetime ? null : r)}>
                <td className="text-slate-400">{e2s(r.f_datetime) === null ? "?" : new Date(e2s(r.f_datetime)! * 1000).toLocaleTimeString()}</td>
                <td>{srcOf(r)}</td>
                <td className="max-w-[52ch] truncate">{r.raw_text}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {sel ? <RowDetail r={sel} /> : null}
      </div>
    </div>
  );
}

function Kpi({ label, v }: { label: string; v: number }) {
  return (
    <div className="card">
      <div className="text-xs uppercase text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{v}</div>
    </div>
  );
}

function RowDetail({ r }: { r: Row }) {
  return (
    <div className="mt-3 rounded-lg border border-slate-700 bg-slate-900 p-3 text-sm">
      <div className="text-slate-400">{srcOf(r)} Â· {e2s(r.f_datetime) === null ? "?" : new Date(e2s(r.f_datetime)! * 1000).toLocaleString()}</div>
      <p className="mt-1">{r.raw_text}</p>
      {r.url ? (
        <a className="mt-1 block break-all text-xs text-sky-400" href={r.url} target="_blank" rel="noreferrer">
          {r.url}
        </a>
      ) : null}
    </div>
  );
}
