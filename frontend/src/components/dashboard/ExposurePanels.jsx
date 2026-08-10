import React from 'react';
import { Network, ServerCog } from 'lucide-react';

import Card from '../ui/Card';
import { compactNumber } from '../../utils/format';

function RankedRows({ rows, primary, secondary, max = 6 }) {
  if (!rows || !rows.length) {
    return <p className="py-8 text-center text-xs text-faint">No data in this window yet.</p>;
  }
  return (
    <ul className="space-y-2.5">
      {rows.slice(0, max).map((r, i) => {
        const pct = Math.max(4, Math.round((r.count / rows[0].count) * 100));
        return (
          <li key={r[primary]} className="flex items-center gap-3">
            <span className="w-6 shrink-0 font-mono text-[10px] text-faint">{String(i + 1).padStart(2, '0')}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate font-mono text-xs text-ink">{r[primary]}</span>
                <span className="shrink-0 font-mono text-[11px] text-faint">{compactNumber(r.count)}</span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-raised">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${pct}%`, background: 'rgb(var(--color-cyan) / 0.6)' }}
                />
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** Top exposed ports & services (from Shodan InternetDB enrichment). */
export function TopPorts({ data }) {
  const ports = data?.ports || [];
  return (
    <Card title="Top Exposed Ports & Services" icon={Network} subtitle="Shodan InternetDB · 60 days">
      <RankedRows rows={ports.map((p) => ({ port: `${p.port} · ${p.service}`, count: p.count }))} primary="port" secondary="count" />
    </Card>
  );
}

/** Most frequently seen CVEs across all raw records. */
export function TopCves({ data }) {
  const cves = data?.cves || [];
  return (
    <Card title="Most Frequently Seen CVEs" icon={ServerCog} subtitle="across raw intel · 60 days">
      <RankedRows rows={cves} primary="cve" secondary="count" max={6} />
    </Card>
  );
}
