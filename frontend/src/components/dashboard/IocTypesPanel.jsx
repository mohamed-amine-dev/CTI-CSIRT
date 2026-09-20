import React from 'react';
import { Fingerprint } from 'lucide-react';
import Card from '../ui/Card';
import { compactNumber } from '../../utils/format';

// Professional, less saturated colors that work well on dark backgrounds
const TYPE_META = {
  ipv4:   { color: '#4F8EF7', label: 'IPv4' },
  ipv6:   { color: '#60A5FA', label: 'IPv6' },
  domain: { color: '#A78BFA', label: 'Domain' },
  hash:   { color: '#F59E0B', label: 'Hash' },
  url:    { color: '#34D399', label: 'URL' },
  cve:    { color: '#F87171', label: 'CVE' },
  email:  { color: '#FB923C', label: 'Email' },
  ja3:    { color: '#E879F9', label: 'JA3' },
};

/**
 * IocTypesPanel — indicator corpus split by type, proportional horizontal bars.
 */
export default function IocTypesPanel({ byType = {} }) {
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, n]) => s + n, 0);
  const max = entries.length ? entries[0][1] : 1;

  return (
    <Card title="Indicator Corpus by Type" icon={Fingerprint} subtitle="processed_iocs · live">
      {!entries.length ? (
        <div className="flex items-center justify-center py-8">
          <p className="text-sm text-faint">No indicators ingested yet.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {entries.slice(0, 7).map(([type, n]) => {
            const meta = TYPE_META[type] || { color: '#64748b', label: type.toUpperCase() };
            const pct = Math.max(4, Math.round((n / max) * 100));
            const sharePct = Math.round((n / total) * 100);
            return (
              <div key={type}>
                <div className="mb-1.5 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className="h-2 w-2 rounded-full shrink-0"
                      style={{ background: meta.color }}
                    />
                    <span className="text-xs font-medium text-dim uppercase tracking-wide">
                      {meta.label}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px]">
                    <span className="font-mono font-semibold text-ink tabular-nums">
                      {compactNumber(n)}
                    </span>
                    <span className="text-faint">{sharePct}%</span>
                  </div>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-raised">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${pct}%`, backgroundColor: meta.color }}
                  />
                </div>
              </div>
            );
          })}
          <p className="pt-1 text-right text-[11px] text-faint">
            {compactNumber(total)} total indicators
          </p>
        </div>
      )}
    </Card>
  );
}