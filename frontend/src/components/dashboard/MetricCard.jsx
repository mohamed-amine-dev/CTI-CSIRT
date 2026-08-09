import React from 'react';
import { TrendingUp } from 'lucide-react';

import { compactNumber } from '../../utils/format';

const ACCENTS = {
  cyan: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',
  red: 'border-red-500/30 bg-red-500/10 text-red-400',
  violet: 'border-violet-500/30 bg-violet-500/10 text-violet-400',
  amber: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
};

/**
 * MetricCard — a KPI card: label, big value, optional sub-line and an icon in
 * an accent tile. Used in the top KPI row of the Executive Overview.
 */
export default function MetricCard({ label, value, sub, icon: Icon, accent = 'cyan', trend }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wider text-faint">{label}</p>
          <p className="mt-2 font-mono text-3xl font-bold text-ink">{compactNumber(value)}</p>
          {sub && <p className="mt-1 truncate text-xs text-dim">{sub}</p>}
        </div>
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border ${ACCENTS[accent] || ACCENTS.cyan}`}>
          {Icon && <Icon size={20} aria-hidden="true" />}
        </div>
      </div>
      {trend && (
        <p className="mt-3 flex items-center gap-1 text-xs font-medium text-emerald-400">
          <TrendingUp size={13} />
          {trend}
        </p>
      )}
    </div>
  );
}
