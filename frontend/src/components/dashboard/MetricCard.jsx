import React, { useId } from 'react';
import { TrendingDown, TrendingUp } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer } from 'recharts';
import { cn } from '../../lib/utils';
import { compactNumber } from '../../utils/format';

const ACCENT_META = {
  blue:   { tile: 'bg-primary/10 text-primary border-primary/20',         hex: '#4F8EF7' },
  red:    { tile: 'bg-red-500/10 text-red-400 border-red-500/20',         hex: '#ef4444' },
  violet: { tile: 'bg-violet-500/10 text-violet-400 border-violet-500/20', hex: '#a855f7' },
  amber:  { tile: 'bg-amber-500/10 text-amber-400 border-amber-500/20',   hex: '#f59e0b' },
  // legacy alias
  cyan:   { tile: 'bg-primary/10 text-primary border-primary/20',         hex: '#4F8EF7' },
};

/**
 * MetricCard — professional KPI card with optional sparkline + delta chip.
 */
export default function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  accent = 'blue',
  delta = null,
  spark = [],
  trend,
}) {
  const meta = ACCENT_META[accent] || ACCENT_META.blue;
  const gradId = useId().replace(/[:]/g, '');

  const sparkData = (spark || []).map((v, i) => ({ i, v: Number(v) || 0 }));
  const hasSpark = sparkData.length > 0;

  const deltaPct =
    typeof delta === 'object' && delta !== null
      ? Number(delta.pct)
      : typeof delta === 'number'
        ? delta
        : null;
  const deltaGood =
    typeof delta === 'object' && delta !== null
      ? Boolean(delta.good)
      : (deltaPct ?? 0) >= 0;
  const hasDelta =
    deltaPct !== null && !Number.isNaN(deltaPct) && delta !== undefined;

  return (
    <div className="relative flex flex-col overflow-hidden rounded-xl border border-line bg-surface shadow-sm transition-all duration-150 hover:border-primary/30 hover:shadow-md">
      <div className="flex items-start justify-between gap-3 p-5 pb-4">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-semibold uppercase tracking-widest text-faint">
            {label}
          </p>
          <p className="mt-2 text-3xl font-bold text-ink tabular-nums">
            {compactNumber(value)}
            {hasDelta && (
              <span
                className={cn(
                  'ml-2 inline-flex items-center gap-0.5 align-middle font-mono text-xs font-semibold',
                  deltaGood ? 'text-emerald-400' : 'text-red-400',
                )}
              >
                {deltaGood ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
                {deltaPct >= 0 ? '+' : ''}
                {deltaPct.toFixed(1)}%
              </span>
            )}
          </p>
          {sub && (
            <p className="mt-1 truncate text-xs text-faint">{sub}</p>
          )}
          {!hasDelta && trend && (
            <p className="mt-2 flex items-center gap-1 text-xs font-medium text-emerald-400">
              <TrendingUp size={12} />
              {trend}
            </p>
          )}
        </div>

        {/* Icon tile */}
        <div
          className={cn(
            'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border',
            meta.tile,
          )}
        >
          {Icon && <Icon size={18} aria-hidden="true" />}
        </div>
      </div>

      {/* Sparkline flush to card bottom */}
      {hasSpark && (
        <div className="pointer-events-none h-12 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={sparkData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id={`spark-${gradId}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={meta.hex} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={meta.hex} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke={meta.hex}
                strokeWidth={1.5}
                fill={`url(#spark-${gradId})`}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}