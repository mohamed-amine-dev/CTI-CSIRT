import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ChevronRight } from 'lucide-react';

import { threatColor, compactNumber } from '../../utils/format';

const TOOLTIP_STYLE = {
  backgroundColor: 'rgb(var(--color-surface))',
  border: '1px solid rgb(var(--color-line))',
  borderRadius: '8px',
  color: 'rgb(var(--color-ink))',
  fontSize: '12px',
};
const AXIS = { stroke: 'rgb(var(--color-faint))', fontSize: 11 };

function TrendTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE} className="px-3 py-2 shadow-lg">
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-faint">week of {label}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-xs">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: p.stroke || p.color }} />
          <span className="text-dim">{p.name}:</span>
          <span className="font-mono text-ink">{compactNumber(p.value)}</span>
        </p>
      ))}
    </div>
  );
}

/**
 * ThreatLandscapePanel — the Threat & Malware Category Landscape.
 * Top-left: 60-day weekly-bucket stacked trend of the leading threat types.
 * Bottom:    ranked attack types; clicking one opens the /feeds view filtered
 *            to that threat category (the underlying items / IOCs).
 */
export default function ThreatLandscapePanel({ data, height = 380 }) {
  const navigate = useNavigate();

  const { chartCategories, chartData, ranked, total } = useMemo(() => {
    const weeks = data?.weeks || [];
    const trend = data?.trend || {};
    const ranked = data?.ranked || [];
    const chartCategories = ranked.slice(0, 5).map((r) => r.category);

    const chartData = weeks.map((w) => {
      const row = { week: w };
      for (const cat of chartCategories) row[cat] = trend[w]?.[cat] || 0;
      return row;
    });

    return {
      chartCategories,
      chartData,
      ranked,
      total: ranked.reduce((s, r) => s + (r.count || 0), 0),
    };
  }, [data]);

  if (!data || !ranked.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <p className="text-xs text-faint">No threat landscape data yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div style={{ height: height * 0.55 }} className="min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              {chartCategories.map((cat) => (
                <linearGradient key={cat} id={`threat-${cat}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={threatColor(cat)} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={threatColor(cat)} stopOpacity={0.03} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgb(var(--color-line))" vertical={false} />
            <XAxis dataKey="week" tick={AXIS} axisLine={false} tickLine={false} />
            <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={<TrendTooltip />} />
            {chartCategories.map((cat) => (
              <Area
                key={cat}
                type="monotone"
                dataKey={cat}
                stackId="threat"
                stroke={threatColor(cat)}
                fill={`url(#threat-${cat})`}
                strokeWidth={1.5}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <h4 className="font-mono text-[10px] uppercase tracking-wide text-faint">
            Top attack types · last 60 days
          </h4>
          <span className="font-mono text-xs text-ink">{compactNumber(total)} items</span>
        </div>
        <ul className="space-y-1">
          {ranked.slice(0, 8).map((r) => (
            <li key={r.category}>
              <button
                type="button"
                onClick={() => navigate(`/feeds?threat=${encodeURIComponent(r.category)}`)}
                className="group flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-raised/60"
              >
                <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: threatColor(r.category) }} />
                <span className="min-w-0 flex-1 truncate text-xs text-ink group-hover:text-cyan-200">
                  {r.category}
                </span>
                <span className="font-mono text-xs text-faint">{compactNumber(r.count)}</span>
                <ChevronRight size={13} className="shrink-0 text-faint transition-transform group-hover:translate-x-0.5" />
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
