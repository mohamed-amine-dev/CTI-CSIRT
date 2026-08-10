import React from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { CATEGORY_COLORS, SEVERITY, severityStyle } from '../../utils/format';

// Shared dark-theme tooltip + axis styles so every chart matches.
const TOOLTIP_STYLE = {
  backgroundColor: 'rgb(var(--color-surface))',
  border: '1px solid rgb(var(--color-line))',
  borderRadius: '8px',
  color: 'rgb(var(--color-ink))',
  fontSize: '12px',
};
const AXIS = { stroke: 'rgb(var(--color-faint))', fontSize: 11 };

function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE} className="px-3 py-2 shadow-lg">
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-faint">{label}</p>
      {payload.map((p, i) => (
        <p key={i} className="flex items-center gap-2 text-xs">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: p.color || p.payload?.fill }} />
          <span className="text-dim">{p.name}:</span>
          <span className="font-mono text-ink">{formatter ? formatter(p.value) : p.value}</span>
        </p>
      ))}
    </div>
  );
}

/** Threat-category breakdown (donut). Data: { name, value }[]. */
export function CategoryDonut({ data, height = 260 }) {
  const total = data.reduce((s, d) => s + (d.value || 0), 0);
  return (
    <div className="flex flex-col" style={{ height }}>
      <div className="min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius="58%"
              outerRadius="85%"
              paddingAngle={2}
              stroke="rgb(var(--color-base))"
            >
              {data.map((d) => (
                <Cell key={d.name} fill={CATEGORY_COLORS[d.name] || '#64748b'} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 shrink-0 text-center font-mono text-2xl font-bold text-ink">
        {total.toLocaleString()}
      </p>
      <p className="shrink-0 pb-1 text-center text-[11px] uppercase tracking-wider text-faint">total items</p>
    </div>
  );
}

/** Daily ingestion volume (area). Data: { date, count }[]. */
export function TimelineArea({ data, height = 260 }) {
  if (!data.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <p className="text-xs text-faint">
          No ingestion data yet — run a sync or wait for the next scheduled poll.
        </p>
      </div>
    );
  }
  if (data.length < 2) {
    const only = data[0];
    return (
      <div style={{ height }} className="flex flex-col items-center justify-center gap-1.5 px-6 text-center">
        <span className="font-mono text-3xl font-bold text-cyan-300">
          {(only.count ?? 0).toLocaleString()}
        </span>
        <span className="text-xs text-dim">{only.date} · first day of ingestion</span>
        <span className="text-xs text-faint">
          The daily curve fills in automatically as new days are ingested — there is no
          history before the platform started collecting.
        </span>
      </div>
    );
  }
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="ctiVolume" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgb(var(--color-line))" vertical={false} />
          <XAxis dataKey="date" tick={AXIS} axisLine={false} tickLine={false} />
          <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} />
          <Area
            type="monotone"
            dataKey="count"
            name="Items ingested"
            stroke="#22d3ee"
            strokeWidth={2}
            fill="url(#ctiVolume)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Severity distribution (bar). Data: { name, value }[]. */
export function SeverityBar({ data, height = 260 }) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sorted = [...data].sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={sorted} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgb(var(--color-line))" vertical={false} />
          <XAxis dataKey="name" tick={{ ...AXIS, fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgb(var(--color-raised))', opacity: 0.5 }} />
          <Bar dataKey="value" name="Count" radius={[4, 4, 0, 0]} maxBarSize={60} barCategoryGap="20%">
            {sorted.map((d) => (
              <Cell key={d.name} fill={(SEVERITY[d.name] || SEVERITY.INFO).hex} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export { severityStyle };
