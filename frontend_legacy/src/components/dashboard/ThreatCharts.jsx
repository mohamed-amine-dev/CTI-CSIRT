import React from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { CATEGORY_COLORS, SEVERITY, compactNumber, severityStyle } from '../../utils/format';

// ---------------------------------------------------------------------------
// Shared chart styles — professional enterprise dark theme
// ---------------------------------------------------------------------------
const TOOLTIP_STYLE = {
  backgroundColor: 'rgb(22 27 42)',        // --color-surface
  border: '1px solid rgb(37 46 68)',        // --color-line
  borderRadius: '8px',
  color: 'rgb(241 245 249)',               // --color-ink
  fontSize: '12px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
  padding: '10px 12px',
};
const AXIS = { stroke: 'rgb(71 85 105)', fontSize: 11 }; // --color-faint
const GRID_COLOR = 'rgb(37 46 68)';                       // --color-line

// ---------------------------------------------------------------------------
// Custom tooltip
// ---------------------------------------------------------------------------
function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE}>
      {label && (
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-faint">
          {label}
        </p>
      )}
      {payload.map((p, i) => (
        <p key={i} className="flex items-center gap-2 text-[12px]">
          <span
            className="inline-block h-2 w-2 rounded-full flex-shrink-0"
            style={{ background: p.color || p.payload?.fill }}
          />
          <span className="text-dim">{p.name}:</span>
          <span className="ml-auto font-mono font-semibold text-ink">
            {formatter ? formatter(p.value) : p.value.toLocaleString()}
          </span>
        </p>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CategoryDonut — threat category breakdown
// ---------------------------------------------------------------------------
export function CategoryDonut({ data, height = 280 }) {
  const sorted = [...data].sort((a, b) => b.value - a.value);
  const total = sorted.reduce((s, d) => s + (d.value || 0), 0);
  const legend = sorted.slice(0, 7);

  if (!data.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <p className="text-xs text-faint">No category data yet.</p>
      </div>
    );
  }

  return (
    <div className="flex" style={{ height }}>
      {/* Donut */}
      <div className="relative min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={sorted}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius="58%"
              outerRadius="84%"
              paddingAngle={2}
              stroke="none"
            >
              {sorted.map((d) => (
                <Cell key={d.name} fill={CATEGORY_COLORS[d.name] || '#475569'} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        {/* Center total */}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-ink tabular-nums">
            {compactNumber(total)}
          </span>
          <span className="text-[10px] uppercase tracking-widest text-faint">total</span>
        </div>
      </div>

      {/* Legend */}
      <ul className="w-40 shrink-0 space-y-2 pl-3 py-2">
        {legend.map((d) => (
          <li key={d.name} className="flex items-center gap-2 text-[11px]">
            <span
              className="h-2 w-2 shrink-0 rounded-full"
              style={{ background: CATEGORY_COLORS[d.name] || '#475569' }}
            />
            <span className="min-w-0 flex-1 truncate text-dim">{d.name}</span>
            <span className="font-mono font-semibold text-ink tabular-nums">
              {compactNumber(d.value)}
            </span>
          </li>
        ))}
        {sorted.length > legend.length && (
          <li className="pt-0.5 text-[10px] text-faint">
            +{sorted.length - legend.length} more
          </li>
        )}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TimelineArea — daily ingestion volume
// ---------------------------------------------------------------------------
export function TimelineArea({ data, height = 240 }) {
  if (!data.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <p className="text-xs text-faint">
          No ingestion data yet — run a sync or wait for the scheduled poll.
        </p>
      </div>
    );
  }
  if (data.length < 2) {
    const only = data[0];
    return (
      <div
        style={{ height }}
        className="flex flex-col items-center justify-center gap-2 px-6 text-center"
      >
        <span className="text-3xl font-bold text-ink tabular-nums">
          {(only.count ?? 0).toLocaleString()}
        </span>
        <span className="text-xs text-dim">{only.date} · first day of ingestion</span>
        <span className="text-xs text-faint">
          The daily curve fills in automatically as new days are ingested.
        </span>
      </div>
    );
  }

  // Format date labels more compactly
  const formatted = data.map((d) => ({
    ...d,
    label: d.date ? String(d.date).slice(5) : d.date, // MM-DD
  }));

  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={formatted} margin={{ top: 8, right: 4, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="ctiVolume" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#4F8EF7" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#4F8EF7" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ ...AXIS, fontSize: 10 }}
            axisLine={false}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={AXIS}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
            tickFormatter={(v) => compactNumber(v)}
            width={40}
          />
          <Tooltip
            content={<ChartTooltip formatter={(v) => compactNumber(v)} />}
          />
          <Area
            type="monotone"
            dataKey="count"
            name="Items ingested"
            stroke="#4F8EF7"
            strokeWidth={2}
            fill="url(#ctiVolume)"
            dot={false}
            activeDot={{ r: 4, fill: '#4F8EF7', strokeWidth: 0 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SeverityBar — horizontal bar chart (much more readable than vertical)
// ---------------------------------------------------------------------------
export function SeverityBar({ data, height = 240 }) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sorted = [...data].sort(
    (a, b) => order.indexOf(a.name) - order.indexOf(b.name),
  );
  const max = Math.max(...sorted.map((d) => d.value || 0), 1);

  if (!sorted.length) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <p className="text-xs text-faint">No severity data yet.</p>
      </div>
    );
  }

  // Render as a custom horizontal bar list for cleaner look
  return (
    <div style={{ height }} className="flex flex-col justify-center gap-3 py-2">
      {sorted.map((d) => {
        const sev = SEVERITY[d.name] || SEVERITY.INFO;
        const pct = Math.round(((d.value || 0) / max) * 100);
        return (
          <div key={d.name} className="flex items-center gap-3">
            <span className="w-16 shrink-0 text-right text-[11px] font-semibold uppercase tracking-wide text-dim">
              {d.name}
            </span>
            <div className="relative flex-1 overflow-hidden rounded-full bg-raised h-2">
              <div
                className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, backgroundColor: sev.hex }}
              />
            </div>
            <span className="w-12 text-right font-mono text-xs font-semibold text-ink tabular-nums">
              {compactNumber(d.value)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// Re-export for components that import it from here
export { severityStyle };