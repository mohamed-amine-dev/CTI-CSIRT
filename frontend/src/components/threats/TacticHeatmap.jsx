import React, { useMemo, useState } from 'react';

import { compactNumber, threatColor } from '../../utils/format';

const CYAN = [34, 211, 238]; // #22d3ee

/**
 * TacticHeatmap — threat category × MITRE ATT&CK tactic grid.
 *
 * Data comes from /api/v1/threats/heatmap: rows are the ranked threat
 * categories, columns the ATT&CK tactic ordering (an always-present
 * "Unclassified" column absorbs categories with no analyst mapping — the
 * heatmap never guesses an attribution). Cell intensity = share of the
 * strongest cell. Clicking a row opens /feeds filtered to that category.
 */
export default function TacticHeatmap({ data, onSelectCategory }) {
  const [hovered, setHovered] = useState(null);

  const { tactics, rows, maxCell } = useMemo(() => {
    const tactics = data?.tactics || [];
    const categories = data?.categories || [];
    const matrix = data?.matrix || {};
    const totals = data?.category_totals || {};
    let maxCell = 0;
    const rows = categories.map((cat) => {
      const cells = tactics.map((t) => matrix[cat]?.[t] || 0);
      for (const v of cells) if (v > maxCell) maxCell = v;
      return { category: cat, total: totals[cat] || 0, cells };
    });
    return { tactics, rows, maxCell: maxCell || 1 };
  }, [data]);

  if (!rows.length) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-xs text-faint">No tactic heatmap data yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-lg border border-line">
        <div
          className="grid min-w-max"
          style={{ gridTemplateColumns: `minmax(160px, 1fr) repeat(${tactics.length}, 64px)` }}
        >
          {/* Header row */}
          <div className="sticky left-0 z-10 border-b border-r border-line bg-surface px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-faint">
            Category
          </div>
          {tactics.map((t) => (
            <div
              key={t}
              className="border-b border-l border-line bg-surface px-1 py-2 text-center text-[9px] font-semibold uppercase tracking-wide text-faint"
              title={t}
            >
              <span className="block truncate">{t}</span>
            </div>
          ))}

          {rows.map((row) => (
            <React.Fragment key={row.category}>
              <button
                type="button"
                onClick={() => onSelectCategory?.(row.category)}
                className="group sticky left-0 z-10 flex cursor-pointer items-center gap-2 border-b border-r border-line bg-surface px-3 py-1.5 text-left transition-colors hover:bg-raised/70"
              >
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: threatColor(row.category) }} />
                <span className="min-w-0 flex-1 truncate text-xs text-ink group-hover:text-cyan-200">{row.category}</span>
                <span className="font-mono text-[10px] text-faint">{compactNumber(row.total)}</span>
              </button>
              {row.cells.map((v, i) => {
                const intensity = v / maxCell;
                return (
                  <div
                    key={tactics[i]}
                    className="flex items-center justify-center border-b border-l border-line px-1 py-1.5"
                    style={{ background: v > 0 ? `rgba(${CYAN.join(',')}, ${0.1 + intensity * 0.85})` : 'transparent' }}
                    onMouseEnter={() => setHovered({ category: row.category, tactic: tactics[i], v })}
                    onMouseLeave={() => setHovered(null)}
                  >
                    {v > 0 && <span className="font-mono text-[11px] text-ink">{compactNumber(v)}</span>}
                  </div>
                );
              })}
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] text-faint">
          {hovered
            ? `${hovered.category} → ${hovered.tactic}: ${compactNumber(hovered.v)} records`
            : 'Cell intensity = records mapped to that tactic · click a category to open its feeds'}
        </p>
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-faint">low</span>
          <div className="h-2 w-24 rounded-full" style={{ background: `linear-gradient(to right, transparent, rgba(${CYAN.join(',')},0.95))` }} />
          <span className="text-[10px] uppercase tracking-wider text-faint">high</span>
        </div>
      </div>
    </div>
  );
}
