import React from 'react';

/**
 * Table — styled data table for the dark theme.
 * `columns` is an array of { key, label, align, render(row) }.
 * Rows are `data` (array of objects). Falls back to an empty-state message.
 */
export default function Table({ columns, data = [], loading = false, emptyText = 'No data', rowKey = 'id' }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line">
            {columns.map((c) => (
              <th
                key={c.key}
                className={`px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-faint ${
                  c.align === 'right' ? 'text-right' : ''
                }`}
              >
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr
              key={row[rowKey] ?? i}
              className="border-b border-line/60 transition-colors last:border-0 hover:bg-raised/50"
            >
              {columns.map((c) => (
                <td
                  key={c.key}
                  className={`px-3 py-2.5 ${c.align === 'right' ? 'text-right' : ''} ${c.className || ''}`}
                >
                  {c.render ? c.render(row) : row[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {!loading && data.length === 0 && (
        <p className="px-3 py-10 text-center text-sm text-faint">{emptyText}</p>
      )}
    </div>
  );
}
