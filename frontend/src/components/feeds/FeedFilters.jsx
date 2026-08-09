import React from 'react';
import { Search, X } from 'lucide-react';

import Button from '../ui/Button';

const CATEGORIES = ['Ransomware', 'Phishing', 'Malware', 'Exploit', 'Vulnerability', 'Other'];

/**
 * FeedFilters — source / category / free-text controls for the feeds page.
 * Source options are fed from the live /api/v1/feeds/sources aggregation.
 */
export default function FeedFilters({ source, setSource, category, setCategory, search, setSearch, sources, onReset }) {
  const sourceNames = Object.keys(sources || {}).sort();
  const selectCls =
    'focus-neon rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink';

  return (
    <div className="flex flex-wrap items-end gap-3 rounded-xl border border-line bg-surface p-4">
      <label className="min-w-[180px] flex-1">
        <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">Source</span>
        <select value={source} onChange={(e) => setSource(e.target.value)} className={`${selectCls} w-full`}>
          <option value="">All sources</option>
          {sourceNames.map((s) => (
            <option key={s} value={s}>
              {s} ({sources[s]})
            </option>
          ))}
        </select>
      </label>

      <label className="min-w-[160px] flex-1">
        <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">Category</span>
        <select value={category} onChange={(e) => setCategory(e.target.value)} className={`${selectCls} w-full`}>
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </label>

      <label className="min-w-[200px] flex-1">
        <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">Search text</span>
        <div className="relative">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="ransomware, CVE-2024…"
            className="focus-neon w-full rounded-lg border border-line bg-surface py-2 pl-8 pr-3 text-sm text-ink placeholder:text-faint"
          />
        </div>
      </label>

      <Button variant="secondary" icon={X} onClick={onReset}>
        Reset
      </Button>
    </div>
  );
}
