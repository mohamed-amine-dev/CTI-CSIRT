import React, { useEffect, useState } from 'react';
import { Activity, Maximize2 } from 'lucide-react';

import Card from '../ui/Card';
import Badge from '../ui/Badge';
import FeedDetailModal from './FeedDetailModal';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { categorySeverity, timeAgo } from '../../utils/format';
import { onRefresh } from '../../utils/events';

/**
 * RecentFeeds — live scrolling list of newest high-priority feed items.
 * Items are clickable and open the detail modal.
 */
export default function RecentFeeds({ limit = 8 }) {
  const [reloadKey, setReloadKey] = useState(0);
  const [selected, setSelected] = useState(null);
  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const { data, loading } = useApi(() => unwrap(api.getFeeds({ limit })), {
    deps: [reloadKey],
    refreshMs: 30_000,
  });
  const items = data?.items || [];

  if (loading && items.length === 0) {
    return (
      <Card title="Recent Threat Feed Items" icon={Activity} subtitle="latest from all sources">
        <div className="flex items-center justify-center py-10">
          <p className="text-sm text-faint">Loading feed items…</p>
        </div>
      </Card>
    );
  }

  const renderItem = (f, i, prefix) => {
    const sev = categorySeverity(f.category);
    const sevMeta = { CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-amber-500', LOW: 'bg-blue-500', INFO: 'bg-slate-500' };
    const dotColor = sevMeta[sev] || 'bg-slate-500';

    return (
      <li
        key={`${prefix}-${i}`}
        onClick={() => setSelected(f)}
        className="flex cursor-pointer items-start gap-3 px-5 py-3 transition-colors hover:bg-raised/50 border-b border-line/50 last:border-0"
      >
        <span className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${dotColor}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-0.5">
            <span className="text-[11px] font-semibold text-dim uppercase tracking-wide">
              {f.source}
            </span>
            <Badge severity={sev} className="text-[10px]">{f.category}</Badge>
            <span className="ml-auto shrink-0 text-[10px] text-faint">{timeAgo(f.ts)}</span>
          </div>
          <p className="truncate text-xs font-medium text-ink">{f.title || f.raw_text}</p>
        </div>
        <Maximize2 size={12} className="mt-1.5 shrink-0 text-faint/50" />
      </li>
    );
  };

  return (
    <Card
      title="Recent Threat Feed Items"
      icon={Activity}
      subtitle="hover to pause · click for details"
      padded={false}
    >
      {items.length === 0 ? (
        <div className="flex items-center justify-center py-10">
          <p className="text-sm text-faint">No feed items ingested yet.</p>
        </div>
      ) : (
        <div className="relative max-h-[400px] overflow-hidden">
          <div className="animate-ticker hover:[animation-play-state:paused]">
            <ul>{items.map((f, i) => renderItem(f, i, 'a'))}</ul>
            <ul>{items.map((f, i) => renderItem(f, i, 'b'))}</ul>
          </div>
          <div className="pointer-events-none absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-surface to-transparent" />
        </div>
      )}
      <FeedDetailModal feed={selected} onClose={() => setSelected(null)} />
    </Card>
  );
}
