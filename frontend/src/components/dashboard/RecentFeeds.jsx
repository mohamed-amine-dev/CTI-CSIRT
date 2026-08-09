import React, { useEffect, useState } from 'react';
import { Activity } from 'lucide-react';

import Card from '../ui/Card';
import Badge from '../ui/Badge';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { categorySeverity, timeAgo } from '../../utils/format';
import { onRefresh } from '../../utils/events';

/**
 * RecentFeeds — live scrolling ticker of the newest high-priority feed items.
 * The inner list is rendered twice and translated -50% for a seamless loop;
 * hovering pauses the animation for analysts to read a line.
 */
export default function RecentFeeds({ limit = 8 }) {
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const { data, loading } = useApi(() => unwrap(api.getFeeds({ limit })), {
    deps: [reloadKey],
    refreshMs: 30_000,
  });
  const items = data?.items || [];

  if (loading && items.length === 0) {
    return (
      <Card title="Recent High-Priority Feeds" icon={Activity} subtitle="Live ticker">
        <p className="py-10 text-center text-sm text-faint">Loading feed…</p>
      </Card>
    );
  }

  const list = (keyPrefix) => (
    <ul className="space-y-2 px-5 py-4">
      {items.map((f, i) => {
        const sev = categorySeverity(f.category);
        return (
          <li
            key={`${keyPrefix}-${i}`}
            className="flex items-start gap-3 rounded-lg border border-line/70 bg-base/40 px-3 py-2.5"
          >
            <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${sev.dot}`} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Badge severity={sev}>{f.category}</Badge>
                <span className="text-[11px] font-semibold text-cyan-300">{f.source}</span>
                <span className="ml-auto shrink-0 text-[10px] text-faint">{timeAgo(f.ts)}</span>
              </div>
              <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-dim">{f.raw_text}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );

  return (
    <Card title="Recent High-Priority Feeds" icon={Activity} subtitle="Live ticker · hover to pause">
      {items.length === 0 ? (
        <p className="py-10 text-center text-sm text-faint">No feed items ingested yet.</p>
      ) : (
        <div className="relative max-h-[420px] overflow-hidden">
          <div className="animate-ticker hover:[animation-play-state:paused]">
            {list('a')}
            {list('b')}
          </div>
          <div className="pointer-events-none absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-surface to-transparent" />
        </div>
      )}
    </Card>
  );
}
