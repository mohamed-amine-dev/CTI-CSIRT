import React, { useState } from 'react';
import { Crosshair, Eye, Target } from 'lucide-react';

import Card from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { timeAgo } from '../../utils/format';
import { onRefresh } from '../../utils/events';

const TONE = { domain: 'blue', phone: 'violet', email: 'amber', org: 'neutral' };

/**
 * WatchlistPanel — dashboard view of the Org Exposure watchlist.
 * Left side: saved targets you're watching. Right side: the newest recorded
 * matches from the automatic sweep (real dark-web/Telegram hits only). Links
 * through to the full Exposure & Watchlist page.
 */
export default function WatchlistPanel({ limit = 6 }) {
  const [reloadKey, setReloadKey] = useState(0);
  React.useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const targets = useApi(() => unwrap(api.getWatchlist()), {
    deps: [reloadKey],
    refreshMs: 60_000,
  });
  const matches = useApi(() => unwrap(api.getWatchlistMatches(limit)), {
    deps: [reloadKey, limit],
    refreshMs: 60_000,
  });

  const targetList = targets.data?.items || [];
  const matchList = matches.data?.items || [];

  return (
    <Card
      title="Org Exposure Watchlist"
      icon={Crosshair}
      subtitle="watched targets & real dark-web/Telegram hits"
      padded={false}
    >
      <div className="grid grid-cols-1 divide-y divide-line/50 md:grid-cols-2 md:divide-x md:divide-y-0">
        {/* ── Watched targets ─────────────────────────────────────────── */}
        <div>
          <div className="flex items-center gap-1.5 px-4 pt-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-dim">
            <Target size={12} /> Watched targets
          </div>
          <div className="flex max-h-52 flex-col gap-1.5 overflow-y-auto p-3">
            {targetList.length === 0 ? (
              <EmptyState
                icon={Target}
                title="Nothing watched yet"
                message="Add targets on the Exposure & Watchlist page."
              />
            ) : (
              targetList.map((t) => (
                <div key={t.id} className="flex items-center gap-2 rounded-lg border border-line bg-base/60 px-2.5 py-1.5">
                  <Badge tone={TONE[t.type] || 'blue'} className="shrink-0">{t.type}</Badge>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[12px] text-ink">{t.value}</p>
                    {t.label && <p className="truncate text-[11px] text-faint">{t.label}</p>}
                  </div>
                </div>
              ))
            )}
            {matches.error && (
              <p className="px-1 text-[11px] text-red-400">Watchlist unavailable: {String(matches.error)}</p>
            )}
          </div>
        </div>

        {/* ── Recent matches ───────────────────────────────────────────── */}
        <div>
          <div className="flex items-center gap-1.5 px-4 pt-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-dim">
            <Eye size={12} /> Recent matches
          </div>
          <div className="flex max-h-52 flex-col gap-1.5 overflow-y-auto p-3">
            {matchList.length === 0 ? (
              <EmptyState
                icon={Eye}
                title="No recorded matches"
                message="A watched value being found on the dark web/Telegram will appear here."
              />
            ) : (
              matchList.map((m) => (
                <a
                  key={m.id}
                  href={m.url || undefined}
                  target={m.url ? '_blank' : undefined}
                  rel={m.url ? 'noreferrer' : undefined}
                  className="block rounded-lg border border-line bg-base/60 px-2.5 py-1.5 transition-colors hover:bg-raised/50"
                >
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                    <Badge tone="blue" className="shrink-0">{m.source}</Badge>
                    <span className="shrink-0 font-semibold text-ink">{m.target_label || m.target_value}</span>
                    <span className="ml-auto shrink-0 text-[10px] text-faint">{timeAgo(m.created_at)}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    <code className="rounded bg-raised px-1 text-[11px] text-rose-400">{m.matched_term}</code>
                    {m.snippet && (
                      <span className="truncate text-[11px] text-dim">{m.snippet}</span>
                    )}
                  </div>
                </a>
              ))
            )}
          </div>
        </div>
      </div>
    </Card>
  );
}