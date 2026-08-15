import React, { useEffect, useMemo, useState } from 'react';
import { Info, Skull } from 'lucide-react';

import DarkWebCard from '../components/feeds/DarkWebCard';
import EmptyState from '../components/ui/EmptyState';
import Loader from '../components/ui/Loader';
import ErrorState from '../components/ui/ErrorState';
import { useApi } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { onRefresh } from '../utils/events';

/**
 * Dark Web & Telegram Monitor (/darkweb) — focused view over the onion-scrape
 * and Telegram sources. Both sources are only populated when the platform is
 * configured for them (see Settings: DARKWEB_ENABLED + Tor, TELEGRAM_BOT_TOKEN).
 */
export default function DarkWeb() {
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const onion = useApi(() => unwrap(api.getFeeds({ source: 'DARKWEB-ONION', limit: 50 })), {
    deps: [reloadKey],
    refreshMs: 60_000,
  });
  const telegram = useApi(() => unwrap(api.getFeeds({ source: 'TELEGRAM', limit: 50 })), {
    deps: [reloadKey],
    refreshMs: 60_000,
  });

  const items = useMemo(() => {
    const all = [...(onion.data?.items || []), ...(telegram.data?.items || [])];
    return all.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  }, [onion.data, telegram.data]);

  const loading = (onion.loading || telegram.loading) && items.length === 0;
  const sources = {
    'DARKWEB-ONION': onion.data?.total || 0,
    TELEGRAM: telegram.data?.total || 0,
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
            <Skull size={20} className="text-red-400" /> Dark Web &amp; Telegram Monitor
          </h1>
          <p className="text-xs text-dim">Onion-site scrapes and Telegram channel mentions</p>
        </div>
        <span className="flex gap-2 text-[11px] text-faint">
          {Object.entries(sources).map(([s, n]) => (
            <span key={s} className="rounded border border-line bg-surface px-2 py-1">
              {s}: <b className="text-cyan-300">{n}</b>
            </span>
          ))}
        </span>
      </div>

      <div className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-xs text-amber-200">
        <Info size={14} className="mt-0.5 shrink-0" />
        <p>
          In the Docker stack the dark web collector is already enabled and routes through the
          bundled Tor proxy (<code className="font-mono">cti-tor</code> on <code className="font-mono">tor:9050</code>)
          — no manual Tor install is needed. The first crawl through Tor can be slow. The Telegram
          source stays off until you set <code className="font-mono">TELEGRAM_BOT_TOKEN</code> and{' '}
          <code className="font-mono">TELEGRAM_CHANNEL</code> in <code className="font-mono">.env</code>.
        </p>
      </div>

      {loading ? (
        <Loader label="Scanning dark web sources…" />
      ) : (onion.error || telegram.error) && items.length === 0 ? (
        <ErrorState
          title="Failed to load dark web sources"
          message={errorText(onion.error || telegram.error)}
          onRetry={() => { onion.reload(); telegram.reload(); }}
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={Skull}
          title="No dark web / Telegram items yet"
          message="Enable the dark web + Telegram collectors in the backend configuration to start monitoring these sources."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {items.map((f) => (
            <DarkWebCard key={f.ts + f.source + f.url} feed={f} />
          ))}
        </div>
      )}
    </div>
  );
}
