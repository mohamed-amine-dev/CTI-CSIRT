import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Menu, Moon, RefreshCw, Search, Sun } from 'lucide-react';

import { useApi } from '../../hooks/useApi';
import { api, errorText, unwrap } from '../../services/api';
import { useTheme } from '../../theme';
import { emitRefresh } from '../../utils/events';
import NotificationBell from './NotificationBell';

/**
 * TopBar — global search, live API status indicator, a manual "Force Sync"
 * trigger for the ingestion pipeline, theme toggle and a view-refresh button.
 */
export default function TopBar({ onOpenSidebar }) {
  const { theme, toggle } = useTheme();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState(null); // { ok: bool, text: string } | null

  // Poll /health every 20s for the live status dot.
  const { data: health, error } = useApi(() => unwrap(api.health()), {
    deps: [],
    refreshMs: 20_000,
  });
  const online = !error && health?.status === 'ok';

  const onSearch = (e) => {
    e.preventDefault();
    const q = query.trim();
    if (q) navigate(`/ioc-search?q=${encodeURIComponent(q)}`);
  };

  const onRefresh = async () => {
    setRefreshing(true);
    emitRefresh(); // every listening page reloads
    setTimeout(() => setRefreshing(false), 600);
  };

  const onForceSync = async () => {
    if (syncing || !online) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      // 1. Launch the background sync (returns 202 immediately).
      const res = await unwrap(api.forceSync());
      if (res.status === 'already_running') {
        setSyncMsg({ ok: true, text: 'A full sync is already running — watching it…' });
      }
      // 2. Poll status while the sync runs, keeping the spinner alive.
      const deadline = Date.now() + 10 * 60_000; // hard cap 10 min
      let last = null;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 4000));
        const status = await unwrap(api.getIngestStatus());
        last = status.last;
        if (!status.running) break;
      }
      if (!last || last.status !== 'finished') {
        setSyncMsg({ ok: false, text: 'Force sync did not complete cleanly.' });
      } else {
        const n = last.collected ?? 0;
        const failed = Object.values(last.sources || {}).filter((s) => s.failed).length;
        setSyncMsg({
          ok: true,
          text: failed
            ? `Sync finished: +${n} records, ${failed} feed(s) failed (see server logs)`
            : `Sync finished: +${n} records across all feeds`,
        });
      }
      emitRefresh();
    } catch (e) {
      setSyncMsg({ ok: false, text: `Force sync failed: ${errorText(e)}` });
    } finally {
      setSyncing(false);
      // Clear the transient feedback after a few seconds.
      setTimeout(() => setSyncMsg(null), 6000);
    }
  };

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-line bg-base/90 px-4 backdrop-blur sm:px-6">
      <button
        onClick={onOpenSidebar}
        className="rounded-lg p-2 text-dim transition-colors hover:bg-raised hover:text-ink lg:hidden"
        aria-label="Open menu"
      >
        <Menu size={20} />
      </button>

      {/* Global search */}
      <form onSubmit={onSearch} className="relative flex-1 max-w-xl">
        <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search IP, domain, hash or CVE…"
          className="focus-neon w-full rounded-lg border border-line bg-surface py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint"
        />
      </form>

      <div className="ml-auto flex items-center gap-2">
        {/* Live API status */}
        <div
          className="hidden items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 sm:flex"
          title={online ? `API online · ${health?.llm_provider || 'unknown'} engine` : 'API unreachable'}
        >
          <span
            className={`h-2 w-2 rounded-full ${
              online ? 'bg-emerald-400 animate-pulse-glow' : 'bg-red-500'
            }`}
          />
          <span className="text-xs font-medium text-dim">
            {online ? 'API Online' : 'API Offline'}
          </span>
        </div>

        {/* Force Sync Feeds */}
        <button
          onClick={onForceSync}
          disabled={syncing || !online}
          className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-dim transition-colors hover:border-cyan-400/60 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
          title="Manually run every collector right now (POST /api/v1/ingest/force-sync)"
        >
          <RefreshCw size={14} className={syncing ? 'animate-spin text-cyan-300' : ''} />
          <span className="hidden text-xs font-semibold md:inline">
            {syncing ? 'Syncing…' : 'Force Sync Feeds'}
          </span>
        </button>

        {/* Refresh trigger */}
        <button
          onClick={onRefresh}
          className="rounded-lg border border-line bg-surface p-2 text-dim transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
          title="Refresh all views"
        >
          <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
        </button>

        {/* Real-time alerts (Phase 5) */}
        <NotificationBell />

        {/* Dark / light toggle */}
        <button
          onClick={toggle}
          className="rounded-lg border border-line bg-surface p-2 text-dim transition-colors hover:text-cyan-300"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </div>

      {/* Transient sync feedback */}
      {syncMsg && (
        <div
          className={`absolute left-1/2 top-16 z-30 -translate-x-1/2 whitespace-nowrap rounded-lg border px-3 py-2 text-xs shadow-lg backdrop-blur ${
            syncMsg.ok
              ? 'border-emerald-500/40 bg-emerald-950/80 text-emerald-200'
              : 'border-red-500/40 bg-red-950/80 text-red-200'
          }`}
          role="status"
        >
          {syncMsg.text}
        </div>
      )}
    </header>
  );
}
