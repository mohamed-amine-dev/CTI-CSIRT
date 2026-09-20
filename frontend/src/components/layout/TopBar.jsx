import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Menu, Moon, RefreshCw, Search, Sun, Wifi, WifiOff } from 'lucide-react';

import { useApi } from '../../hooks/useApi';
import { api, errorText, unwrap } from '../../services/api';
import { useTheme } from '../../theme';
import { emitRefresh } from '../../utils/events';
import NotificationBell from './NotificationBell';

/**
 * TopBar — global search, live API status, Force Sync trigger, theme toggle.
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
    emitRefresh();
    setTimeout(() => setRefreshing(false), 600);
  };

  const onForceSync = async () => {
    if (syncing || !online) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await unwrap(api.forceSync());
      if (res.status === 'already_running') {
        setSyncMsg({ ok: true, text: 'Sync already running — monitoring…' });
      }
      const deadline = Date.now() + 10 * 60_000;
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
            ? `Sync complete: +${n} records, ${failed} feed(s) failed`
            : `Sync complete: +${n} records across all feeds`,
        });
      }
      emitRefresh();
    } catch (e) {
      setSyncMsg({ ok: false, text: `Force sync failed: ${errorText(e)}` });
    } finally {
      setSyncing(false);
      setTimeout(() => setSyncMsg(null), 6000);
    }
  };

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-surface/95 px-4 backdrop-blur-sm sm:px-5">
      {/* Mobile menu button */}
      <button
        onClick={onOpenSidebar}
        className="rounded-lg p-2 text-dim transition-colors hover:bg-raised hover:text-ink lg:hidden"
        aria-label="Open navigation menu"
      >
        <Menu size={18} />
      </button>

      {/* Global search */}
      <form onSubmit={onSearch} className="relative flex-1 max-w-md">
        <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search IP, domain, hash or CVE…"
          className="focus-ring w-full rounded-lg border border-line bg-base py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint transition-colors hover:border-line/80"
        />
      </form>

      <div className="ml-auto flex items-center gap-1.5">
        {/* API status indicator */}
        <div
          className="hidden items-center gap-2 rounded-lg border border-line bg-base px-3 py-1.5 sm:flex"
          title={online ? `API online · ${health?.llm_provider || 'unknown'} LLM` : 'API unreachable'}
        >
          {online ? (
            <Wifi size={13} className="text-emerald-400" />
          ) : (
            <WifiOff size={13} className="text-red-400" />
          )}
          <span className={`text-xs font-medium ${online ? 'text-emerald-400' : 'text-red-400'}`}>
            {online ? 'Online' : 'Offline'}
          </span>
          {online && health?.llm_provider && (
            <span className="hidden text-[11px] text-faint md:block">
              · {health.llm_provider}
            </span>
          )}
        </div>

        {/* Force Sync Feeds */}
        <button
          onClick={onForceSync}
          disabled={syncing || !online}
          className="flex items-center gap-1.5 rounded-lg border border-line bg-base px-3 py-1.5 text-xs font-medium text-dim transition-colors hover:border-primary/40 hover:text-primary disabled:cursor-not-allowed disabled:opacity-50"
          title="Manually run every collector now (POST /api/v1/ingest/force-sync)"
        >
          <RefreshCw size={13} className={syncing ? 'animate-spin text-primary' : ''} />
          <span className="hidden md:inline">
            {syncing ? 'Syncing…' : 'Sync Feeds'}
          </span>
        </button>

        {/* View refresh */}
        <button
          onClick={onRefresh}
          className="rounded-lg border border-line bg-base p-2 text-dim transition-colors hover:border-primary/40 hover:text-primary"
          title="Refresh all views"
          aria-label="Refresh views"
        >
          <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
        </button>

        {/* Notifications */}
        <NotificationBell />

        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="rounded-lg border border-line bg-base p-2 text-dim transition-colors hover:border-primary/40 hover:text-primary"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
      </div>

      {/* Transient sync feedback toast */}
      {syncMsg && (
        <div
          className={`absolute left-1/2 top-16 z-30 -translate-x-1/2 whitespace-nowrap rounded-lg border px-4 py-2 text-xs font-medium shadow-xl backdrop-blur-sm transition-all ${
            syncMsg.ok
              ? 'border-emerald-500/30 bg-surface text-emerald-400'
              : 'border-red-500/30 bg-surface text-red-400'
          }`}
          role="status"
        >
          {syncMsg.text}
        </div>
      )}
    </header>
  );
}
