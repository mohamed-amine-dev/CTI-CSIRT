import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Menu, Moon, RefreshCw, Search, Sun } from 'lucide-react';

import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { useTheme } from '../../theme';
import { emitRefresh } from '../../utils/events';

/**
 * TopBar — global search, live API status indicator, theme toggle and a
 * manual refresh trigger that fans out to every mounted view.
 */
export default function TopBar({ onOpenSidebar }) {
  const { theme, toggle } = useTheme();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);

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

        {/* Refresh trigger */}
        <button
          onClick={onRefresh}
          className="rounded-lg border border-line bg-surface p-2 text-dim transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
          title="Refresh all views"
        >
          <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
        </button>

        {/* Dark / light toggle */}
        <button
          onClick={toggle}
          className="rounded-lg border border-line bg-surface p-2 text-dim transition-colors hover:text-cyan-300"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </div>
    </header>
  );
}
