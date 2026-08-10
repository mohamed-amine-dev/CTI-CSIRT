import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ChevronLeft,
  Database,
  LayoutDashboard,
  RadioTower,
  ScanSearch,
  ShieldAlert,
  Skull,
  Table2,
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Executive Overview', icon: LayoutDashboard },
  { to: '/feeds', label: 'Live Threat Feeds', icon: RadioTower },
  { to: '/vulnerabilities', label: "Fiches d'Alerte", icon: ShieldAlert },
  { to: '/ioc-search', label: 'IoC Search & Shodan', icon: ScanSearch },
  { to: '/search', label: 'Search & Export', icon: Database },
  { to: '/explore', label: 'Data Explorer', icon: Table2 },
  { to: '/darkweb', label: 'Dark Web & Telegram', icon: Skull },
];

/**
 * Sidebar — collapsible primary navigation.
 *  * lg+ : inline rail that collapses to icons only.
 *  * <lg  : off-canvas drawer with a backdrop.
 * `collapsed` / `mobileOpen` are controlled by <Layout>.
 */
export default function Sidebar({ collapsed, setCollapsed, mobileOpen, setMobileOpen }) {
  const linkBase =
    'group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors';
  const linkInactive = 'text-dim hover:bg-raised hover:text-ink';
  const linkActive = 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30';

  const renderLinks = () => (
    <nav className="flex flex-1 flex-col gap-1 px-3">
      {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          onClick={() => setMobileOpen?.(false)}
          className={({ isActive }) =>
            `${linkBase} ${isActive ? linkActive : linkInactive} ${collapsed ? 'justify-center px-2' : ''}`
          }
          title={collapsed ? label : undefined}
        >
          <Icon size={18} className="shrink-0" aria-hidden="true" />
          {!collapsed && <span className="truncate">{label}</span>}
        </NavLink>
      ))}
    </nav>
  );

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-950/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 transform flex-col border-r border-line bg-base transition-all duration-200 lg:static lg:z-auto ${
          collapsed ? 'lg:w-16' : 'lg:w-64'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Brand */}
        <div
          className={`flex h-16 items-center gap-2.5 border-b border-line px-4 ${
            collapsed ? 'justify-center' : ''
          }`}
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
            <ShieldAlert size={18} className="text-cyan-400" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-sm font-bold tracking-wide text-ink">CSIRT CTI</p>
              <p className="text-[10px] uppercase tracking-widest text-faint">Threat Intelligence</p>
            </div>
          )}
        </div>

        {renderLinks()}

        {/* Collapse toggle (desktop only) */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="m-3 hidden items-center justify-center gap-2 rounded-lg border border-line bg-raised px-3 py-2 text-xs text-dim transition-colors hover:text-cyan-300 lg:flex"
        >
          <ChevronLeft size={14} className={collapsed ? 'rotate-180' : ''} />
          {!collapsed && 'Collapse'}
        </button>

        <div className="border-t border-line px-4 py-3">
          <p className="text-[10px] leading-relaxed text-faint">
            {collapsed ? 'v1.0' : 'Phase 3 · v1.0.0\nFastAPI · ClickHouse · Gemini'}
          </p>
        </div>
      </aside>
    </>
  );
}
