import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Bot,
  ChevronLeft,
  Database,
  Globe,
  LayoutDashboard,
  Map,
  RadioTower,
  ScanSearch,
  ShieldAlert,
  Skull,
  Table2,
  Shield,
} from 'lucide-react';

const NAV_GROUPS = [
  {
    label: 'Intelligence',
    items: [
      { to: '/dashboard',        label: 'Executive Overview',  icon: LayoutDashboard },
      { to: '/threat-landscape', label: 'Threat Landscape',    icon: Map },
      { to: '/actors',           label: 'Threat Actors & APTs',icon: Skull },
      { to: '/feeds',            label: 'Live Threat Feeds',   icon: RadioTower },
      { to: '/darkweb',          label: 'Dark Web & Telegram', icon: Globe },
    ],
  },
  {
    label: 'Investigation',
    items: [
      { to: '/vulnerabilities',  label: 'Alert Sheets',        icon: ShieldAlert },
      { to: '/ioc-search',       label: 'IoC Search & Shodan', icon: ScanSearch },
      { to: '/agent',            label: 'Autonomous Triage',   icon: Bot },
    ],
  },
  {
    label: 'Data',
    items: [
      { to: '/search',           label: 'Search & Export',     icon: Database },
      { to: '/explore',          label: 'Data Explorer',       icon: Table2 },
    ],
  },
];

/**
 * Sidebar — collapsible primary navigation with grouped sections.
 *  * lg+ : inline rail that collapses to icon-only mode.
 *  * <lg  : off-canvas drawer with a backdrop.
 */
export default function Sidebar({ collapsed, setCollapsed, mobileOpen, setMobileOpen }) {
  const linkBase =
    'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150';
  const linkInactive =
    'text-dim hover:bg-raised hover:text-ink';
  const linkActive =
    'bg-primary/10 text-primary border border-primary/20 shadow-sm';

  const renderLinks = () => (
    <nav className="flex flex-1 flex-col gap-5 px-3 py-2 overflow-y-auto">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          {!collapsed && (
            <p className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-widest text-faint">
              {group.label}
            </p>
          )}
          <div className="flex flex-col gap-0.5">
            {group.items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                onClick={() => setMobileOpen?.(false)}
                className={({ isActive }) =>
                  `${linkBase} ${isActive ? linkActive : linkInactive} ${
                    collapsed ? 'justify-center px-2' : 'pl-3'
                  }`
                }
                title={collapsed ? label : undefined}
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      size={17}
                      className={`shrink-0 transition-colors ${
                        isActive ? 'text-primary' : 'text-faint group-hover:text-dim'
                      }`}
                      aria-hidden="true"
                    />
                    {!collapsed && (
                      <span className="truncate">{label}</span>
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-line bg-surface transition-all duration-200 lg:sticky lg:top-0 lg:h-screen lg:shrink-0 lg:z-auto ${
          collapsed ? 'lg:w-[60px]' : 'lg:w-60'
        } ${
          mobileOpen ? 'w-64 translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand header */}
        <div
          className={`flex h-16 shrink-0 items-center gap-3 border-b border-line px-4 ${
            collapsed ? 'justify-center px-2' : ''
          }`}
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/15 border border-primary/25">
            <Shield size={18} className="text-primary" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-sm font-bold tracking-wide text-ink">Argus CTI</p>
              <p className="text-[10px] uppercase tracking-widest text-faint">Threat Intelligence</p>
            </div>
          )}
        </div>

        {renderLinks()}

        {/* Collapse toggle (desktop only) */}
        <div className="shrink-0 border-t border-line p-2">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden w-full items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs text-faint transition-colors hover:bg-raised hover:text-dim lg:flex"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <ChevronLeft
              size={14}
              className={`transition-transform duration-200 ${collapsed ? 'rotate-180' : ''}`}
            />
            {!collapsed && <span>Collapse</span>}
          </button>
          {!collapsed && (
            <p className="mt-1 px-3 text-[10px] leading-relaxed text-faint/60">
              Phase 3 · v1.0.0
            </p>
          )}
        </div>
      </aside>
    </>
  );
}
