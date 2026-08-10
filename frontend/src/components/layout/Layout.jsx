import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';

import Sidebar from './Sidebar';
import TopBar from './TopBar';

/**
 * Layout — fixed sidebar + top bar shell. All routed pages render through the
 * <Outlet>. Sidebar collapse state and the mobile drawer are owned here so
 * they survive route changes.
 */
export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-base text-ink">
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenSidebar={() => setMobileOpen(true)} />
        <main className="bg-grid flex-1 p-4 sm:p-6">
          <Outlet />
        </main>
        <footer className="border-t border-line px-6 py-3 text-[11px] text-faint">
          Argus CTI — Cyber Threat Intelligence Platform · data served live from ClickHouse
        </footer>
      </div>
    </div>
  );
}
