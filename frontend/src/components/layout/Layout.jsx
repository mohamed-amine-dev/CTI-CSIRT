import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';

import Sidebar from './Sidebar';
import TopBar from './TopBar';
import Footer from './Footer';

/**
 * Layout — sticky sidebar + top bar shell. All routed pages render through the
 * <Outlet>. Sidebar collapse state and the mobile drawer are owned here so
 * they survive route changes. The shell is locked to the viewport: the
 * sidebar stays fixed on the left while only the main content area scrolls.
 */
export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden bg-base text-ink">
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenSidebar={() => setMobileOpen(true)} />
        <main className="min-h-0 flex-1 overflow-y-auto bg-grid p-4 sm:p-6">
          <Outlet />
        </main>
        <Footer />
      </div>
    </div>
  );
}
