import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import Layout from './components/layout/Layout';
import ErrorBoundary from './components/ui/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import DarkWeb from './pages/DarkWeb';
import DataExplorer from './pages/DataExplorer';
import Feeds from './pages/Feeds';
import IoCSearch from './pages/IoCSearch';
import SearchExport from './pages/SearchExport';
import Vulnerabilities from './pages/Vulnerabilities';
import { ThemeProvider } from './theme';

/**
 * App — root component: theme provider + route table. Every route renders
 * inside the persistent <Layout> shell (sidebar + top bar) and is wrapped in an
 * ErrorBoundary so a render crash never blank-screens the whole app. `/`
 * redirects to the Executive Overview dashboard.
 */
export default function App() {
  return (
    <ThemeProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
          <Route path="/feeds" element={<ErrorBoundary><Feeds /></ErrorBoundary>} />
          <Route path="/vulnerabilities" element={<ErrorBoundary><Vulnerabilities /></ErrorBoundary>} />
          <Route path="/ioc-search" element={<ErrorBoundary><IoCSearch /></ErrorBoundary>} />
          <Route path="/search" element={<ErrorBoundary><SearchExport /></ErrorBoundary>} />
          <Route path="/darkweb" element={<ErrorBoundary><DarkWeb /></ErrorBoundary>} />
          <Route path="/explore" element={<ErrorBoundary><DataExplorer /></ErrorBoundary>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </ThemeProvider>
  );
}
