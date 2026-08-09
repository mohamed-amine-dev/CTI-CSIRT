import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import DarkWeb from './pages/DarkWeb';
import Feeds from './pages/Feeds';
import IoCSearch from './pages/IoCSearch';
import Vulnerabilities from './pages/Vulnerabilities';
import { ThemeProvider } from './theme';

/**
 * App — root component: theme provider + route table. Every route renders
 * inside the persistent <Layout> shell (sidebar + top bar). `/` redirects to
 * the Executive Overview dashboard.
 */
export default function App() {
  return (
    <ThemeProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/feeds" element={<Feeds />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/ioc-search" element={<IoCSearch />} />
          <Route path="/darkweb" element={<DarkWeb />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </ThemeProvider>
  );
}
