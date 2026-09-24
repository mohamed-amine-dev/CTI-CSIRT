import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import Layout from './components/layout/Layout';
import ErrorBoundary from './components/ui/ErrorBoundary';
import Agent from './pages/Agent';
import Dashboard from './pages/Dashboard';
import DarkWeb from './pages/DarkWeb';
import DataExplorer from './pages/DataExplorer';
import ExposureWatchlist from './pages/ExposureWatchlist';
import Feeds from './pages/Feeds';
import Indicators from './pages/Indicators';
import IoCSearch from './pages/IoCSearch';
import MalwareArsenal from './pages/MalwareArsenal';
import MalwareDetail from './pages/MalwareDetail';
import NetworkAnalysis from './pages/NetworkAnalysis';
import SearchExport from './pages/SearchExport';
import SampleScanner from './pages/SampleScanner';
import StreamMonitor from './pages/StreamMonitor';
import ThreatActors from './pages/ThreatActors';
import ThreatLandscape from './pages/ThreatLandscape';
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
          <Route path="/threat-landscape" element={<ErrorBoundary><ThreatLandscape /></ErrorBoundary>} />
          <Route path="/actors" element={<ErrorBoundary><ThreatActors /></ErrorBoundary>} />
          <Route path="/malware" element={<ErrorBoundary><MalwareArsenal /></ErrorBoundary>} />
          <Route path="/malware/:stixId" element={<ErrorBoundary><MalwareDetail /></ErrorBoundary>} />
          <Route path="/indicators" element={<ErrorBoundary><Indicators /></ErrorBoundary>} />
          <Route path="/feeds" element={<ErrorBoundary><Feeds /></ErrorBoundary>} />
          <Route path="/vulnerabilities" element={<ErrorBoundary><Vulnerabilities /></ErrorBoundary>} />
          <Route path="/ioc-search" element={<ErrorBoundary><IoCSearch /></ErrorBoundary>} />
          <Route path="/samples" element={<ErrorBoundary><SampleScanner /></ErrorBoundary>} />
          <Route path="/network-analysis" element={<ErrorBoundary><NetworkAnalysis /></ErrorBoundary>} />
          <Route path="/search" element={<ErrorBoundary><SearchExport /></ErrorBoundary>} />
          <Route path="/darkweb" element={<ErrorBoundary><DarkWeb /></ErrorBoundary>} />
          <Route path="/darkweb-monitor" element={<ErrorBoundary><StreamMonitor kind="darkweb" /></ErrorBoundary>} />
          <Route path="/telegram-monitor" element={<ErrorBoundary><StreamMonitor kind="telegram" /></ErrorBoundary>} />
          <Route path="/exposure" element={<ErrorBoundary><ExposureWatchlist /></ErrorBoundary>} />
          <Route path="/explore" element={<ErrorBoundary><DataExplorer /></ErrorBoundary>} />
          <Route path="/agent" element={<ErrorBoundary><Agent /></ErrorBoundary>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </ThemeProvider>
  );
}
