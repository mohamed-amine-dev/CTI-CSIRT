import React, { useEffect, useState } from 'react';
import { Activity, FileDown, Globe, ShieldAlert, Skull, Waves } from 'lucide-react';

import Card from '../components/ui/Card';
import ErrorState from '../components/ui/ErrorState';
import Button from '../components/ui/Button';
import MetricCard from '../components/dashboard/MetricCard';
import RealTimeMap from '../components/dashboard/RealTimeMap';
import RecentFeeds from '../components/dashboard/RecentFeeds';
import ThreatLandscapePanel from '../components/dashboard/ThreatLandscapePanel';
import { TopPorts, TopCves } from '../components/dashboard/ExposurePanels';
import { CategoryDonut, SeverityBar, TimelineArea } from '../components/dashboard/ThreatCharts';
import { OriginPreviewTile, TacticsPreviewTile } from '../components/dashboard/ThreatLandscapePreviews';
import { useApi } from '../hooks/useApi';
import { api, unwrap } from '../services/api';
import { onRefresh } from '../utils/events';
import { exportFullReportPdf } from '../utils/report';

/**
 * Executive Overview (/dashboard) — the KPI + charts landing view.
 * Every number is aggregated live from the backend/ClickHouse:
 *   * Total items ingested   -> sum of raw_threat_intel sources
 *   * Critical CVEs          -> vulnerability_alerts CRITICAL count
 *   * Active IoCs            -> processed_iocs total
 *   * Dark Web / Telegram    -> DARKWEB-ONION + TELEGRAM feed count
 */
export default function Dashboard() {
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const sources = useApi(() => unwrap(api.getFeedSources()), { deps: [reloadKey], refreshMs: 60_000 });
  const categories = useApi(() => unwrap(api.getFeedCategories()), { deps: [reloadKey], refreshMs: 60_000 });
  const timeline = useApi(() => unwrap(api.getFeedTimeline(14)), { deps: [reloadKey], refreshMs: 60_000 });
  const alertStats = useApi(() => unwrap(api.getAlertStats()), { deps: [reloadKey], refreshMs: 60_000 });
  const iocStats = useApi(() => unwrap(api.getIocStats()), { deps: [reloadKey], refreshMs: 60_000 });
  const threatLandscape = useApi(() => unwrap(api.getThreatLandscape(60)), { deps: [reloadKey], refreshMs: 60_000 });
  const topPorts = useApi(() => unwrap(api.getTopPorts(60)), { deps: [reloadKey], refreshMs: 60_000 });
  const topCves = useApi(() => unwrap(api.getTopCves(60)), { deps: [reloadKey], refreshMs: 60_000 });

  const sourceMap = sources.data?.sources || {};
  const totalItems = Object.values(sourceMap).reduce((s, n) => s + n, 0);
  const critical = alertStats.data?.by_risk_level?.CRITICAL || 0;
  const totalIocs = Object.values(iocStats.data?.by_type || {}).reduce((s, n) => s + n, 0);
  const darkWebCount = (sourceMap['DARKWEB-ONION'] || 0) + (sourceMap['TELEGRAM'] || 0);

  const categoryData = Object.entries(categories.data?.by_category || {}).map(([name, value]) => ({
    name,
    value,
  }));
  const severityData = Object.entries(alertStats.data?.by_risk_level || {}).map(([name, value]) => ({
    name,
    value,
  }));
  const timelineData = timeline.data?.timeline || [];

  const queries = [sources, categories, timeline, alertStats, iocStats, threatLandscape, topPorts, topCves];
  const anyError = queries.some((q) => q.error);
  const allEmpty =
    totalItems === 0 &&
    critical === 0 &&
    totalIocs === 0 &&
    darkWebCount === 0 &&
    timelineData.length === 0;
  const retryAll = () => queries.forEach((q) => q.reload());

  const [exporting, setExporting] = useState(false);
  const [reportError, setReportError] = useState('');
  const onExportReport = async () => {
    setExporting(true);
    setReportError('');
    try {
      await exportFullReportPdf();
    } catch (err) {
      setReportError(err?.message || String(err));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="font-mono text-xl font-bold text-ink">Executive Overview</h1>
          <p className="text-xs text-dim">
            Real-time posture from the ClickHouse corpus · auto-refreshes every 60s
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
            LIVE
          </span>
          <Button
            variant="secondary"
            size="sm"
            icon={FileDown}
            loading={exporting}
            onClick={onExportReport}
            title="Generate a full printable report (PDF) of the whole platform"
          >
            Export full report (PDF)
          </Button>
          {reportError && <p className="w-full text-right text-xs text-red-400">{reportError}</p>}
        </div>
      </div>

      {anyError && allEmpty ? (
        <ErrorState
          title="Dashboard unavailable"
          message="The overview endpoints did not respond. This usually means the backend or ClickHouse is unreachable."
          onRetry={retryAll}
        />
      ) : (
        <>
          {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Threat Items Ingested" value={totalItems} sub="across all live feeds" icon={Waves} accent="cyan" />
        <MetricCard label="Critical Vulnerabilities" value={critical} sub="CVEs flagged CRITICAL" icon={ShieldAlert} accent="red" />
        <MetricCard label="Active Indicators" value={totalIocs} sub="IPs · domains · hashes · URLs" icon={Activity} accent="violet" />
        <MetricCard label="Dark Web / Telegram" value={darkWebCount} sub="onion + telegram mentions" icon={Skull} accent="amber" />
      </div>

      {/* Global attack map */}
      <RealTimeMap />

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Ingestion Volume Timeline" icon={Waves} subtitle="last 14 days" className="xl:col-span-2">
          <TimelineArea data={timelineData} />
        </Card>
        <Card title="Threat Category Breakdown" icon={Globe} subtitle="keyword-classified feeds">
          <CategoryDonut data={categoryData} />
        </Card>
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Severity Distribution" icon={ShieldAlert} subtitle="Alert Sheets">
          <SeverityBar data={severityData} />
        </Card>
        <div className="xl:col-span-2">
          <RecentFeeds limit={8} />
        </div>
      </div>

      {/* Threat & Malware Category Landscape (feature) */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          title="Threat & Malware Category Landscape"
          icon={Skull}
          subtitle="weekly trend · top attack types (click to filter feeds)"
          className="xl:col-span-2"
        >
          <ThreatLandscapePanel data={threatLandscape.data} />
        </Card>
        <TopPorts data={topPorts.data} />
      </div>

      {/* Threat Landscape preview tiles -> dedicated /threat-landscape page */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <OriginPreviewTile />
        <TacticsPreviewTile />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <TopCves data={topCves.data} />
      </div>
        </>
      )}
    </div>
  );
}
