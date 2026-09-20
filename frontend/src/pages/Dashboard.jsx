import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  FileDown,
  Globe,
  LayoutDashboard,
  ShieldAlert,
  Skull,
  TrendingUp,
  Waves,
} from 'lucide-react';

import Card from '../components/ui/Card';
import ErrorState from '../components/ui/ErrorState';
import Button from '../components/ui/Button';
import MetricCard from '../components/dashboard/MetricCard';
import RealTimeMap from '../components/dashboard/RealTimeMap';
import RecentFeeds from '../components/dashboard/RecentFeeds';
import ThreatLandscapePanel from '../components/dashboard/ThreatLandscapePanel';
import AiPipelineCard from '../components/dashboard/AiPipelineCard';
import GeoCoverageCard from '../components/dashboard/GeoCoverageCard';
import IocTypesPanel from '../components/dashboard/IocTypesPanel';
import { TopPorts, TopCves } from '../components/dashboard/ExposurePanels';
import { CategoryDonut, SeverityBar, TimelineArea } from '../components/dashboard/ThreatCharts';
import { OriginPreviewTile, TacticsPreviewTile } from '../components/dashboard/ThreatLandscapePreviews';
import { useApi } from '../hooks/useApi';
import { api, unwrap } from '../services/api';
import { onRefresh } from '../utils/events';
import { exportFullReportPdf } from '../utils/report';

/**
 * Section heading used between dashboard sections.
 */
function SectionHead({ title, description }) {
  return (
    <div className="flex items-end justify-between">
      <div>
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {description && (
          <p className="mt-0.5 text-xs text-faint">{description}</p>
        )}
      </div>
    </div>
  );
}

/**
 * Executive Overview (/dashboard) — the KPI + charts landing view.
 */
export default function Dashboard() {
  const [reloadKey, setReloadKey] = useState(0);
  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);

  const sources       = useApi(() => unwrap(api.getFeedSources()),         { deps: [reloadKey], refreshMs: 60_000 });
  const categories    = useApi(() => unwrap(api.getFeedCategories()),      { deps: [reloadKey], refreshMs: 60_000 });
  const timeline      = useApi(() => unwrap(api.getFeedTimeline(14)),      { deps: [reloadKey], refreshMs: 60_000 });
  const alertStats    = useApi(() => unwrap(api.getAlertStats()),          { deps: [reloadKey], refreshMs: 60_000 });
  const iocStats      = useApi(() => unwrap(api.getIocStats()),            { deps: [reloadKey], refreshMs: 60_000 });
  const threatLandscape = useApi(() => unwrap(api.getThreatLandscape(60)), { deps: [reloadKey], refreshMs: 60_000 });
  const topPorts      = useApi(() => unwrap(api.getTopPorts(60)),          { deps: [reloadKey], refreshMs: 60_000 });
  const topCves       = useApi(() => unwrap(api.getTopCves(60)),           { deps: [reloadKey], refreshMs: 60_000 });

  const sourceMap    = sources.data?.sources || {};
  const totalItems   = Object.values(sourceMap).reduce((s, n) => s + n, 0);
  const sourceCount  = Object.keys(sourceMap).length;
  const severityByRisk = alertStats.data?.by_risk_level || {};
  const critical     = severityByRisk.CRITICAL || 0;
  const totalAlerts  = Object.values(severityByRisk).reduce((s, n) => s + n, 0);
  const totalIocs    = Object.values(iocStats.data?.by_type || {}).reduce((s, n) => s + n, 0);
  const darkWebCount = (sourceMap['DARKWEB-ONION'] || 0) + (sourceMap['TELEGRAM'] || 0);

  const categoryData  = Object.entries(categories.data?.by_category || {}).map(([name, value]) => ({ name, value }));
  const severityData  = Object.entries(severityByRisk).map(([name, value]) => ({ name, value }));
  const timelineData  = timeline.data?.timeline || [];

  // Sparkline + day-over-day delta for ingestion card
  const ingestSpark = useMemo(
    () => timelineData.map((d) => Number(d.count) || 0),
    [timelineData],
  );
  let ingestDelta = null;
  if (ingestSpark.length >= 2) {
    const last = ingestSpark[ingestSpark.length - 1];
    const prev = ingestSpark[ingestSpark.length - 2];
    if (prev > 0) ingestDelta = { pct: ((last - prev) / prev) * 100, good: last >= prev };
  }

  const queries   = [sources, categories, timeline, alertStats, iocStats, threatLandscape, topPorts, topCves];
  const anyError  = queries.some((q) => q.error);
  const allEmpty  = totalItems === 0 && critical === 0 && totalIocs === 0 && darkWebCount === 0 && timelineData.length === 0;
  const retryAll  = () => queries.forEach((q) => q.reload());

  const [exporting, setExporting]     = useState(false);
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
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
            <LayoutDashboard size={16} className="text-primary" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">Executive Overview</h1>
            <p className="text-xs text-faint">
              Real-time posture · auto-refreshes every 60s · {sourceCount > 0 ? `${sourceCount} live feeds` : 'connecting…'}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[11px] font-medium text-emerald-400">LIVE</span>
          </div>
          <Button
            variant="secondary"
            size="sm"
            icon={FileDown}
            loading={exporting}
            onClick={onExportReport}
            title="Export a full PDF report"
          >
            Export Report
          </Button>
        </div>
        {reportError && (
          <p className="w-full text-right text-xs text-red-400">{reportError}</p>
        )}
      </div>

      {anyError && allEmpty ? (
        <ErrorState
          title="Dashboard unavailable"
          message="The overview endpoints did not respond. This usually means the backend or ClickHouse is unreachable."
          onRetry={retryAll}
        />
      ) : (
        <>
          {/* ── KPI row ─────────────────────────────────────────────────── */}
          <section className="space-y-3">
            <SectionHead title="Key Performance Indicators" description="Live corpus metrics" />
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <MetricCard
                label="Threat Items Ingested"
                value={totalItems}
                sub={sourceCount ? `across ${sourceCount} live feeds` : 'across all live feeds'}
                icon={Waves}
                accent="blue"
                spark={ingestSpark}
                delta={ingestDelta}
              />
              <MetricCard
                label="Critical Vulnerabilities"
                value={critical}
                sub={
                  totalAlerts
                    ? `${Math.round((critical / totalAlerts) * 100)}% of ${totalAlerts.toLocaleString()} alert sheets`
                    : 'CVEs flagged CRITICAL'
                }
                icon={ShieldAlert}
                accent="red"
              />
              <MetricCard
                label="Active Indicators"
                value={totalIocs}
                sub="IPs · domains · hashes · URLs"
                icon={Activity}
                accent="violet"
              />
              <MetricCard
                label="Dark Web Mentions"
                value={darkWebCount}
                sub="onion + telegram channel"
                icon={Skull}
                accent="amber"
              />
            </div>
          </section>

          {/* ── Platform Intelligence ────────────────────────────────────── */}
          <section className="space-y-3">
            <SectionHead
              title="Platform Intelligence"
              description="AI pipeline · geolocation coverage · indicator breakdown"
            />
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <AiPipelineCard />
              <GeoCoverageCard />
              <IocTypesPanel byType={iocStats.data?.by_type || {}} />
            </div>
          </section>

          {/* ── Global Attack Map ────────────────────────────────────────── */}
          <section className="space-y-3">
            <SectionHead
              title="Global Attack Map"
              description="Malicious IP origin countries · last 60 days"
            />
            <RealTimeMap />
          </section>

          {/* ── Threat Analysis ──────────────────────────────────────────── */}
          <section className="space-y-3">
            <SectionHead
              title="Threat Analysis"
              description="Ingestion trend · category distribution · severity breakdown"
            />
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Card
                title="Ingestion Volume"
                icon={TrendingUp}
                subtitle="last 14 days"
                className="xl:col-span-2"
              >
                <TimelineArea data={timelineData} />
              </Card>
              <Card title="Threat Categories" icon={Globe} subtitle="keyword-classified">
                <CategoryDonut data={categoryData} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Card title="Severity Distribution" icon={ShieldAlert} subtitle="Alert Sheets by risk level">
                <SeverityBar data={severityData} />
              </Card>
              <div className="xl:col-span-2">
                <RecentFeeds limit={8} />
              </div>
            </div>
          </section>

          {/* ── Landscape & Exposure ─────────────────────────────────────── */}
          <section className="space-y-3">
            <SectionHead
              title="Threat Landscape & Exposure"
              description="Attack categories trend · top exposed ports · recent CVEs"
            />
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Card
                title="Threat & Malware Category Landscape"
                icon={Skull}
                subtitle="weekly trend · top attack types"
                className="xl:col-span-2"
              >
                <ThreatLandscapePanel data={threatLandscape.data} />
              </Card>
              <TopPorts data={topPorts.data} />
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              <OriginPreviewTile />
              <TacticsPreviewTile />
            </div>

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <TopCves data={topCves.data} />
            </div>
          </section>
        </>
      )}
    </div>
  );
}