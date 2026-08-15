import React, { useEffect, useMemo, useState } from 'react';
import { ShieldAlert, Eye, Cpu, CheckCircle2, Loader2, Clock, XCircle } from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Table from '../components/ui/Table';
import Loader from '../components/ui/Loader';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import AlertSheetModal from '../components/vulnerabilities/AlertSheetModal';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { onRefresh } from '../utils/events';
import { PAGE_SIZE } from '../config';
import { SEVERITY } from '../utils/format';

const RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * Live strip showing the honest state of the AI sheet generation pipeline
 * (pending / processing / done / failed) from `/api/v1/ai/status`, so analysts
 * can tell at a glance whether CVEs are still being processed or stalled.
 */
function AiPipelineStatus() {
  const status = useApi(() => unwrap(api.getAiStatus()), { refreshMs: 10_000 });
  const [retrying, setRetrying] = useState(false);
  const counts = status.data?.counts || {};
  const total = (counts.pending || 0) + (counts.processing || 0) + (counts.done || 0) + (counts.failed || 0);

  const retryFailed = async () => {
    setRetrying(true);
    try {
      await unwrap(api.retryAiFailed());
      status.reload();
    } finally {
      setRetrying(false);
    }
  };

  if (total === 0) return null;

  const items = [
    { key: 'done', label: 'Done', n: counts.done || 0, icon: CheckCircle2, cls: 'text-emerald-400' },
    { key: 'pending', label: 'Pending', n: counts.pending || 0, icon: Clock, cls: 'text-amber-400' },
    { key: 'processing', label: 'Processing', n: counts.processing || 0, icon: Loader2, cls: 'text-cyan-300', spin: true },
    { key: 'failed', label: 'Failed', n: counts.failed || 0, icon: XCircle, cls: 'text-rose-400' },
  ];

  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-line bg-surface px-4 py-2.5 text-xs">
      <span className="flex items-center gap-1.5 font-mono font-semibold text-faint">
        <Cpu size={14} className="text-cyan-400" /> AI pipeline
      </span>
      {items.map(({ key, label, n, icon: Icon, cls, spin }) => (
        <span key={key} className="flex items-center gap-1.5" title={`${n} CVEs ${label.toLowerCase()}`}>
          <Icon size={13} className={`${cls} ${spin && n > 0 ? 'animate-spin' : ''}`} />
          <span className="font-mono text-ink">{n}</span>
          <span className="text-dim">{label}</span>
        </span>
      ))}
      {(counts.failed || 0) > 0 && (
        <Button size="sm" variant="secondary" disabled={retrying} onClick={retryFailed}>
          {retrying ? 'Retrying…' : `Retry ${counts.failed} failed`}
        </Button>
      )}
      {status.data?.provider && (
        <span className="ml-auto text-dim">
          Provider: <span className="font-mono text-cyan-300">{status.data.provider}</span>
        </span>
      )}
    </div>
  );
}

/**
 * Alert Sheets (/vulnerabilities) — the vulnerability-management view.
 * Lists every tracked CVE (from ClickHouse `vulnerability_alerts`), filters by
 * risk/search, and opens the 4-point Alert Sheet viewer on selection.
 */
export default function Vulnerabilities() {
  const [risk, setRisk] = useState('');
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);
  useEffect(() => setOffset(0), [risk, search]);

  const params = useMemo(
    () => ({ risk_level: risk || undefined, search: search || undefined, limit: PAGE_SIZE, offset }),
    [risk, search, offset]
  );

  const list = useApi(() => unwrap(api.getAlerts(params)), { deps: [JSON.stringify(params), reloadKey] });
  const detail = useAsync((cve) => unwrap(api.getAlert(cve)));

  const openSheet = async (cve) => {
    setSelected(null);
    try {
      const f = await detail.run(cve);
      setSelected(f);
    } catch (e) {
      setSelected({ error: errorText(e) });
    }
  };

  const items = list.data?.items || [];
  const hasMore = items.length === PAGE_SIZE;

  const columns = [
    {
      key: 'vuln_cve',
      label: 'CVE',
      render: (r) => <span className="font-mono text-[13px] font-semibold text-cyan-300">{r.vuln_cve}</span>,
    },
    {
      key: 'risk_level_label',
      label: 'Risk',
      render: (r) => <Badge severity={r.risk_level_label}>{r.risk_level_label}</Badge>,
    },
    {
      key: 'threat_score',
      label: 'Threat score',
      render: (r) => (
        <span className="font-mono" style={{ color: (SEVERITY[r.risk_level_label] || SEVERITY.INFO).hex }}>
          {r.threat_score}
        </span>
      ),
    },
    {
      key: 'exploitation_status',
      label: 'Public PoC',
      render: (r) => (
        <span className="text-xs">{r.exploitation_status?.public_poc_available ? 'Yes' : 'No'}</span>
      ),
    },
    {
      key: 'ts',
      label: 'Updated',
      render: (r) => <span className="text-xs text-dim">{new Date(r.ts).toLocaleString()}</span>,
    },
    {
      key: 'action',
      label: '',
      align: 'right',
      render: (r) => (
        <Button size="sm" variant="secondary" icon={Eye} onClick={() => openSheet(r.vuln_cve)}>
          View
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <ShieldAlert size={20} className="text-cyan-400" /> Alert Sheets
        </h1>
        <p className="text-xs text-dim">
          Vulnerability management · one structured Alert Sheet per CVE · generated by the AI engine
        </p>
      </div>

      {/* Live AI pipeline state (pending/processing/done/failed) */}
      <AiPipelineStatus />

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-line bg-surface p-4">
        <label className="min-w-[200px] flex-1">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">Search CVE / summary</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="CVE-2024-…"
            className="focus-neon w-full rounded-lg border border-line bg-base px-3 py-2 text-sm text-ink placeholder:text-faint"
          />
        </label>
        <label className="min-w-[160px]">
          <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">Risk level</span>
          <select
            value={risk}
            onChange={(e) => setRisk(e.target.value)}
            className="focus-neon w-full rounded-lg border border-line bg-base px-3 py-2 text-sm text-ink"
          >
            <option value="">All risks</option>
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-line bg-surface">
        {list.loading && items.length === 0 ? (
          <Loader label="Loading sheets…" />
        ) : list.error ? (
          <ErrorState title="Failed to load sheets" message={errorText(list.error)} onRetry={list.reload} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No sheets found"
            message="Sheets are created automatically when the ingestion pipeline finds a CVE."
          />
        ) : (
          <>
            <Table columns={columns} data={items} rowKey="vuln_cve" emptyText="No sheets match" />
            <div className="flex justify-center gap-3 border-t border-line p-3">
              <Button variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                Previous
              </Button>
              <Button variant="secondary" disabled={!hasMore} onClick={() => setOffset(offset + PAGE_SIZE)}>
                Load more
              </Button>
            </div>
          </>
        )}
      </div>

      <AlertSheetModal sheet={selected && !selected.error ? selected : null} onClose={() => setSelected(null)} />
    </div>
  );
}
