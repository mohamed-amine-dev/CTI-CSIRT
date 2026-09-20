import React, { useEffect, useMemo, useState } from 'react';
import {
  ShieldAlert,
  Eye,
  Cpu,
  CheckCircle2,
  Loader2,
  Clock,
  XCircle,
  SlidersHorizontal,
  Search,
} from 'lucide-react';

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
 * AI pipeline status strip (compact inline widget).
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
    { key: 'done',       label: 'Generated',  n: counts.done       || 0, icon: CheckCircle2, cls: 'text-emerald-400' },
    { key: 'pending',    label: 'Queued',      n: counts.pending    || 0, icon: Clock,        cls: 'text-amber-400' },
    { key: 'processing', label: 'Processing',  n: counts.processing || 0, icon: Loader2,      cls: 'text-primary', spin: true },
    { key: 'failed',     label: 'Failed',      n: counts.failed     || 0, icon: XCircle,      cls: 'text-red-400' },
  ];

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-line bg-surface px-5 py-3 text-xs">
      <div className="flex items-center gap-2">
        <Cpu size={13} className="text-primary" />
        <span className="font-semibold text-dim">AI Pipeline</span>
      </div>
      {items.map(({ key, label, n, icon: Icon, cls, spin }) => (
        <div key={key} className="flex items-center gap-1.5">
          <Icon size={13} className={`${cls} ${spin && n > 0 ? 'animate-spin' : ''}`} />
          <span className="font-mono font-semibold text-ink tabular-nums">{n}</span>
          <span className="text-faint">{label}</span>
        </div>
      ))}
      {(counts.failed || 0) > 0 && (
        <Button size="sm" variant="danger" disabled={retrying} onClick={retryFailed}>
          {retrying ? 'Retrying…' : `Retry ${counts.failed} failed`}
        </Button>
      )}
      {status.data?.provider && (
        <span className="ml-auto rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary">
          {status.data.provider}
        </span>
      )}
    </div>
  );
}

/**
 * Alert Sheets (/vulnerabilities) — vulnerability management view.
 */
export default function Vulnerabilities() {
  const [risk,      setRisk]      = useState('');
  const [search,    setSearch]    = useState('');
  const [offset,    setOffset]    = useState(0);
  const [selected,  setSelected]  = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);
  useEffect(() => setOffset(0), [risk, search]);

  const params = useMemo(
    () => ({ risk_level: risk || undefined, search: search || undefined, limit: PAGE_SIZE, offset }),
    [risk, search, offset],
  );

  const list   = useApi(() => unwrap(api.getAlerts(params)), { deps: [JSON.stringify(params), reloadKey] });
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

  const items   = list.data?.items || [];
  const total   = list.data?.total ?? null;
  const hasMore = items.length === PAGE_SIZE;

  const columns = [
    {
      key: 'vuln_cve',
      label: 'CVE',
      render: (r) => (
        <span className="font-mono text-[13px] font-semibold text-primary">
          {r.vuln_cve}
        </span>
      ),
    },
    {
      key: 'risk_level_label',
      label: 'Risk',
      render: (r) => <Badge severity={r.risk_level_label}>{r.risk_level_label}</Badge>,
    },
    {
      key: 'threat_score',
      label: 'Score',
      render: (r) => (
        <span
          className="font-mono text-sm font-semibold tabular-nums"
          style={{ color: (SEVERITY[r.risk_level_label] || SEVERITY.INFO).hex }}
        >
          {r.threat_score}
        </span>
      ),
    },
    {
      key: 'exploitation_status',
      label: 'Public PoC',
      render: (r) => (
        <span className={`text-xs font-medium ${r.exploitation_status?.public_poc_available ? 'text-red-400' : 'text-faint'}`}>
          {r.exploitation_status?.public_poc_available ? '⚠ Yes' : 'No'}
        </span>
      ),
    },
    {
      key: 'ts',
      label: 'Updated',
      render: (r) => (
        <span className="text-xs text-faint">
          {new Date(r.ts).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'action',
      label: '',
      align: 'right',
      render: (r) => (
        <Button size="sm" variant="ghost" icon={Eye} onClick={() => openSheet(r.vuln_cve)}>
          View Sheet
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
            <ShieldAlert size={16} className="text-primary" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">Alert Sheets</h1>
            <p className="text-xs text-faint">
              Vulnerability management · one structured sheet per CVE · AI-generated
            </p>
          </div>
        </div>
        {total !== null && (
          <span className="rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-dim">
            {total.toLocaleString()} sheets
          </span>
        )}
      </div>

      {/* AI pipeline status strip */}
      <AiPipelineStatus />

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="mb-1 flex w-full items-center gap-2 text-[11px] font-semibold uppercase tracking-widest text-faint">
          <SlidersHorizontal size={12} />
          Filters
        </div>
        <div className="relative min-w-[220px] flex-1">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE or summary…"
            className="focus-ring w-full rounded-lg border border-line bg-base py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint"
          />
        </div>
        <div className="min-w-[160px]">
          <select
            value={risk}
            onChange={(e) => setRisk(e.target.value)}
            className="focus-ring w-full rounded-lg border border-line bg-base px-3 py-2 text-sm text-ink"
          >
            <option value="">All risk levels</option>
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </div>
        {(risk || search) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { setRisk(''); setSearch(''); }}
          >
            Clear filters
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-xl border border-line bg-surface overflow-hidden">
        {list.loading && items.length === 0 ? (
          <Loader label="Loading alert sheets…" />
        ) : list.error ? (
          <ErrorState
            title="Failed to load sheets"
            message={errorText(list.error)}
            onRetry={list.reload}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No sheets found"
            message="Alert Sheets are generated automatically when the ingestion pipeline detects a CVE."
          />
        ) : (
          <>
            <Table columns={columns} data={items} rowKey="vuln_cve" emptyText="No sheets match" />
            <div className="flex items-center justify-between border-t border-line px-5 py-3">
              <span className="text-xs text-faint">
                Showing {offset + 1}–{offset + items.length}
                {total !== null ? ` of ${total.toLocaleString()}` : ''}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  Previous
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={!hasMore}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </div>

      <AlertSheetModal
        sheet={selected && !selected.error ? selected : null}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
