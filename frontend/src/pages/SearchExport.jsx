import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Database,
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  Search,
  ShieldAlert,
  ShieldCheck,
  RadioTower,
  Bell,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import Loader from '../components/ui/Loader';
import { api, downloadBlob, errorText, unwrap } from '../services/api';
import { useAsync } from '../hooks/useApi';
import { IOC_TYPE_LABELS } from '../utils/iocs';
import { severityFromScore, severityStyle, timeAgo, titleCase } from '../utils/format';

const KINDS = [
  { value: '', label: 'All corpora' },
  { value: 'feeds', label: 'Live feeds' },
  { value: 'iocs', label: 'Indicators' },
  { value: 'alerts', label: "Fiches d'Alerte" },
];

const RESOURCES = [
  {
    key: 'alerts',
    title: "Fiches d'Alerte",
    icon: ShieldAlert,
    desc: 'AI-generated vulnerability fiches (CVE, risk, remediation).',
    stix: true,
    filter: {
      label: 'Risk level',
      options: ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
    },
  },
  {
    key: 'iocs',
    title: 'Indicators',
    icon: ShieldCheck,
    desc: 'Normalised indicators (IPs, hashes, domains…) from every feed.',
    stix: true,
    filter: {
      label: 'IoC type',
      options: ['', ...Object.keys(IOC_TYPE_LABELS)],
    },
  },
  {
    key: 'feeds',
    title: 'Live feeds',
    icon: RadioTower,
    desc: 'Raw threat intel items with computed category.',
    stix: true,
    filter: {
      label: 'Category',
      options: ['', 'Ransomware', 'Phishing', 'Malware', 'Exploit', 'Vulnerability', 'Other'],
    },
  },
  {
    key: 'notifications',
    title: 'Notifications',
    icon: Bell,
    desc: 'In-app alert feed (KEV + risk threshold events).',
    stix: false,
  },
];

const FORMATS = [
  { fmt: 'csv', label: 'CSV', icon: FileSpreadsheet },
  { fmt: 'json', label: 'JSON', icon: FileJson },
  { fmt: 'stix', label: 'STIX', icon: FileText },
];

/**
 * Search & Export hub (/search) — Phase 6.
 *  * Global search: one query across feeds, indicators and fiches, grouped.
 *  * Export hub: bulk download of any read model as CSV / JSON / STIX 2.1,
 *    honouring the same filters the list endpoints accept.
 */
export default function SearchExport() {
  const [term, setTerm] = useState('');
  const [kind, setKind] = useState('');
  const [submitted, setSubmitted] = useState('');

  const search = useAsync((q) => unwrap(api.searchAll(q, kind)));

  const [busy, setBusy] = useState({});
  const [done, setDone] = useState({});
  const [errors, setErrors] = useState({});
  const [filters, setFilters] = useState({ alerts: '', iocs: '', feeds: '', notifications: false });

  const onSearch = (e) => {
    e?.preventDefault();
    const q = term.trim();
    if (!q) return;
    setSubmitted(q);
    search.run(q);
  };

  const onExport = async (res, fmt) => {
    setBusy((b) => ({ ...b, [`${res}-${fmt}`]: true }));
    setErrors((e) => ({ ...e, [res]: null }));
    try {
      const params = { resource: res, format: fmt, limit: 10000 };
      if (res === 'alerts' && filters.alerts) params.risk_level = filters.alerts;
      if (res === 'iocs' && filters.iocs) params.type = filters.iocs;
      if (res === 'feeds' && filters.feeds) params.category = filters.feeds;
      if (res === 'notifications' && filters.notifications) params.unread_only = true;
      const response = await api.exportResource(params);
      downloadBlob(response);
      setDone((d) => ({ ...d, [res]: fmt }));
    } catch (err) {
      const blob = err.response?.data;
      const text = blob instanceof Blob ? await blob.text().catch(() => '') : '';
      setErrors((e) => ({ ...e, [res]: text ? `${text}${text.includes('detail') ? '' : ''}` : errorText(err) }));
    } finally {
      setBusy((b) => ({ ...b, [`${res}-${fmt}`]: false }));
    }
  };

  const results = search.data?.results;
  const total = search.data?.total || 0;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <Database size={20} className="text-cyan-400" /> Search &amp; Export Hub
        </h1>
        <p className="text-xs text-dim">One query across every corpus — and bulk analyst-ready exports</p>
      </div>

      {/* ---- Global search ---- */}
      <Card title="Global search" icon={Search} subtitle="feeds + indicators + fiches in one query">
        <form onSubmit={onSearch} className="flex flex-wrap gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
            <input
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              placeholder="CVE, IP, domain, hash, keyword…"
              className="focus-neon w-full rounded-lg border border-line bg-base py-2.5 pl-9 pr-3 font-mono text-sm text-ink placeholder:font-sans placeholder:text-faint"
            />
          </div>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="focus-neon rounded-lg border border-line bg-raised px-3 py-2 text-sm text-ink"
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>{k.label}</option>
            ))}
          </select>
          <Button variant="primary" type="submit" icon={Search} loading={search.loading}>
            Search
          </Button>
        </form>

        {submitted && (
          <div className="mt-5 space-y-3">
            <p className="text-xs text-dim">
              {search.loading
                ? 'Searching…'
                : search.error
                  ? 'Search failed.'
                  : `${total} hit${total === 1 ? '' : 's'} for “${submitted}”`}
            </p>
            {search.error && <ErrorState title="Search failed" message={errorText(search.error)} onRetry={onSearch} />}
            {results && (
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                <SearchPane
                  title="Live feeds"
                  count={results.feeds.length}
                  empty="No feed items matched"
                  items={results.feeds.map((r) => ({
                    key: `${r.kind}-${r.source}-${r.ts}`,
                    primary: r.source,
                    meta: r.category,
                    secondary: (r.snippet || r.url || '').slice(0, 140),
                    ts: r.ts,
                    to: '/feeds',
                  }))}
                />
                <SearchPane
                  title="Indicators"
                  count={results.iocs.length}
                  empty="No indicators matched"
                  items={results.iocs.map((r) => ({
                    key: `${r.kind}-${r.indicator}`,
                    primary: r.indicator,
                    meta: IOC_TYPE_LABELS[r.type] || r.type,
                    score: r.severity,
                    ts: r.ts,
                    to: `/ioc-search?q=${encodeURIComponent(r.indicator)}`,
                  }))}
                />
                <SearchPane
                  title="Fiches d'Alerte"
                  count={results.alerts.length}
                  empty="No fiches matched"
                  items={results.alerts.map((r) => ({
                    key: `${r.kind}-${r.vuln_cve}`,
                    primary: r.vuln_cve,
                    meta: r.risk_level?.risk_level || r.risk_level,
                    score: r.threat_score,
                    secondary: (r.snippet || '').slice(0, 140),
                    ts: r.ts,
                    to: '/vulnerabilities',
                  }))}
                />
              </div>
            )}
          </div>
        )}
      </Card>

      {/* ---- Export hub ---- */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {RESOURCES.map((res) => (
          <Card key={res.key} title={res.title} icon={res.icon} subtitle={res.desc}>
            <div className="space-y-4">
              {res.filter && (
                <label className="flex items-center gap-2 text-xs text-dim">
                  <span className="w-24 shrink-0">{res.filter.label}</span>
                  <select
                    value={filters[res.key]}
                    onChange={(e) => setFilters((f) => ({ ...f, [res.key]: e.target.value }))}
                    className="focus-neon flex-1 rounded-lg border border-line bg-raised px-2.5 py-1.5 text-sm text-ink"
                  >
                    {res.filter.options.map((o) => (
                      <option key={o} value={o}>{o || 'All'}</option>
                    ))}
                  </select>
                </label>
              )}
              {res.key === 'notifications' && (
                <label className="flex items-center gap-2 text-xs text-dim">
                  <input
                    type="checkbox"
                    checked={Boolean(filters.notifications)}
                    onChange={(e) => setFilters((f) => ({ ...f, notifications: e.target.checked }))}
                    className="h-3.5 w-3.5 accent-cyan-500"
                  />
                  Unread only
                </label>
              )}
              {errors[res.key] && <p className="text-xs text-red-400">{errors[res.key]}</p>}
              {done[res.key] && (
                <p className="text-xs text-emerald-400">
                  Exported as {done[res.key].toUpperCase()} — check your downloads.
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                {FORMATS.filter((f) => f.fmt !== 'stix' || res.stix).map((f) => (
                  <Button
                    key={f.fmt}
                    size="sm"
                    variant={done[res.key] === f.fmt ? 'primary' : 'secondary'}
                    icon={f.icon}
                    loading={Boolean(busy[`${res.key}-${f.fmt}`])}
                    onClick={() => onExport(res.key, f.fmt)}
                  >
                    {f.label}
                  </Button>
                ))}
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

/** One grouped search result pane. */
function SearchPane({ title, count, empty, items }) {
  return (
    <div className="rounded-lg border border-line bg-base/40 p-3">
      <div className="mb-2 flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-faint">{title}</h4>
        <span className="rounded bg-raised px-1.5 py-0.5 text-[10px] text-cyan-300">{count}</span>
      </div>
      {count === 0 ? (
        <p className="text-xs text-faint">{empty}</p>
      ) : (
        <ul className="space-y-1.5">
          {items.slice(0, 6).map((it) => (
            <li key={it.key}>
              <Link
                to={it.to}
                className="block rounded-md border border-transparent px-2 py-1.5 transition-colors hover:border-cyan-500/30 hover:bg-raised"
              >
                <div className="flex items-center gap-2">
                  <span className="truncate font-mono text-xs text-cyan-300">{it.primary}</span>
                  {it.meta && <Badge tone="neutral">{String(it.meta)}</Badge>}
                  {typeof it.score === 'number' && (
                    <span className="ml-auto text-[10px] font-semibold" style={{ color: severityFromScore(it.score).hex }}>
                      {it.score.toFixed(1)}
                    </span>
                  )}
                  {it.ts && <span className="ml-auto text-[10px] text-faint">{timeAgo(it.ts)}</span>}
                </div>
                {it.secondary && <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-dim">{it.secondary}</p>}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
