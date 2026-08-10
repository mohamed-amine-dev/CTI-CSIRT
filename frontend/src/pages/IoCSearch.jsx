import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  ExternalLink,
  Globe,
  Layers,
  Radar,
  Search,
  Server,
  ShieldCheck,
  Tag,
  Zap,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import Loader from '../components/ui/Loader';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { guessIocType, IOC_TYPE_LABELS } from '../utils/iocs';
import { severityFromScore, timeAgo } from '../utils/format';

// Per-source metadata for the enrichment panel grid.
const SOURCE_META = {
  internetdb: { label: 'Shodan InternetDB', icon: Server, accent: 'text-cyan-300' },
  dns: { label: 'DNS over HTTPS', icon: Globe, accent: 'text-violet-300' },
  urlhaus: { label: 'URLhaus (abuse.ch)', icon: Tag, accent: 'text-amber-300' },
  nvd: { label: 'NVD (NIST)', icon: ShieldCheck, accent: 'text-red-300' },
};

function Chip({ children, tone = 'line' }) {
  const tones = {
    line: 'border-line bg-raised text-dim',
    cyan: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
    red: 'border-red-500/30 bg-red-500/10 text-red-300',
  };
  return (
    <span className={`rounded border px-2 py-0.5 font-mono text-xs ${tones[tone]}`}>{children}</span>
  );
}

function SourceHeader({ name, data }) {
  const meta = SOURCE_META[name];
  const Icon = meta.icon;
  const status = data === null ? 'unavailable' : data.found ? 'record' : 'no record';
  const statusCls =
    status === 'record' ? 'text-cyan-300' : status === 'unavailable' ? 'text-amber-300' : 'text-faint';
  return (
    <div className="mb-2.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
      <Icon size={12} className={meta.accent} />
      <span>{meta.label}</span>
      <span className={`ml-auto font-mono ${statusCls}`}>{status}</span>
    </div>
  );
}

function SourceBody({ name, data }) {
  if (data === null) {
    return <p className="text-xs text-dim">Source unavailable — request failed or timed out.</p>;
  }
  if (!data.found) {
    return <p className="text-xs text-dim">{data.detail || 'No record found.'}</p>;
  }

  if (name === 'internetdb') {
    const row = (label, items, tone = 'line') => (
      <div className="mb-3">
        <p className="mb-1.5 text-[11px] text-faint">{label}</p>
        <div className="flex flex-wrap gap-1.5">
          {(items || []).length ? items.map((i) => <Chip key={i} tone={tone}>{i}</Chip>) : <span className="text-xs text-faint">none</span>}
        </div>
      </div>
    );
    return (
      <div>
        {row('Open ports', data.ports)}
        {row('Detected CVEs', data.cves, 'red')}
        {row('Hostnames', data.hostnames)}
        {row('Tags', data.tags)}
        {row('CPEs', data.cpes)}
      </div>
    );
  }

  if (name === 'dns') {
    return (
      <div>
        <p className="mb-1.5 text-[11px] text-faint">Records (A / AAAA / PTR)</p>
        <div className="flex flex-wrap gap-1.5">
          {(data.records || []).map((r) => <Chip key={r}>{r}</Chip>)}
        </div>
      </div>
    );
  }

  if (name === 'urlhaus') {
    return (
      <div className="space-y-2">
        <p className="text-[11px] text-faint">{data.url_count ?? 0} URLs reported</p>
        {(data.urls || []).map((u) => (
          <div key={u.url} className="rounded-md border border-line bg-raised/70 p-2">
            <a href={u.url} target="_blank" rel="noreferrer" className="break-all font-mono text-[11px] text-cyan-300 hover:underline">
              {u.url}
            </a>
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              {u.threat && <Chip tone="red">{u.threat}</Chip>}
              {(u.tags || []).map((t) => <Chip key={t}>{t}</Chip>)}
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (name === 'nvd') {
    return (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          {data.cvss_score != null && (
            <span className="rounded-md bg-red-500/10 px-2 py-1 font-mono text-sm font-bold text-red-300">
              CVSS {data.cvss_score}
            </span>
          )}
          {data.cvss_severity && <Badge severity={data.cvss_severity}>{data.cvss_severity}</Badge>}
          {data.cvss_vector && <span className="break-all font-mono text-[10px] text-faint">{data.cvss_vector}</span>}
        </div>
        {data.description && <p className="text-xs leading-relaxed text-dim">{data.description}</p>}
        {data.published && <p className="text-[11px] text-faint">Published {data.published}</p>}
        {(data.references || []).length > 0 && (
          <div>
            <p className="mb-1 text-[11px] text-faint">References</p>
            <ul className="space-y-1">
              {data.references.map((r) => (
                <li key={r}>
                  <a href={r} target="_blank" rel="noreferrer" className="break-all text-[11px] text-cyan-300 hover:underline">{r}</a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  return null;
}

/**
 * IoC Search (/ioc-search) — analyst lookup engine.
 *  * ClickHouse match -> "do we already know this indicator?" (type, severity)
 *  * Free enrichment  -> VirusTotal-style source panels (InternetDB, DNS,
 *                        URLhaus, NVD) plus links to external deep dives
 *  * Recent indicators -> context of the newest tracked indicators
 */
export default function IoCSearch() {
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get('q') || '');
  const [term, setTerm] = useState(params.get('q') || '');

  const ioc = useAsync((q) => unwrap(api.getIoc(q)));
  const enrich = useAsync((q) => unwrap(api.getEnrich(q)));
  const recent = useApi(() => unwrap(api.getIocs({ limit: 8 })), { deps: [], refreshMs: 60_000 });

  // Sync when the global search bar navigates here with ?q=...
  useEffect(() => {
    const q = params.get('q');
    if (q) {
      setQuery(q);
      setTerm(q);
    }
  }, [params]);

  const onSearch = async (e) => {
    e?.preventDefault();
    const q = term.trim();
    if (!q) return;
    setQuery(q);
    ioc.setData(null); ioc.setError(null);
    enrich.setData(null); enrich.setError(null);
    try { await ioc.run(q); } catch { /* 404 handled below */ }
    try { await enrich.run(q); } catch { /* handled below */ }
  };

  const type = guessIocType(query);
  const iocNotFound = !ioc.loading && ioc.error;
  const known = ioc.data;
  const enrichment = enrich.data;
  const enrichmentCardShown = query && !enrich.loading && (enrichment || enrich.error);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <Radar size={20} className="text-cyan-400" /> IoC Lookup &amp; Enrichment
        </h1>
        <p className="text-xs text-dim">
          Check an indicator against ClickHouse history and free enrichment sources (InternetDB, DNS, URLhaus, NVD)
        </p>
      </div>

      {/* Search */}
      <form onSubmit={onSearch} className="flex flex-wrap gap-3">
        <div className="relative min-w-[260px] flex-1">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder="IP address, domain, URL, file hash or CVE…"
            className="focus-neon w-full rounded-lg border border-line bg-surface py-2.5 pl-9 pr-3 font-mono text-sm text-ink placeholder:font-sans placeholder:text-faint"
          />
        </div>
        <Button variant="primary" type="submit" icon={Search} loading={ioc.loading}>
          Lookup
        </Button>
      </form>

      {/* Result: known indicator */}
      {query && (
        <Card title="ClickHouse Indicator Match" icon={Layers} subtitle={query}>
          {ioc.loading ? (
            <Loader label="Querying ClickHouse…" />
          ) : known ? (
            <div className="flex flex-wrap items-center gap-4">
              <span className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 font-mono text-sm text-cyan-300">
                {known.indicator}
              </span>
              <Badge tone="neutral">{IOC_TYPE_LABELS[known.type] || known.type}</Badge>
              <span className="flex items-center gap-1.5 text-sm font-semibold" style={{ color: severityFromScore(known.severity).hex }}>
                <Zap size={14} className="text-amber-400" /> severity {known.severity.toFixed(1)}
              </span>
              <span className="text-xs text-dim">first seen {timeAgo(known.ts)}</span>
            </div>
          ) : (
            <EmptyState
              icon={Search}
              title={iocNotFound ? 'Not previously tracked' : 'Search to begin'}
              message={
                iocNotFound
                  ? 'No indicator of this type was found in the processed_iocs corpus.'
                  : 'Submit an indicator above to query ClickHouse history and enrichment sources.'
              }
            />
          )}
        </Card>
      )}

      {/* Result: multi-source enrichment */}
      {enrichmentCardShown && (
        <Card title="External Enrichment" icon={Radar} subtitle={`${type} · ${query}`}>
          {enrich.loading ? (
            <Loader label="Querying enrichment sources…" />
          ) : enrich.error ? (
            <p className="text-sm text-dim">{errorText(enrich.error)}</p>
          ) : !enrichment?.sources ? (
            <EmptyState
              icon={Search}
              title={enrichment?.detail || 'No enrichment available'}
              message="No free, key-less source provides enrichment for this indicator type."
            />
          ) : (
            <>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {Object.keys(SOURCE_META).map((name) => (
                  <div key={name} className="rounded-lg border border-line bg-base/50 p-4">
                    <SourceHeader name={name} data={enrichment.sources[name]} />
                    <SourceBody name={name} data={enrichment.sources[name]} />
                  </div>
                ))}
              </div>
              {enrichment.links && Object.keys(enrichment.links).length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line/70 pt-3">
                  <span className="text-[11px] uppercase tracking-wider text-faint">Open in</span>
                  {Object.entries(enrichment.links).map(([label, url]) => (
                    <a
                      key={label}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded border border-line bg-raised px-2.5 py-1 text-xs capitalize text-dim transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                    >
                      {label} <ExternalLink size={11} />
                    </a>
                  ))}
                </div>
              )}
            </>
          )}
        </Card>
      )}

      {/* Recent indicators for context */}
      <Card title="Recently Tracked Indicators" icon={Layers} subtitle="latest from processed_iocs">
        {recent.loading ? (
          <Loader label="Loading…" />
        ) : recent.error ? (
          <ErrorState title="Failed to load recent indicators" message={errorText(recent.error)} onRetry={recent.reload} />
        ) : !recent.data?.items?.length ? (
          <EmptyState
            icon={Layers}
            title="No indicators tracked yet"
            message="Indicators are extracted automatically from every ingested feed. Run a force sync or seed the database to populate this list."
          />
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {recent.data.items.map((i) => (
              <button
                key={i.indicator}
                onClick={() => { setTerm(i.indicator); setQuery(i.indicator); onSearch(); }}
                className="flex items-center gap-3 rounded-lg border border-line bg-base/50 px-3 py-2 text-left transition-colors hover:border-cyan-500/30"
                title="Look up this indicator"
              >
                <span className="font-mono text-xs text-cyan-300">{i.indicator}</span>
                <span className="ml-auto rounded bg-raised px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-faint">
                  {IOC_TYPE_LABELS[i.type] || i.type}
                </span>
                <span className="text-[10px] text-faint">{timeAgo(i.ts)}</span>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
