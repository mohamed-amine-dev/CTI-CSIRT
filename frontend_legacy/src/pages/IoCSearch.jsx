import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Bug,
  ExternalLink,
  Globe,
  History,
  Layers,
  Radar,
  Search,
  Server,
  ShieldCheck,
  Tag,
  Users,
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

// Per-source metadata for enrichment panels
const SOURCE_META = {
  internetdb: { label: 'Shodan InternetDB',   icon: Server,      accent: 'text-primary' },
  dns:        { label: 'DNS Resolution',       icon: Globe,       accent: 'text-violet-400' },
  urlhaus:    { label: 'URLhaus (abuse.ch)',   icon: Tag,         accent: 'text-amber-400' },
  nvd:        { label: 'NVD (NIST)',           icon: ShieldCheck, accent: 'text-red-400' },
};

// IOC type -> Chip tone (mirrors the indicator taxonomy colours)
const TYPE_TONE = {
  cve: 'red',
  ipv4: 'blue', ipv6: 'blue', cidr: 'blue',
  domain: 'blue', url: 'blue',
  sha256: 'green', sha1: 'green', md5: 'green',
  email: 'neutral', ja3: 'neutral',
};

function Chip({ children, tone = 'neutral' }) {
  const tones = {
    neutral: 'border border-line bg-raised text-dim',
    blue:    'border border-primary/30 bg-primary/10 text-primary',
    red:     'border border-red-500/30 bg-red-500/10 text-red-400',
    green:   'border border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
  };
  return (
    <span className={`rounded-md px-2 py-0.5 font-mono text-[11px] ${tones[tone] || tones.neutral}`}>
      {children}
    </span>
  );
}

function SourceHeader({ name, data }) {
  const meta   = SOURCE_META[name];
  const Icon   = meta.icon;
  const status = data === null ? 'unavailable' : data.found ? 'found' : 'not found';
  const statusCls =
    status === 'found'       ? 'text-emerald-400' :
    status === 'unavailable' ? 'text-amber-400' :
    'text-faint';

  return (
    <div className="mb-3 flex items-center justify-between border-b border-line pb-3">
      <div className="flex items-center gap-2">
        <Icon size={14} className={meta.accent} />
        <span className="text-sm font-semibold text-ink">{meta.label}</span>
      </div>
      <span className={`text-xs font-medium ${statusCls}`}>
        {status === 'found' ? '● Record found' : status === 'unavailable' ? '○ Unavailable' : '○ No record'}
      </span>
    </div>
  );
}

function SourceBody({ name, data }) {
  if (data === null) {
    return (
      <p className="text-xs text-faint">Source unavailable — request timed out or failed.</p>
    );
  }
  if (!data.found) {
    return (
      <p className="text-xs text-faint">{data.detail || 'No record found for this indicator.'}</p>
    );
  }

  if (name === 'internetdb') {
    const row = (label, items, tone = 'neutral') => (
      <div className="mb-3">
        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
          {label}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {(items || []).length
            ? items.map((i) => <Chip key={i} tone={tone}>{i}</Chip>)
            : <span className="text-xs text-faint">none</span>}
        </div>
      </div>
    );
    return (
      <div>
        {row('Open Ports',    data.ports)}
        {row('Detected CVEs', data.cves,      'red')}
        {row('Hostnames',     data.hostnames, 'blue')}
        {row('Tags',          data.tags)}
        {row('CPEs',          data.cpes)}
      </div>
    );
  }

  if (name === 'dns') {
    return (
      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-faint">
          Records (A / AAAA / PTR)
        </p>
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
          <div key={u.url} className="rounded-lg border border-line bg-base/60 p-3">
            <a
              href={u.url}
              target="_blank"
              rel="noreferrer"
              className="break-all font-mono text-[11px] text-primary hover:underline"
            >
              {u.url}
            </a>
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
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
            <span className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 font-mono text-sm font-bold text-red-400">
              CVSS {data.cvss_score}
            </span>
          )}
          {data.cvss_severity && (
            <Badge severity={data.cvss_severity}>{data.cvss_severity}</Badge>
          )}
          {data.cvss_vector && (
            <span className="break-all font-mono text-[10px] text-faint">
              {data.cvss_vector}
            </span>
          )}
        </div>
        {data.description && (
          <p className="text-xs leading-relaxed text-dim">{data.description}</p>
        )}
        {data.published && (
          <p className="text-[11px] text-faint">Published: {data.published}</p>
        )}
        {(data.references || []).length > 0 && (
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
              References
            </p>
            <ul className="space-y-1">
              {data.references.map((r) => (
                <li key={r}>
                  <a
                    href={r}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 break-all text-[11px] text-primary hover:underline"
                  >
                    {r} <ExternalLink size={10} className="shrink-0" />
                  </a>
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
 */
export default function IoCSearch() {
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get('q') || '');
  const [term,  setTerm]  = useState(params.get('q') || '');

  const ioc    = useAsync((q) => unwrap(api.getIoc(q)));
  const enrich = useAsync((q) => unwrap(api.getEnrich(q)));
  const recent = useApi(() => unwrap(api.getRecentIocs(10)), { deps: [], refreshMs: 60_000 });

  // Sync when global search bar navigates here with ?q=…
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
    ioc.setData(null);    ioc.setError(null);
    enrich.setData(null); enrich.setError(null);
    try { await ioc.run(q); }    catch { /* 404 handled below */ }
    try { await enrich.run(q); } catch { /* handled below */  }
  };

  const type               = guessIocType(query);
  const iocNotFound        = !ioc.loading && ioc.error;
  const known              = ioc.data;
  const enrichment         = enrich.data;
  const enrichmentShown    = query && !enrich.loading && (enrichment || enrich.error);

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
          <Radar size={16} className="text-primary" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-ink">IoC Lookup & Enrichment</h1>
          <p className="text-xs text-faint">
            Shodan InternetDB · DNS · URLhaus · NVD — no API key required
          </p>
        </div>
      </div>

      {/* Search bar */}
      <form
        onSubmit={onSearch}
        className="flex flex-wrap gap-3 rounded-xl border border-line bg-surface p-4"
      >
        <div className="relative min-w-[260px] flex-1">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder="Enter IP address, domain, URL, file hash or CVE…"
            className="focus-ring w-full rounded-lg border border-line bg-base py-2.5 pl-9 pr-3 font-mono text-sm text-ink placeholder:font-sans placeholder:text-faint"
          />
        </div>
        <Button variant="primary" type="submit" icon={Search} loading={ioc.loading || enrich.loading}>
          Lookup Indicator
        </Button>
      </form>

      {/* ClickHouse match result */}
      {query && (
        <Card title="Internal Corpus Match" icon={Layers} subtitle={`Querying processed_iocs for: ${query}`}>
          {ioc.loading ? (
            <Loader label="Querying ClickHouse corpus…" />
          ) : known ? (
            <>
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2 rounded-lg border border-primary/25 bg-primary/10 px-4 py-2.5">
                <span className="font-mono text-sm font-semibold text-primary">
                  {known.indicator}
                </span>
              </div>
              <Badge tone="neutral">{IOC_TYPE_LABELS[known.type] || known.type}</Badge>
              <div
                className="flex items-center gap-1.5 text-sm font-semibold"
                style={{ color: severityFromScore(known.severity).hex }}
              >
                <Zap size={13} />
                Severity {known.severity.toFixed(1)} / 10
              </div>
              <span className="text-xs text-faint">First seen {timeAgo(known.ts)}</span>
            </div>

            {/* Actor / malware cross-links from the platform's own corpus */}
            {(known.actors?.length > 0 || known.malware) && (
              <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
                {known.malware && (
                  <Link
                    to={`/malware/${encodeURIComponent(known.malware.stix_id)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-1.5 text-xs font-medium text-violet-300 transition-colors hover:border-violet-400/50"
                  >
                    <Bug size={12} />
                    Matches known tool: {known.malware.name}
                  </Link>
                )}
                {known.actors.map((a) => (
                  <Link
                    key={a.stix_id}
                    to={`/actors?actor=${encodeURIComponent(a.stix_id)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary transition-colors hover:border-primary/50"
                  >
                    <Users size={12} />
                    Associated with {a.name}
                  </Link>
                ))}
              </div>
            )}
            </>
          ) : (
            <EmptyState
              icon={Search}
              title={iocNotFound ? 'Not in corpus' : 'Submit to search'}
              message={
                iocNotFound
                  ? 'This indicator was not found in the processed_iocs table. It may be new or not yet ingested.'
                  : 'Submit an indicator above to query ClickHouse history and enrichment sources.'
              }
            />
          )}
        </Card>
      )}

      {/* Multi-source enrichment */}
      {enrichmentShown && (
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
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {Object.keys(SOURCE_META).map((name) => (
                  <div
                    key={name}
                    className="rounded-xl border border-line bg-base/60 p-4"
                  >
                    <SourceHeader name={name} data={enrichment.sources[name]} />
                    <SourceBody   name={name} data={enrichment.sources[name]} />
                  </div>
                ))}
              </div>

              {/* External deep-dive links */}
              {enrichment.links && Object.keys(enrichment.links).length > 0 && (
                <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
                  <span className="text-[11px] font-semibold uppercase tracking-widest text-faint">
                    Open in
                  </span>
                  {Object.entries(enrichment.links).map(([label, url]) => (
                    <a
                      key={label}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 rounded-lg border border-line bg-raised px-3 py-1.5 text-xs capitalize text-dim transition-colors hover:border-primary/30 hover:text-primary"
                    >
                      {label}
                      <ExternalLink size={11} />
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* Recent indicators */}
      <Card
        title="Recently Tracked Indicators"
        icon={History}
        subtitle="latest from processed_iocs · click to look up"
      >
        {recent.loading ? (
          <Loader label="Loading recent indicators…" />
        ) : recent.error ? (
          <ErrorState
            title="Failed to load recent indicators"
            message={errorText(recent.error)}
            onRetry={recent.reload}
          />
        ) : !recent.data?.items?.length ? (
          <EmptyState
            icon={Layers}
            title="No indicators tracked yet"
            message="Indicators are extracted automatically from every ingested feed. Run a Force Sync to populate."
          />
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {recent.data.items.map((i) => (
              <button
                key={i.indicator}
                onClick={() => {
                  setTerm(i.indicator);
                  setQuery(i.indicator);
                  onSearch();
                }}
                className="flex items-center gap-3 rounded-lg border border-line bg-base/50 px-4 py-2.5 text-left transition-all hover:border-primary/30 hover:bg-raised"
                title="Look up this indicator"
              >
                <span className="font-mono text-xs text-primary truncate flex-1">
                  {i.indicator}
                </span>
                <span
                  className="flex shrink-0 items-center gap-1.5 text-[10px] font-semibold"
                  style={{ color: severityFromScore(i.severity).hex }}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${severityFromScore(i.severity).dot}`} />
                  {i.severity.toFixed(1)}
                </span>
                <Chip tone={TYPE_TONE[i.type] || 'neutral'}>
                  {IOC_TYPE_LABELS[i.type] || i.type}
                </Chip>
                <span className="shrink-0 text-[10px] text-faint">{timeAgo(i.ts)}</span>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
