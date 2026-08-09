import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Globe,
  Layers,
  Radar,
  Search,
  Server,
  Tag,
  Zap,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import Loader from '../components/ui/Loader';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { guessIocType, IOC_TYPE_LABELS } from '../utils/iocs';
import { severityFromScore, timeAgo } from '../utils/format';

const ACCENT_MAP = { ipv4: 'violet', ipv6: 'violet', domain: 'cyan', cve: 'red', sha256: 'amber', sha1: 'amber', md5: 'amber', onion: 'red', url: 'cyan' };

/**
 * IoC Search (/ioc-search) — analyst lookup engine.
 *  * ClickHouse match  -> "do we already know this indicator?" (type, severity)
 *  * Shodan InternetDB -> ports / CVEs / hostnames / tags for IP addresses
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
    const type = guessIocType(q);
    if (type === 'ipv4') {
      try { await enrich.run(q); } catch { /* handled below */ }
    }
  };

  const type = guessIocType(query);
  const iocNotFound = !ioc.loading && ioc.error;
  const known = ioc.data;
  const enrichment = enrich.data;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <Radar size={20} className="text-cyan-400" /> IoC Search &amp; Shodan Lookup
        </h1>
        <p className="text-xs text-dim">Check an indicator against ClickHouse history and Shodan InternetDB</p>
      </div>

      {/* Search */}
      <form onSubmit={onSearch} className="flex flex-wrap gap-3">
        <div className="relative min-w-[260px] flex-1">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder="IP address, domain, file hash or CVE…"
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
                  : 'Submit an indicator above to query ClickHouse history and Shodan.'
              }
            />
          )}
        </Card>
      )}

      {/* Result: Shodan InternetDB (IPs only) */}
      {query && type === 'ipv4' && (
        <Card title="Shodan InternetDB Enrichment" icon={Server} subtitle="free internetdb.shodan.io">
          {enrich.loading ? (
            <Loader label="Querying Shodan InternetDB…" />
          ) : enrichment ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="rounded-lg border border-line bg-base/50 p-4">
                <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                  <Server size={12} /> Open ports
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(enrichment.ports || []).length ? (
                    enrichment.ports.map((p) => (
                      <span key={p} className="rounded border border-line bg-raised px-2 py-0.5 font-mono text-xs text-cyan-300">
                        {p}/tcp
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-faint">none</span>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-base/50 p-4">
                <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                  <Globe size={12} /> Hostnames
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(enrichment.hostnames || []).length ? (
                    enrichment.hostnames.map((h) => (
                      <span key={h} className="font-mono text-xs text-dim">{h}</span>
                    ))
                  ) : (
                    <span className="text-xs text-faint">none</span>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-base/50 p-4">
                <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                  <Zap size={12} /> Detected vulnerabilities
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(enrichment.vulns || []).length ? (
                    enrichment.vulns.map((v) => (
                      <span key={v} className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-mono text-xs text-red-300">
                        {v}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-faint">none detected</span>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-line bg-base/50 p-4">
                <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                  <Tag size={12} /> Tags
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {(enrichment.tags || []).length ? (
                    enrichment.tags.map((t) => (
                      <span key={t} className="rounded border border-line bg-raised px-2 py-0.5 text-xs text-dim">{t}</span>
                    ))
                  ) : (
                    <span className="text-xs text-faint">none</span>
                  )}
                </div>
              </div>
            </div>
          ) : enrich.error ? (
            <p className="text-sm text-dim">{errorText(enrich.error)}</p>
          ) : null}
        </Card>
      )}

      {/* Recent indicators for context */}
      <Card title="Recently Tracked Indicators" icon={Layers} subtitle="latest from processed_iocs">
        {recent.loading ? (
          <Loader label="Loading…" />
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
