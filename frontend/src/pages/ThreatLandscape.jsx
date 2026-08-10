import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Flame, Globe2, Map, ShieldQuestion } from 'lucide-react';

import Card from '../components/ui/Card';
import ErrorState from '../components/ui/ErrorState';
import ChoroplethMap from '../components/threats/ChoroplethMap';
import TacticHeatmap from '../components/threats/TacticHeatmap';
import { useApi } from '../hooks/useApi';
import { api, unwrap } from '../services/api';
import { compactNumber } from '../utils/format';

const RANGES = [
  { label: '24h', days: 1 },
  { label: '7d', days: 7 },
  { label: '30d', days: 30 },
  { label: '60d', days: 60 },
];

/**
 * Threat Landscape (/threat-landscape) — dedicated deep-dive page.
 *
 * Two tabs over the ClickHouse corpus:
 *   * By Origin    — D3 choropleth of indicator IPs geolocated per country
 *                    (free ipwho.is + ClickHouse cache); click a country to
 *                    open its filtered IOC list.
 *   * By Technique — threat category × MITRE ATT&CK tactic heatmap (analyst
 *                    mapping, unclassified column, never guessed).
 * A time-range switch (24h/7d/30d/60d) re-queries both views.
 */
export default function ThreatLandscape() {
  const navigate = useNavigate();
  const [days, setDays] = useState(60);
  const [tab, setTab] = useState('origin');

  const geo = useApi(() => unwrap(api.getGeoSummary(days)), { deps: [days] });
  const heatmap = useApi(() => unwrap(api.getTacticHeatmap(days)), { deps: [days] });
  const geoStatus = useApi(() => unwrap(api.getGeoStatus()), { deps: [] });

  const countries = geo.data?.countries || [];
  const countriesError = geo.error || (tab === 'origin' && geoStatus.error ? geoStatus.error : null);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-mono text-xl font-bold text-ink">Threat Landscape</h1>
          <p className="text-xs text-dim">
            Where the threats originate and which ATT&CK techniques they target
          </p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-line bg-raised p-1">
          {RANGES.map((r) => (
            <button
              key={r.days}
              type="button"
              onClick={() => setDays(r.days)}
              className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                days === r.days ? 'bg-cyan-500/15 text-cyan-300' : 'text-dim hover:text-ink'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-line">
        {[
          { id: 'origin', label: 'By Origin', icon: Globe2 },
          { id: 'technique', label: 'By Technique', icon: ShieldQuestion },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-semibold transition-colors ${
              tab === t.id
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-dim hover:text-ink'
            }`}
          >
            <t.icon size={15} />
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'origin' ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
          <Card
            title="Threat Origin Map"
            icon={Map}
            subtitle={`geolocated indicator IPs · last ${RANGES.find((r) => r.days === days)?.label}`}
            padded={false}
            className="xl:col-span-3"
          >
            {geo.loading ? (
              <div className="flex h-[520px] items-center justify-center">
                <p className="text-xs text-faint">Loading geolocation data…</p>
              </div>
            ) : countriesError ? (
              <div className="p-5">
                <ErrorState
                  title="Geolocation data unavailable"
                  message={String(countriesError?.message || countriesError)}
                  onRetry={geo.reload}
                />
              </div>
            ) : (
              <ChoroplethMap
                countries={countries}
                total={geo.data?.total || 0}
                onSelect={(code, name) => navigate(`/indicators?country=${code}&days=${days}`)}
              />
            )}
          </Card>

          <div className="space-y-4">
            <Card title="Top Countries" icon={Globe2} subtitle="click to drill into IOCs">
              <ul className="space-y-1">
                {(countries.slice(0, 12).length ? countries.slice(0, 12) : []).map((c) => (
                  <li key={c.code}>
                    <button
                      type="button"
                      onClick={() => navigate(`/indicators?country=${c.code}&days=${days}`)}
                      className="group flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-raised/60"
                    >
                      <span className="inline-block w-8 shrink-0 font-mono text-[11px] text-faint">{c.code}</span>
                      <span className="min-w-0 flex-1 truncate text-xs text-ink group-hover:text-cyan-200">{c.name}</span>
                      <span className="font-mono text-xs text-faint">{compactNumber(c.count)}</span>
                    </button>
                  </li>
                ))}
                {!countries.length && !geo.loading && (
                  <li className="px-2 py-4 text-center text-xs text-faint">
                    No geolocated IPs yet — the enricher tops up the cache in the background.
                  </li>
                )}
              </ul>
            </Card>

            {geoStatus.data && (
              <Card title="Geolocation Coverage" icon={Flame} subtitle="free ipwho.is cache">
                <dl className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <dt className="text-dim">Cached IPs</dt>
                    <dd className="font-mono text-ink">{compactNumber(geoStatus.data.cached)}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-dim">Countries covered</dt>
                    <dd className="font-mono text-ink">{geoStatus.data.countries}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-dim">Monthly quota used</dt>
                    <dd className="font-mono text-ink">
                      {geoStatus.data.monthly_used}/{geoStatus.data.monthly_budget}
                    </dd>
                  </div>
                  {geoStatus.data.last_run?.pending > 0 && (
                    <div className="flex justify-between">
                      <dt className="text-dim">Awaiting geolocation</dt>
                      <dd className="font-mono text-cyan-300">{compactNumber(geoStatus.data.last_run.pending)}</dd>
                    </div>
                  )}
                </dl>
              </Card>
            )}
          </div>
        </div>
      ) : (
        <Card
          title="ATT&CK Technique Heatmap"
          icon={ShieldQuestion}
          subtitle={`category → tactics · analyst-mapped · last ${RANGES.find((r) => r.days === days)?.label}`}
          padded={false}
        >
          {heatmap.loading ? (
            <div className="flex h-64 items-center justify-center">
              <p className="text-xs text-faint">Loading heatmap…</p>
            </div>
          ) : heatmap.error ? (
            <div className="p-5">
              <ErrorState
                title="Heatmap unavailable"
                message={String(heatmap.error?.message || heatmap.error)}
                onRetry={heatmap.reload}
              />
            </div>
          ) : (
            <div className="p-4">
              <TacticHeatmap
                data={heatmap.data}
                onSelectCategory={(cat) => navigate(`/feeds?threat=${encodeURIComponent(cat)}`)}
              />
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
