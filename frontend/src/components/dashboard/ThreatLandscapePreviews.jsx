import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpRight, Globe2, ShieldQuestion } from 'lucide-react';

import Card from '../ui/Card';
import ChoroplethMap from '../threats/ChoroplethMap';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { compactNumber } from '../../utils/format';

/**
 * ThreatLandscapePreviews — the two small Executive Overview tiles that point
 * into the dedicated Threat Landscape page (per brief: previews only, the full
 * visualisations live on /threat-landscape).
 */

function OpenLink({ to }) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      onClick={() => navigate(to)}
      className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-300 transition-colors hover:text-cyan-200"
    >
      Open <ArrowUpRight size={13} />
    </button>
  );
}

/** Map thumbnail: mini choropleth + top-3 countries caption. */
export function OriginPreviewTile() {
  const navigate = useNavigate();
  const { data, loading } = useApi(() => unwrap(api.getGeoSummary(60)), { deps: [] });
  const countries = data?.countries || [];
  const top = countries.slice(0, 3);

  return (
    <Card
      title="Threat Origin"
      icon={Globe2}
      subtitle="geolocated indicator IPs · last 60d"
      actions={<OpenLink to="/threat-landscape" />}
      padded={false}
    >
      {loading ? (
        <div className="flex h-44 items-center justify-center p-5">
          <p className="text-xs text-faint">Loading…</p>
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-b-xl">
            <ChoroplethMap
              countries={countries}
              total={data?.total || 0}
              height={190}
              onSelect={() => navigate('/threat-landscape')}
            />
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line px-4 py-2 text-[11px] text-dim">
            <span className="font-semibold uppercase tracking-wider text-faint">Top origins</span>
            {top.map((c) => (
              <span key={c.code} className="flex items-center gap-1">
                <span className="font-mono text-faint">{c.code}</span>
                <span className="font-mono text-cyan-300">{compactNumber(c.count)}</span>
              </span>
            ))}
            {!top.length && <span className="text-faint">enricher warming up…</span>}
          </div>
        </>
      )}
    </Card>
  );
}

/** Tactics preview: top-3 ATT&CK tactics as a mini bar chart. */
export function TacticsPreviewTile() {
  const { data, loading } = useApi(() => unwrap(api.getTacticHeatmap(60)), { deps: [] });
  const totals = data?.tactic_totals || {};
  const ranked = Object.entries(totals)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  const top = ranked.slice(0, 3);
  const max = top.length ? top[0][1] : 1;

  return (
    <Card
      title="Top ATT&CK Tactics"
      icon={ShieldQuestion}
      subtitle="mapped from threat categories · last 60d"
      actions={<OpenLink to="/threat-landscape" />}
    >
      {loading ? (
        <p className="text-xs text-faint">Loading…</p>
      ) : !top.length ? (
        <p className="text-xs text-faint">No tactic data yet.</p>
      ) : (
        <div className="space-y-3">
          {top.map(([tactic, n]) => (
            <div key={tactic}>
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="truncate text-ink">{tactic}</span>
                <span className="font-mono text-faint">{compactNumber(n)}</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-raised">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${Math.max(6, (n / max) * 100)}%`, background: 'linear-gradient(to right, #155e75, #22d3ee)' }}
                />
              </div>
            </div>
          ))}
          <p className="pt-1 text-[11px] text-faint">
            {data?.categories?.length || 0} threat categories mapped · click “Open” for the full heatmap
          </p>
        </div>
      )}
    </Card>
  );
}
