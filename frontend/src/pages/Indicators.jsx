import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Fingerprint } from 'lucide-react';

import Button from '../components/ui/Button';
import IocListView from '../components/iocs/IocListView';

/**
 * Indicators (/indicators) — standalone, paginated IOC list.
 *
 * Reads `country` (alpha-2) and `days` from the query string, so it doubles as
 * the drill-down target of the Threat Landscape choropleth. With no country it
 * simply lists the whole corpus, highest severity first.
 */
export default function Indicators() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const country = (params.get('country') || '').toUpperCase();
  const days = Number(params.get('days')) || 0;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-mono text-xl font-bold text-ink">Indicators</h1>
          <p className="text-xs text-dim">
            {country
              ? `Indicator IPs geolocated to ${country} · last ${days > 0 ? `${days}d` : 'all time'}`
              : 'Processed indicators, highest severity first'}
          </p>
        </div>
        <Button size="sm" icon={ArrowLeft} onClick={() => navigate(-1)}>
          Back
        </Button>
      </div>

      <IocListView
        country={country}
        days={days}
        title={country ? `Country ${country}` : 'All indicators'}
        subtitle={country ? 'Click any row to copy the indicator' : undefined}
        emptyMessage={
          country
            ? `No IPs geolocated to ${country} in this window yet — the geolocation enricher fills the cache gradually.`
            : 'No indicators match this filter.'
        }
      />
    </div>
  );
}
