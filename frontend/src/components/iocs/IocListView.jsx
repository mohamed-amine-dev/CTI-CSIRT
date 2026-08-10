import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, Fingerprint } from 'lucide-react';

import Badge from '../ui/Badge';
import Button from '../ui/Button';
import CopyButton from '../ui/CopyButton';
import EmptyState from '../ui/EmptyState';
import Loader from '../ui/Loader';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { severityFromScore, timeAgo, titleCase } from '../../utils/format';

const PAGE_SIZE = 25;

/**
 * IocListView — reusable, paginated indicator table over /api/v1/iocs.
 *
 * Used by the standalone /indicators route and as the drill-down target for
 * the choropleth (country) clicks. Pass `country` (alpha-2) and/or `days`
 * (window) to filter; `onIndicator` lets a parent hook row clicks.
 */
export default function IocListView({ country, days = 0, title, subtitle, emptyMessage }) {
  const [page, setPage] = useState(0);

  const { data, loading, error, reload } = useApi(
    () =>
      unwrap(
        api.getIocs({
          country: country || undefined,
          days: days > 0 ? days : undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        }),
      ),
    { deps: [page, country, days] },
  );

  const items = data?.items || [];
  const hasMore = items.length === PAGE_SIZE;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          {title && <h3 className="text-sm font-semibold text-ink">{title}</h3>}
          {subtitle && <p className="text-xs text-dim">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" icon={ChevronLeft} disabled={page === 0 || loading} onClick={() => setPage((p) => p - 1)}>
            Prev
          </Button>
          <span className="font-mono text-xs text-faint">page {page + 1}</span>
          <Button size="sm" icon={ChevronRight} disabled={!hasMore || loading} onClick={() => setPage((p) => p + 1)}>
            Next
          </Button>
        </div>
      </div>

      {loading ? (
        <Loader label="Loading indicators…" />
      ) : error ? (
        <EmptyState
          icon={Fingerprint}
          title="Could not load indicators"
          message={String(error?.message || error)}
        >
          <Button size="sm" variant="secondary" onClick={reload}>
            Retry
          </Button>
        </EmptyState>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Fingerprint}
          title="No indicators match"
          message={emptyMessage || 'Nothing geolocated or ingested for this filter yet.'}
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-max text-left text-sm">
            <thead>
              <tr className="border-b border-line bg-raised/50 text-[10px] uppercase tracking-wider text-faint">
                <th className="px-4 py-2.5 font-semibold">Indicator</th>
                <th className="px-4 py-2.5 font-semibold">Type</th>
                <th className="px-4 py-2.5 font-semibold">Severity</th>
                <th className="px-4 py-2.5 font-semibold">First seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => {
                const sev = severityFromScore(it.severity);
                return (
                  <tr key={`${it.type}:${it.indicator}`} className="border-b border-line/60 last:border-0 hover:bg-raised/40">
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <span className="break-all font-mono text-xs text-cyan-200">{it.indicator}</span>
                        <CopyButton value={it.indicator} label="Copy indicator" />
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      <Badge tone="neutral">{titleCase(it.type)}</Badge>
                    </td>
                    <td className="px-4 py-2">
                      <Badge severity={sev.label}>{sev.label}</Badge>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-dim">{timeAgo(it.ts)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
