import React from 'react';
import { MapPin } from 'lucide-react';
import Card from '../ui/Card';
import { Progress } from '../ui/progress';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { compactNumber, timeAgo } from '../../utils/format';

/**
 * GeoCoverageCard — ipwho.is geolocation enrichment coverage stats.
 */
export default function GeoCoverageCard() {
  const { data, loading } = useApi(() => unwrap(api.getGeoStatus()), {
    deps: [],
    refreshMs: 60_000,
  });

  const cached    = data?.cached    || 0;
  const ok        = data?.ok        || 0;
  const fail      = data?.fail      || 0;
  const budget    = data?.monthly_budget || 0;
  const used      = data?.monthly_used   || 0;
  const budgetPct = budget ? Math.min(100, Math.round((used / budget) * 100)) : 0;
  const okPct     = cached ? Math.round((ok / cached) * 100) : 0;

  const budgetIndicatorColor =
    budgetPct >= 85 ? 'bg-red-500' :
    budgetPct >= 60 ? 'bg-amber-500' :
    'bg-primary';

  return (
    <Card
      title="Geolocation Coverage"
      icon={MapPin}
      subtitle="indicator IPs → country · ipwho.is"
    >
      {loading && !cached ? (
        <div className="flex items-center justify-center py-8">
          <p className="text-sm text-faint">Loading coverage data…</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Top stats */}
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-lg border border-line bg-base/50 px-4 py-3">
              <p className="text-2xl font-bold text-ink tabular-nums">
                {compactNumber(cached)}
              </p>
              <p className="mt-0.5 text-[11px] text-faint">IPs cached</p>
            </div>
            <div className="rounded-lg border border-line bg-base/50 px-4 py-3">
              <p className="text-2xl font-bold text-ink tabular-nums">
                {data?.countries || 0}
              </p>
              <p className="mt-0.5 text-[11px] text-faint">countries resolved</p>
            </div>
          </div>

          {/* Resolution rate */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-dim">Resolution rate</span>
              <span className="font-mono font-semibold text-ink">
                {compactNumber(ok)} / {compactNumber(cached)}
                {cached > 0 && (
                  <span className="ml-1.5 text-faint">({okPct}%)</span>
                )}
              </span>
            </div>
            <Progress
              value={okPct}
              className="h-1.5"
              indicatorClassName="bg-emerald-500"
            />
            {fail > 0 && (
              <p className="text-[11px] text-faint">
                {compactNumber(fail)} IPs failed geolocation
              </p>
            )}
          </div>

          {/* Monthly quota */}
          <div className="space-y-1.5 border-t border-line pt-3">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-dim">Monthly lookup quota</span>
              <span className="font-mono font-semibold text-ink">
                {compactNumber(used)} / {compactNumber(budget)}
              </span>
            </div>
            <Progress
              value={budgetPct}
              className="h-1.5"
              indicatorClassName={budgetIndicatorColor}
            />
            {data?.last_run && (
              <p className="text-[11px] text-faint">
                Last run {timeAgo(data.last_run)}
              </p>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}