import React from 'react';
import { Sparkles, CheckCircle2, Clock, Loader2, XCircle } from 'lucide-react';
import { cn } from '../../lib/utils';
import Card from '../ui/Card';
import { Progress } from '../ui/progress';
import { useApi } from '../../hooks/useApi';
import { api, unwrap } from '../../services/api';
import { compactNumber } from '../../utils/format';

const STATUS_ITEMS = [
  {
    key: 'done',
    label: 'Generated',
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/20',
  },
  {
    key: 'pending',
    label: 'Queued',
    icon: Clock,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/20',
  },
  {
    key: 'processing',
    label: 'Processing',
    icon: Loader2,
    color: 'text-primary',
    bg: 'bg-primary/10 border-primary/20',
    spin: true,
  },
  {
    key: 'failed',
    label: 'Failed',
    icon: XCircle,
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/20',
  },
];

/**
 * AiPipelineCard — live state of the Alert Sheet generation pipeline.
 */
export default function AiPipelineCard() {
  const { data, loading } = useApi(() => unwrap(api.getAiStatus()), {
    deps: [],
    refreshMs: 30_000,
  });
  const counts = data?.counts || {};
  const total = Object.values(counts).reduce((s, n) => s + (n || 0), 0);
  const donePct = total ? Math.round(((counts.done || 0) / total) * 100) : 0;

  return (
    <Card title="AI Alert Sheet Pipeline" icon={Sparkles} subtitle="durable job queue · live">
      {loading && !total ? (
        <div className="flex items-center justify-center py-8">
          <p className="text-sm text-faint">Loading pipeline status…</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* 4-stat grid */}
          <div className="grid grid-cols-2 gap-2">
            {STATUS_ITEMS.map((s) => {
              const Icon = s.icon;
              const n = counts[s.key] || 0;
              return (
                <div
                  key={s.key}
                  className={cn(
                    'flex items-center gap-3 rounded-lg border px-3 py-2.5',
                    s.bg,
                  )}
                >
                  <Icon
                    size={15}
                    className={cn(s.color, s.spin && n > 0 ? 'animate-spin' : '')}
                  />
                  <div className="min-w-0">
                    <p className={cn('font-mono text-lg font-bold leading-none tabular-nums', s.color)}>
                      {compactNumber(n)}
                    </p>
                    <p className="mt-0.5 text-[11px] text-dim">{s.label}</p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Completion progress */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-dim">Completion</span>
              <span className="font-mono font-semibold text-ink">{donePct}%</span>
            </div>
            <Progress
              value={donePct}
              className="h-1.5"
              indicatorClassName="bg-emerald-500"
            />
          </div>

          {/* Provider */}
          {data?.provider && (
            <div className="flex items-center justify-between border-t border-line pt-3 text-[11px]">
              <span className="text-faint">LLM Provider</span>
              <span className="rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary">
                {data.provider}
              </span>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}