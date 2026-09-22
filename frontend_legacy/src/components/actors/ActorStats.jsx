import React from 'react';
import { Link } from 'react-router-dom';
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Activity,
  Bug,
  Crosshair,
  Landmark,
  Radar,
  Skull,
  Target,
  Trophy,
  Wrench,
} from 'lucide-react';

import Card from '../ui/Card';
import ErrorState from '../ui/ErrorState';
import { Skeleton } from '../ui/skeleton';
import { compactNumber } from '../../utils/format';
import { tacticColor, tacticLabel } from '../../utils/tactics';

const TOOLTIP_STYLE = {
  backgroundColor: 'rgb(22 27 42)',
  border: '1px solid rgb(37 46 68)',
  borderRadius: '8px',
  color: 'rgb(241 245 249)',
  fontSize: '12px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
  padding: '10px 12px',
};
const AXIS = { stroke: 'rgb(71 85 105)', fontSize: 12 };

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE}>
      {label && (
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-faint">{label}</p>
      )}
      {payload.map((p, i) => (
        <p key={i} className="flex items-center gap-2 text-[12px]">
          <span className="inline-block h-2 w-2 rounded-full flex-shrink-0" style={{ background: p.color }} />
          <span className="text-dim">{p.name}:</span>
          <span className="ml-auto font-mono font-semibold text-ink">{compactNumber(p.value)}</span>
        </p>
      ))}
    </div>
  );
}

function KpiCard({ icon: Icon, label, value, subtle }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-line bg-surface px-3.5 py-3">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line bg-raised">
        <Icon size={15} className="text-primary" />
      </div>
      <div className="min-w-0">
        <div className="font-mono text-lg font-bold leading-tight text-ink tabular-nums">{value}</div>
        <div className="truncate text-[11px] leading-tight text-faint">{subtle || label}</div>
      </div>
    </div>
  );
}

function RankBar({ label, value, max, color, sub }) {
  const pct = Math.round(((value || 0) / (max || 1)) * 100);
  return (
    <div className="flex items-center gap-3">
      <span className="w-48 shrink-0 truncate text-xs text-dim" title={label}>
        {label}
      </span>
      <div className="relative h-2.5 flex-1 overflow-hidden rounded-full bg-raised">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="w-20 shrink-0 text-right font-mono text-xs font-semibold text-ink tabular-nums">
        {compactNumber(value)}
        {sub && <span className="ml-1 font-normal text-faint">{sub}</span>}
      </span>
    </div>
  );
}

function MiniList({ items, color, unit }) {
  if (!items || items.length === 0) {
    return <p className="flex h-24 items-center justify-center text-xs text-faint">No data mapped yet.</p>;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="space-y-3">
      {items.slice(0, 8).map((item, i) => (
        <div key={i}>
          <div className="flex items-baseline justify-between gap-2 text-xs">
            <span className="truncate" title={item.to ? `Open ${item.label} in a new tab` : item.label}>
              {item.to ? (
                <Link
                  to={item.to}
                  target="_blank"
                  rel="noreferrer"
                  className="font-medium text-ink transition-colors hover:text-primary"
                >
                  {item.label}
                </Link>
              ) : (
                <span className="text-dim">{item.label}</span>
              )}
            </span>
            <span className="shrink-0 font-mono text-xs font-semibold text-ink tabular-nums">
              {compactNumber(item.value)}
              {unit && <span className="ml-1 font-normal text-faint">{unit}</span>}
            </span>
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-raised">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.round(((item.value || 0) / max) * 100)}%`, backgroundColor: color }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function KillChainBar({ tactics, totalTechniques }) {
  if (!tactics || tactics.length === 0) {
    return <p className="text-xs text-faint">No tactic data yet — sync the ATT&CK knowledge base.</p>;
  }
  return (
    <div className="rounded-xl border border-line bg-base/60 p-4">
      <div className="flex h-6 w-full overflow-hidden rounded-lg bg-raised">
        {tactics.map((t) => {
          const pct = Math.round(((t.technique_count || 0) / (totalTechniques || 1)) * 100);
          if (pct <= 0) return null;
          return (
            <div
              key={t.tactic}
              title={`${tacticLabel(t.tactic)} — ${t.technique_count} technique(s), ${t.actor_count} actor(s)`}
              style={{ width: `${pct}%`, backgroundColor: tacticColor(t.tactic) }}
            />
          );
        })}
      </div>
      <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2">
        {tactics.map((t) => (
          <span key={t.tactic} className="inline-flex items-center gap-1.5 text-[11px] text-dim">
            <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: tacticColor(t.tactic) }} />
            <span className="font-medium">{tacticLabel(t.tactic)}</span>
            <span className="font-mono text-faint">{t.technique_count}</span>
          </span>
        ))}
        {tactics.some((t) => t.tactic === 'unknown' || t.tactic === null || t.tactic === '') && (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-dim">
            <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: tacticColor('unknown') }} />
            <span className="font-medium">Unmapped</span>
          </span>
        )}
      </div>
    </div>
  );
}

function LoadingBlock() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-[68px] rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-40 rounded-xl" />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Skeleton className="h-[420px] rounded-xl" />
        <Skeleton className="h-[420px] rounded-xl" />
      </div>
    </div>
  );
}

/**
 * ActorStats — OpenCTI-style knowledge-base statistics.
 * Scoped to threat actors: every technique / malware / tool / tactic counts
 * only when a STIX relationship binds it to an intrusion set.
 */
export default function ActorStats({ data, loading, error, onRetry }) {
  if (loading && !data) return <LoadingBlock />;
  if (error && !data) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <ErrorState title="Failed to load actor statistics" message={error} onRetry={onRetry} />
      </div>
    );
  }
  if (!data) return null;

  const k = data.kpis || {};
  const tactics = data.tactic_coverage || [];
  const maxTactic = Math.max(...tactics.map((t) => t.actor_count), 1);
  const totalTechniques = tactics.reduce((acc, t) => acc + (t.technique_count || 0), 0) || 1;

  const topTechniques = (data.top_techniques || []).map((t) => ({
    label: `${t.x_mitre_id} · ${t.name}`.length > 44
      ? `${t.x_mitre_id} · ${t.name.slice(0, 41)}…`
      : `${t.x_mitre_id} · ${t.name}`,
    name: t.name,
    tactic: t.tactic,
    actor_count: t.actor_count,
  }));

  return (
    <div className="h-full min-h-0 overflow-y-auto p-6">
      <div className="space-y-6 pb-2">
        {/* --- Knowledge-base KPIs --- */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
          <KpiCard icon={Skull} label="Threat actors" value={compactNumber(k.total_actors)} />
          <KpiCard icon={Target} label="Actors with mapped TTPs" value={compactNumber(k.actors_with_ttps)} />
          <KpiCard icon={Crosshair} label="Techniques in ATT&CK" value={compactNumber(k.total_ttps)} />
          <KpiCard icon={Bug} label="Malware" value={compactNumber(k.total_malware)} />
          <KpiCard icon={Wrench} label="Tools" value={compactNumber(k.total_tools)} />
        </div>

        {/* --- Kill-chain distribution (MITRE-style horizontal bar) --- */}
        <Card
          title="Kill-chain distribution"
          subtitle={`${tactics.length} tactic(s) across ${compactNumber(k.total_actors) || 0} threat actors`}
          icon={Landmark}
          padded={false}
          bodyClassName="p-5"
        >
          <KillChainBar tactics={tactics} totalTechniques={totalTechniques} />
        </Card>

        {/* --- Top techniques + tactic coverage --- */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Card
            title="Most-used techniques across actors"
            subtitle="coloured by kill-chain tactic"
            icon={Target}
            padded={false}
            bodyClassName="p-4"
          >
            {topTechniques.length === 0 ? (
              <p className="flex h-48 items-center justify-center text-xs text-faint">
                Run “Sync ATT&CK Data” to populate technique coverage.
              </p>
            ) : (
              <div style={{ height: Math.max(260, topTechniques.length * 38 + 24) }} className="pr-1">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topTechniques} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}>
                    <XAxis type="number" hide />
                    <YAxis
                      type="category"
                      dataKey="label"
                      width={210}
                      tick={{ ...AXIS, fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip cursor={{ fill: 'rgb(137 149 167 / 0.08)' }} content={<ChartTooltip />} />
                    <Bar dataKey="actor_count" name="Actors" radius={[0, 4, 4, 0]} barSize={18}>
                      {topTechniques.map((t, i) => (
                        <Cell key={i} fill={tacticColor(t.tactic)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>

          <Card
            title="Tactic coverage"
            subtitle="actors per MITRE ATT&CK tactic"
            icon={Crosshair}
            padded={false}
            bodyClassName="p-5"
          >
            {tactics.length === 0 ? (
              <p className="flex h-48 items-center justify-center text-xs text-faint">
                No tactic data yet — sync the ATT&CK knowledge base.
              </p>
            ) : (
              <div className="flex flex-col justify-center gap-3 py-1">
                {tactics.map((t) => (
                  <RankBar
                    key={t.tactic}
                    label={t.tactic === 'unknown' || !t.tactic ? 'Unmapped' : tacticLabel(t.tactic)}
                    value={t.actor_count}
                    max={maxTactic}
                    color={tacticColor(t.tactic)}
                    sub="actors"
                  />
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* --- Most associated malware / tools / richest actors --- */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card
            title="Most associated malware"
            subtitle="actors that use them"
            icon={Bug}
            padded={false}
            bodyClassName="p-5"
          >
            <MiniList
              items={(data.top_malware || []).map((m) => ({
                label: m.name,
                value: m.actor_count,
                to: `/malware/${encodeURIComponent(m.stix_id)}`,
              }))}
              color="#a855f7"
              unit="actors"
            />
          </Card>

          <Card
            title="Most associated tools"
            subtitle="actors that use them"
            icon={Wrench}
            padded={false}
            bodyClassName="p-5"
          >
            <MiniList
              items={(data.top_tools || []).map((t) => ({
                label: t.name,
                value: t.actor_count,
                to: `/malware/${encodeURIComponent(t.stix_id)}`,
              }))}
              color="#4F8EF7"
              unit="actors"
            />
          </Card>

          <Card
            title="Actors with the richest coverage"
            subtitle="deepest TTP mapping"
            icon={Trophy}
            padded={false}
            bodyClassName="p-5"
          >
            <MiniList
              items={(data.top_actors || []).map((a) => ({
                label: a.name,
                value: a.ttp_count,
                to: `/actors?actor=${encodeURIComponent(a.stix_id)}`,
              }))}
              color="#fbbf24"
              unit="TTPs"
            />
          </Card>
        </div>

        {/* --- Most-referenced actors by attributed IOC volume (Brief #4) --- */}
        {/* Honest state: rankings fill in from OTX pulse attribution + analyst
            tags; while none exist the coverage panel admits it. */}
        <Card
          title="Most-referenced actors"
          subtitle={`by attributed IOC volume (last ${data.most_referenced?.window_days || 30} days)`}
          icon={Radar}
          padded={false}
          bodyClassName="p-5"
        >
          {(data.most_referenced?.attribution_coverage || 0) === 0 ? (
            <div className="flex flex-col items-start gap-2 py-2">
              <div className="w-full">
                <KpiCard
                  icon={Radar}
                  label="Attributed indicators (window)"
                  value={compactNumber(data.most_referenced?.attribution_coverage || 0)}
                />
              </div>
              <div className="mt-2 rounded-xl border border-dashed border-line bg-base/40 p-4">
                <p className="text-sm font-medium text-ink">Not enough attributed data yet</p>
                <p className="mt-1 text-xs leading-relaxed text-faint">
                  In the last 30 days no indicator has been tagged with a threat actor yet. As OTX
                  pulses attribute IOCs and analysts tag real indicators, this ranking fills in —
                  nothing here is guessed.
                </p>
              </div>
            </div>
          ) : (
            <MiniList
              items={(data.most_referenced?.actors || []).map((a) => ({
                label: a.name,
                value: a.ioc_count,
                to: `/actors?actor=${encodeURIComponent(a.stix_id)}`,
                unit: 'IOCs',
              }))}
              color="#4F8EF7"
              unit="IOCs"
            />
          )}
        </Card>

        {/* Scriptless reassurance line */}
        <p className="flex items-center gap-1.5 text-[11px] text-faint">
          <Activity size={11} className="text-primary/70" />
          Statistics are computed live from ATT&CK STIX relationships scoped to intrusion sets.
        </p>
      </div>
    </div>
  );
}