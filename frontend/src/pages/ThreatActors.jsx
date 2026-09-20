import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BarChart3, Bot, Bug, Crosshair, Download, ExternalLink, List, RefreshCw, Search, ShieldQuestion, Skull, Target, Wrench, X } from 'lucide-react';

import ActorStats from '../components/actors/ActorStats';
import AssistantChat from '../components/actors/AssistantChat';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import CopyButton from '../components/ui/CopyButton';
import EmptyState from '../components/ui/EmptyState';
import ErrorBoundary from '../components/ui/ErrorBoundary';
import ErrorState from '../components/ui/ErrorState';
import { Skeleton } from '../components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { tacticColor, tacticLabel } from '../utils/tactics';
import renderStixMarkdown from '../utils/stix.jsx';

// -----------------------------------------------------------------------------
// Small presentational pieces (keep the page dense but scannable).
// -----------------------------------------------------------------------------

function ActorYear({ iso }) {
  const year = iso ? new Date(iso).getFullYear() : null;
  if (!iso || !year || year <= 1970) return null; // ingest default marks "unknown"
  return year;
}

function CountChip({ label, value }) {
  if (!value) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-line bg-base/60 px-1.5 py-0.5 font-mono text-[10px] text-dim">
      {label}
      <span className="font-bold text-ink">{value}</span>
    </span>
  );
}

function FilterSelect({ label, value, onChange, options = [], allLabel = 'All' }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-faint">
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-line bg-base px-2 py-1.5 text-xs text-ink focus:border-primary focus:outline-none"
      >
        <option value="">{allLabel}</option>
        {options.map((opt) => (
          <option key={opt} value={opt}>
            {opt === 'unknown' ? 'Unknown' : opt}
          </option>
        ))}
      </select>
    </label>
  );
}

function StatKpi({ icon: Icon, label, value, subtle }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-line bg-base/60 px-3.5 py-2.5">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line bg-surface">
        <Icon size={14} className="text-primary" />
      </div>
      <div className="min-w-0">
        <div className="font-mono text-lg font-bold leading-tight text-ink">{value}</div>
        <div className="truncate text-[11px] leading-tight text-faint">{subtle || label}</div>
      </div>
    </div>
  );
}

function SectionTitle({ icon: Icon, title, count, tone }) {
  return (
    <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
      <Icon size={15} className={tone || 'text-primary'} />
      {title}
      <span className="rounded-md border border-line bg-raised px-1.5 py-px font-mono text-[10px] text-dim">
        {count}
      </span>
    </h3>
  );
}

function MitreLink({ url, label }) {
  if (!url) return null;
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline"
    >
      {label || 'MITRE ATT&CK'}
      <ExternalLink size={11} />
    </a>
  );
}

// -----------------------------------------------------------------------------
// Threat Actors & APTs (/actors) — OpenCTI-style knowledge base.
//
// Layout is a fixed full-height console so the page never scrolls; only the two
// panes scroll independently (list on the left, profile on the right). Matches
// the app shell: header + footer + main are flex, and this page fills main's
// content box exactly (h-full), so `main`'s overflow never triggers.
// -----------------------------------------------------------------------------

export default function ThreatActors() {
  const [searchTerm, setSearchTerm] = useState('');
  const [motivationFilter, setMotivationFilter] = useState('');
  const [sectorFilter, setSectorFilter] = useState('');
  const [countryFilter, setCountryFilter] = useState('');
  const [selectedActorId, setSelectedActorId] = useState(null);
  const [activeTab, setActiveTab] = useState('browse');
  const [searchParams] = useSearchParams();
  const detailScrollRef = useRef(null);

  // Allow deep-linking to a specific actor, e.g. /actors?actor=intrusion-set--...
  useEffect(() => {
    const actorParam = searchParams.get('actor');
    if (actorParam) setSelectedActorId(actorParam);
  }, [searchParams]);

  const list = useApi(
    () =>
      unwrap(
        api.getActors(searchTerm, {
          motivation: motivationFilter,
          sector: sectorFilter,
          country: countryFilter,
        }),
      ),
    { deps: [searchTerm, motivationFilter, sectorFilter, countryFilter] },
  );
  const filters = useApi(() => unwrap(api.getActorFilters()), { deps: [] });
  const detail = useApi(
    () => (selectedActorId ? unwrap(api.getActor(selectedActorId)) : Promise.resolve(null)),
    { deps: [selectedActorId] },
  );
  const rules = useApi(
    () => (selectedActorId ? unwrap(api.getActorRules(selectedActorId)) : Promise.resolve(null)),
    { deps: [selectedActorId] },
  );
  const stats = useApi(() => unwrap(api.getActorStats()), { deps: [] });

  const syncMutation = useAsync(api.syncActors);

  const actors = list.data?.actors || [];

  // Keep the detail pane at the top when switching actors.
  useEffect(() => {
    detailScrollRef.current?.scrollTo({ top: 0 });
  }, [selectedActorId]);

  const handleSync = async () => {
    try {
      await syncMutation.run();
      list.reload();
      if (selectedActorId) detail.reload();
      stats.reload();
    } catch { /* handled by useAsync */ }
  };

  const handleAttributionChanged = () => {
    if (selectedActorId) detail.reload();
    stats.reload();
  };

  const yearsActive = (a) => {
    const from = ActorYear({ iso: a.first_seen });
    const to = ActorYear({ iso: a.last_seen });
    if (from && to && from !== to) return `${from}–${to}`;
    return from ? String(from) : null;
  };

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab} className="flex h-full min-h-0 flex-col gap-4">
      {/* Header + segmented view switcher — one organized row */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface">
            <Skull size={16} className="text-primary" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">Threat Actors & APTs</h1>
            <p className="text-xs text-faint">
              MITRE ATT&CK intrusion sets, malware and tools — assess in one place
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <TabsList>
            <TabsTrigger value="browse">
              <List size={13} />
              <span className="hidden sm:inline">Actors & APTs</span>
              <span className="sm:hidden">Actors</span>
            </TabsTrigger>
            <TabsTrigger value="stats">
              <BarChart3 size={13} />
              <span className="hidden sm:inline">Statistics</span>
              <span className="sm:hidden">Stats</span>
            </TabsTrigger>
            <TabsTrigger value="assistant">
              <Bot size={13} />
              <span className="hidden sm:inline">Assistant</span>
              <span className="sm:hidden">Ask</span>
            </TabsTrigger>
          </TabsList>
          <span className="rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-dim">
            <span className="font-mono font-semibold text-ink">{list.loading && !actors.length ? '…' : actors.length}</span>
            {' '}actors
          </span>
          <Button variant="primary" icon={RefreshCw} onClick={handleSync} loading={syncMutation.loading}>
            Sync ATT&CK Data
          </Button>
        </div>
      </div>

      <TabsContent value="browse" className="mt-0 flex min-h-[520px] flex-1 flex-col">
          <div className="flex min-h-0 flex-1 gap-4">
        {/* Left pane — actor list */}
        <Card
          padded={false}
          className="flex w-[320px] shrink-0 flex-col overflow-hidden 2xl:w-[360px]"
          bodyClassName="flex min-h-0 flex-1 flex-col"
        >
          <div className="shrink-0 border-b border-line p-3">
            <div className="relative mb-2">
              <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by name or alias…"
                className="w-full rounded-lg border border-line bg-base py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint focus:border-primary focus:outline-none"
              />
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              <FilterSelect
                label="Motivation"
                value={motivationFilter}
                onChange={(v) => { setMotivationFilter(v); setSelectedActorId(null); }}
                options={filters.data?.motivations || []}
                allLabel="Any"
              />
              <FilterSelect
                label="Target sector"
                value={sectorFilter}
                onChange={(v) => { setSectorFilter(v); setSelectedActorId(null); }}
                options={filters.data?.sectors || []}
                allLabel="Any"
              />
              <FilterSelect
                label="Target country"
                value={countryFilter}
                onChange={(v) => { setCountryFilter(v); setSelectedActorId(null); }}
                options={filters.data?.countries || []}
                allLabel="Any"
              />
            </div>
            {(motivationFilter || sectorFilter || countryFilter) && (
              <button
                type="button"
                onClick={() => {
                  setMotivationFilter('');
                  setSectorFilter('');
                  setCountryFilter('');
                }}
                className="mt-2 w-full rounded-lg border border-line bg-raised px-2 py-1 text-[11px] font-semibold text-dim transition-colors hover:border-primary/40 hover:text-primary"
              >
                Clear all filters
              </button>
            )}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {list.error ? (
              <div className="p-2">
                <ErrorState
                  title="Failed to load actors"
                  message={errorText(list.error)}
                  onRetry={list.reload}
                />
              </div>
            ) : list.loading && !actors.length ? (
              <div className="space-y-2 p-2">
                {[0, 1, 2, 3, 4].map((i) => (
                  <div key={i} className="rounded-lg border border-line p-3">
                    <Skeleton className="mb-2 h-3.5 w-2/3" />
                    <Skeleton className="h-2.5 w-1/3" />
                  </div>
                ))}
              </div>
            ) : actors.length === 0 ? (
              <EmptyState
                icon={Skull}
                title={searchTerm ? 'No actors match' : 'No actors yet'}
                message={
                  searchTerm
                    ? 'Try a different name or alias.'
                    : 'The ATT&CK knowledge base is empty. Run "Sync ATT&CK Data".'
                }
              />
            ) : (
              <div className="space-y-1">
                {actors.map((actor) => {
                  const active = actor.stix_id === selectedActorId;
                  const years = yearsActive(actor);
                  return (
                    <button
                      key={actor.stix_id}
                      type="button"
                      onClick={() => setSelectedActorId(actor.stix_id)}
                      className={`w-full rounded-lg p-3 text-left transition-colors ${
                        active
                          ? 'border border-primary/30 bg-primary/10'
                          : 'border border-transparent hover:bg-raised'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className={`truncate text-sm font-semibold ${active ? 'text-primary' : 'text-ink'}`}>
                          {actor.name}
                        </span>
                        {years && (
                          <span className="shrink-0 font-mono text-[10px] text-faint">{years}</span>
                        )}
                      </div>
                      {actor.aliases?.length > 0 && (
                        <div className="mt-0.5 truncate text-xs text-dim">
                          aka {actor.aliases[0]}
                        </div>
                      )}
                      {(actor.motivation && actor.motivation !== 'unknown') || actor.attribution ? (
                        <div className="mt-1.5 flex flex-wrap items-center gap-1">
                          {actor.motivation && actor.motivation !== 'unknown' && (
                            <span className="rounded-md border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                              {actor.motivation}
                            </span>
                          )}
                          {actor.attribution && (
                            <span className="rounded-md border border-line bg-base/60 px-1.5 py-0.5 text-[10px] font-medium text-dim">
                              {actor.attribution}
                            </span>
                          )}
                        </div>
                      ) : null}
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        <CountChip label="TTPs" value={actor.ttp_count} />
                        <CountChip label="Malware" value={actor.malware_count} />
                        <CountChip label="Tools" value={actor.tool_count} />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </Card>

        {/* Right pane — actor profile */}
        <Card
          padded={false}
          className="flex min-h-0 flex-1 flex-col overflow-hidden"
          bodyClassName="flex min-h-0 flex-1 flex-col"
        >
          {/* Profile body */}
          <div ref={detailScrollRef} className="min-h-0 flex-1 overflow-y-auto">
            {detail.loading && !detail.data ? (
              <div className="space-y-4 p-6">
                <Skeleton className="h-7 w-1/2" />
                <div className="flex gap-2">
                  <Skeleton className="h-5 w-24" />
                  <Skeleton className="h-5 w-24" />
                  <Skeleton className="h-5 w-24" />
                </div>
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-4/5" />
                <Skeleton className="h-3 w-3/5" />
              </div>
            ) : !detail.data ? (
              <div className="flex h-full items-center justify-center">
                <EmptyState
                  icon={ShieldQuestion}
                  title="Select a threat actor"
                  message="Pick an actor on the left to open its full OpenCTI-style profile: aliases, activity window, observed malware & tools and MITRE ATT&CK techniques."
                />
              </div>
            ) : (
              <ProfileView actor={detail.data} rules={rules} onAttributed={handleAttributionChanged} />
            )}
          </div>
        </Card>
          </div>
        </TabsContent>

        <TabsContent value="stats" className="mt-0 flex min-h-[520px] flex-1 flex-col">
          <ErrorBoundary>
            <ActorStats
              data={stats.data}
              loading={stats.loading}
              error={errorText(stats.error)}
              onRetry={stats.reload}
            />
          </ErrorBoundary>
        </TabsContent>

        <TabsContent value="assistant" className="mt-0 flex min-h-[520px] flex-1 flex-col">
          <ErrorBoundary>
            <AssistantChat />
          </ErrorBoundary>
        </TabsContent>
    </Tabs>
  );
}

// -----------------------------------------------------------------------------
// OpenCTI-style entity profile (aligned sections, stat strip, knowledge blocks)
// -----------------------------------------------------------------------------

function ProfileView({ actor, rules, onAttributed }) {
  const [attrForm, setAttrForm] = useState({ indicator: '', type: 'ipv4' });
  const [attrBusy, setAttrBusy] = useState(false);
  const [attrError, setAttrError] = useState('');
  const [attrDone, setAttrDone] = useState('');
  const [attrRemoving, setAttrRemoving] = useState(null);

  const handleAttribute = async (e) => {
    e.preventDefault();
    const indicator = attrForm.indicator.trim();
    if (!indicator) return;
    setAttrBusy(true);
    setAttrError('');
    setAttrDone('');
    try {
      await api.attributeIoc(actor.stix_id, indicator, attrForm.type);
      setAttrDone(`Attributed ${indicator} to ${actor.name}`);
      setAttrForm((f) => ({ ...f, indicator: '' }));
      if (onAttributed) onAttributed();
    } catch (err) {
      setAttrError(errorText(err));
    } finally {
      setAttrBusy(false);
    }
  };

  const handleUnattribute = async (ioc) => {
    if (!window.confirm(`Remove the attribution of ${ioc.indicator} to ${actor.name}?`)) return;
    setAttrRemoving(ioc.indicator);
    setAttrError('');
    setAttrDone('');
    try {
      await api.unattributeIoc(actor.stix_id, ioc.indicator, ioc.type);
      if (onAttributed) onAttributed();
    } catch (err) {
      setAttrError(errorText(err));
    } finally {
      setAttrRemoving(null);
    }
  };

  const techniques = actor.ttps || [];
  const malware = (actor.malware_tools || []).filter((m) => m.type === 'malware');
  const tools = (actor.malware_tools || []).filter((m) => m.type === 'tool');
  const years = (() => {
    const from = ActorYear({ iso: actor.first_seen });
    const to = ActorYear({ iso: actor.last_seen });
    if (from && to && from !== to) return `${from}–${to}`;
    return from ? String(from) : null;
  })();

  // Group observed techniques by kill-chain tactic (OpenCTI "Knowledge" style).
  const tacticGroups = useMemo(() => {
    const groups = {};
    for (const t of techniques) {
      const key = t.tactic || 'unknown';
      (groups[key] ||= []).push(t);
    }
    return Object.entries(groups)
      .map(([tactic, list]) => ({ tactic, list }))
      .sort((a, b) => b.list.length - a.list.length);
  }, [techniques]);

  return (
    <div className="space-y-6 p-6">
      {/* Identity header */}
      <div className="border-b border-line pb-5">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-2xl font-bold text-ink">{actor.name}</h2>
          <Badge tone="blue">Threat Actor</Badge>
          <Badge tone="neutral">APT</Badge>
          {actor.motivation && actor.motivation !== 'unknown' && <Badge tone="blue">{actor.motivation}</Badge>}
          {actor.attribution && <Badge tone="neutral">{actor.attribution} origin</Badge>}
          {actor.url && <MitreLink url={actor.url} />}
        </div>
        {years && (
          <p className="mt-2 text-xs font-medium uppercase tracking-wider text-faint">
            Active since <span className="font-mono text-ink">{years}</span>
          </p>
        )}
        {actor.aliases?.length > 0 && (
          <div className="mt-3">
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">
              Also known as
            </p>
            <div className="flex flex-wrap gap-1.5">
              {actor.aliases.map((alias) => (
                <span
                  key={alias}
                  className="rounded-md border border-line bg-raised px-2.5 py-1 text-xs font-medium text-dim"
                >
                  {alias}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Analyst stat strip */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatKpi icon={Target} label="Observed techniques" value={techniques.length} />
        <StatKpi icon={Bug} label="Associated malware" value={malware.length} />
        <StatKpi icon={Wrench} label="Associated tools" value={tools.length} />
      </div>

      {/* TTPs covered: tactics this actor maps to in the knowledge base */}
      {tacticGroups.length > 0 && (
        <section>
          <SectionTitle icon={Crosshair} title="TTP Covered" count={tacticGroups.length} />
          <p className="mt-1 text-xs text-faint">
            {techniques.length} ATT&CK technique(s) mapped across these tactics.
          </p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {tacticGroups.map((g) => (
              <span
                key={g.tactic}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-base/60 px-2.5 py-1.5"
              >
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ background: tacticColor(g.tactic) }}
                />
                <span className="text-xs font-medium text-ink">{tacticLabel(g.tactic)}</span>
                <span className="font-mono text-[11px] text-dim">{g.list.length}</span>
              </span>
            ))}
          </div>
        </section>
      )}

      {/* Overview */}
      <section>
        <SectionTitle icon={ShieldQuestion} title="Overview" count={years || '—'} />
        <div className="mt-3 rounded-xl border border-line bg-base/60 p-4">
          {renderStixMarkdown(actor.description) || (
            <p className="text-sm text-faint">No description available.</p>
          )}
        </div>
      </section>

      {/* Target profile — sectors & countries derived deterministically from the
          MITRE ATT&CK intrusion-set description (Brief #4 Phase 1). Shown only
          when the source actually names them; otherwise absent (never guessed). */}
      {(actor.target_sectors?.length > 0 || actor.target_countries?.length > 0) && (
        <section>
          <SectionTitle
            icon={Crosshair}
            title="Target Profile"
            count={(actor.target_sectors?.length || 0) + (actor.target_countries?.length || 0)}
          />
          <p className="mt-1 text-xs text-faint">
            {actor.profile_source || 'Derived from the MITRE ATT&CK intrusion-set description'}.
          </p>
          {actor.target_sectors?.length > 0 && (
            <div className="mt-3">
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">
                Target sectors
              </p>
              <div className="flex flex-wrap gap-1.5">
                {actor.target_sectors.map((s) => (
                  <span
                    key={s}
                    className="rounded-md border border-primary/30 bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
          {actor.target_countries?.length > 0 && (
            <div className="mt-3">
              <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">
                Target countries
              </p>
              <div className="flex flex-wrap gap-1.5">
                {actor.target_countries.map((c) => (
                  <span
                    key={c}
                    className="rounded-md border border-line bg-raised px-2.5 py-1 text-xs font-medium text-dim"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Associated malware & tools */}
      <section>
        <SectionTitle icon={Bug} title="Associated Malware & Tools" count={actor.malware_tools?.length || 0} />
        {malware.length === 0 && tools.length === 0 ? (
          <p className="mt-3 text-sm text-faint">
            No malware or tools are mapped to this actor in the ATT&CK knowledge base.
          </p>
        ) : (
          <div className="mt-3 grid grid-cols-1 gap-3 xl:grid-cols-2">
            {[...malware, ...tools].map((item) => (
              <div key={item.stix_id} className="rounded-xl border border-line bg-surface p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <Link
                    to={`/malware/${encodeURIComponent(item.stix_id)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="group flex min-w-0 items-center gap-2 font-semibold text-sm text-ink hover:text-primary"
                    title={`Open ${item.name} profile in a new tab`}
                  >
                    {item.type === 'tool' ? <Wrench size={13} className="shrink-0 text-primary" /> : <Bug size={13} className="shrink-0 text-red-400" />}
                    <span className="truncate">{item.name}</span>
                    <ExternalLink size={11} className="shrink-0 text-faint transition-colors group-hover:text-primary" />
                  </Link>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge tone={item.type === 'tool' ? 'blue' : 'neutral'}>{item.type}</Badge>
                    <MitreLink url={item.url} />
                  </div>
                </div>
                <div className="mt-2 text-xs leading-relaxed text-dim [&_a]:break-all">
                  {renderStixMarkdown(item.description) || (
                    <span className="text-faint">No description.</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Observed ATT&CK techniques, grouped by tactic */}
      <section className="pb-2">
        <SectionTitle icon={Target} title="Observed ATT&CK Techniques" count={techniques.length} />
        {techniques.length === 0 ? (
          <p className="mt-3 text-sm text-faint">No techniques are mapped to this actor yet.</p>
        ) : (
          <div className="mt-3 space-y-4">
            {tacticGroups.map((group) => (
              <div key={group.tactic}>
                <div className="mb-1.5 flex items-center gap-2">
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: tacticColor(group.tactic) }}
                  />
                  <span className="text-xs font-semibold uppercase tracking-wide text-dim">
                    {tacticLabel(group.tactic)}
                  </span>
                  <span className="rounded-md border border-line bg-raised px-1.5 py-px font-mono text-[10px] text-dim">
                    {group.list.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {group.list.map((ttp) => (
                    <div key={ttp.stix_id} className="flex gap-3 rounded-xl border border-line bg-surface p-3.5">
                      <span className="mt-0.5 inline-flex h-fit shrink-0 items-center rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-bold text-primary">
                        {ttp.x_mitre_id}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-sm font-medium text-ink">{ttp.name}</span>
                          <MitreLink url={ttp.url} label="View on MITRE" />
                        </div>
                        <div className="mt-1 text-xs leading-relaxed text-dim [&_a]:break-all">
                          {renderStixMarkdown(ttp.description) || (
                            <span className="text-faint">No description.</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Attributed indicators (Brief #4 Phase 3). Feed attribution comes from OTX
        pulses that name an adversary; operators can additionally tag a real IOC
        from the corpus. This profile never guesses an attribution. */}
      <section className="pb-2">
        <SectionTitle icon={ShieldQuestion} title="Attributed Indicators" count={actor.attributed_ioc_count || 0} />
        {!actor.attributed_ioc_count ? (
          <div className="mt-3 rounded-xl border border-dashed border-line bg-base/40 p-4">
            <p className="text-sm font-medium text-ink">No attributed indicators yet</p>
            <p className="mt-1 text-xs leading-relaxed text-faint">
              Indicators are only tagged when a trusted source names the group — OTX pulses attribute
              their IOCs to an adversary — or when an analyst links a real indicator below. Nothing here
              is ever guessed.
            </p>
          </div>
        ) : (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {(actor.attributed_iocs || []).map((ioc) => (
              <span
                key={`${ioc.type}-${ioc.indicator}`}
                className="inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-1 font-mono text-[10px] text-dim"
                title={`${ioc.type} · tagged by ${ioc.source}${ioc.attributed_by ? ` (${ioc.attributed_by})` : ''}`}
              >
                <span className="text-[9px] font-bold uppercase tracking-wider text-faint">
                  {ioc.source}
                </span>
                {ioc.indicator}
                <span className="text-faint">{ioc.type}</span>
                {ioc.source === 'analyst' && (
                  <button
                    type="button"
                    onClick={() => handleUnattribute(ioc)}
                    disabled={attrRemoving === ioc.indicator}
                    className="ml-0.5 rounded p-0.5 text-faint transition-colors hover:bg-base hover:text-red-400 disabled:opacity-40"
                    title="Remove attribution"
                  >
                    <X size={11} />
                  </button>
                )}
              </span>
            ))}
          </div>
        )}

        {/* Operator tagging: only accepts indicators that already exist in the real IOC corpus. */}
        <form onSubmit={handleAttribute} className="mt-3 flex flex-wrap items-center gap-2">
          <select
            value={attrForm.type}
            onChange={(e) => setAttrForm((f) => ({ ...f, type: e.target.value }))}
            aria-label="Indicator type"
            className="rounded-lg border border-line bg-base px-2 py-1.5 font-mono text-xs text-ink focus:border-primary focus:outline-none"
          >
            {['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'cve', 'ja3', 'email'].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <input
            value={attrForm.indicator}
            onChange={(e) => setAttrForm((f) => ({ ...f, indicator: e.target.value }))}
            placeholder="Indicator from the IOC corpus…"
            className="min-w-0 flex-1 rounded-lg border border-line bg-base px-3 py-1.5 text-xs text-ink placeholder:text-faint focus:border-primary focus:outline-none"
          />
          <Button type="submit" size="sm" loading={attrBusy}>Attribute to this actor</Button>
        </form>
        {attrError && <p className="mt-2 text-xs text-red-400">{attrError}</p>}
        {attrDone && <p className="mt-2 text-xs text-primary">{attrDone}</p>}
      </section>

      <DetectionRules actor={actor} rules={rules} />
    </div>
  );
}

// -----------------------------------------------------------------------------
// Detection rules (Brief #4 Phase 2) — deterministic Sigma generation grounded
// in the KB. Every rule exists only for techniques the ATT&CK KB records this
// actor using; the `note` states they are starting points to review.
// -----------------------------------------------------------------------------

function downloadRuleYaml(rule, actorName) {
  const slug = `${actorName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.x_mitre_id}.yml`;
  const url = window.URL.createObjectURL(new Blob([rule.sigma], { type: 'application/x-yaml' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = slug;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

function LevelBadge({ level }) {
  const tone = level === 'high' ? 'red' : level === 'medium' ? 'blue' : 'neutral';
  return <Badge tone={tone}>{level}</Badge>;
}

function DetectionRules({ actor, rules }) {
  const data = rules?.data;
  const loading = rules?.loading && !data;
  const error = rules?.error;

  return (
    <section className="pb-2">
      <SectionTitle icon={Crosshair} title="Detection Rules" count={data ? data.generated : '…'} />
      {loading ? (
        <div className="mt-3 space-y-3">
          {[0, 1].map((i) => (
            <div key={i} className="rounded-xl border border-line p-4">
              <Skeleton className="mb-3 h-4 w-1/2" />
              <Skeleton className="h-28 w-full" />
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="mt-3">
          <ErrorState
            title="Failed to generate detection rules"
            message={errorText(error)}
            onRetry={rules.reload}
          />
        </div>
      ) : !data ? null : (
        <>
          <p className="mt-1 text-xs text-faint">{data.note}</p>
          {data.generated === 0 ? (
            <div className="mt-3 rounded-xl border border-dashed border-line bg-base/40 p-4">
              <p className="text-sm font-medium text-ink">No rules generated</p>
              <p className="mt-1 text-xs leading-relaxed text-faint">
                {(actor.ttps || []).length === 0
                  ? 'This actor has no techniques recorded in the ATT&CK knowledge base — there is nothing to build a rule from.'
                  : 'The analyst-owned Sigma templates do not yet cover any of the techniques this actor uses in the KB. Nothing is guessed beyond the template set.'}
              </p>
              {data.unmapped_count > 0 && (
                <div className="mt-3">
                  <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">
                    Techniques without a template ({data.unmapped_count})
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.unmapped.map((u) => (
                      <span
                        key={u.x_mitre_id}
                        className="rounded-md border border-line bg-raised px-2 py-1 font-mono text-[10px] text-dim"
                        title={u.name}
                      >
                        {u.x_mitre_id}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="mt-3 space-y-4">
              <div className="flex flex-wrap gap-1.5 text-[11px] text-dim">
                <span className="rounded-md border border-line bg-raised px-2 py-1">
                  {data.generated} rule{data.generated === 1 ? '' : 's'} generated
                </span>
                {data.unmapped_count > 0 && (
                  <span
                    className="rounded-md border border-line bg-raised px-2 py-1"
                    title={data.unmapped.map((u) => u.x_mitre_id).join(', ')}
                  >
                    {data.unmapped_count} techniques without a template
                  </span>
                )}
              </div>
              {data.rules.map((rule) => (
                <div key={rule.rule_id} className="overflow-hidden rounded-xl border border-line bg-surface">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-base/60 px-3.5 py-2.5">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="inline-flex items-center rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-bold text-primary">
                        {rule.x_mitre_id}
                      </span>
                      <span className="truncate text-sm font-semibold text-ink">{rule.technique_name}</span>
                      <span className="hidden text-xs text-faint sm:inline">{rule.tactic}</span>
                      <LevelBadge level={rule.level} />
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <CopyButton value={rule.sigma} label="Copy Sigma rule" />
                      <button
                        type="button"
                        onClick={() => downloadRuleYaml(rule, actor.name)}
                        title="Download as .yml"
                        className="inline-flex items-center gap-1 rounded border border-line bg-raised px-1.5 py-0.5 text-[10px] text-dim transition-colors hover:border-primary/40 hover:text-primary"
                      >
                        <Download size={10} /> yml
                      </button>
                    </div>
                  </div>
                  <pre className="max-h-[300px] overflow-auto p-3.5 font-mono text-[11px] leading-relaxed text-dim">
                    {rule.sigma}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}