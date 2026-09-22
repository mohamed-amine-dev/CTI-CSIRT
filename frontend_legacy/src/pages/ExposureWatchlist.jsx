import React, { useMemo, useState } from 'react';
import {
  Bell, Crosshair, Plus, RefreshCw, Search, Target, Trash2, EyeOff,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { Input } from '../components/ui/input';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';

const TARGET_TYPES = ['domain', 'phone', 'email', 'org'];
const TYPE_HINTS = {
  domain: 'e.g. example.com (subdomains match too)',
  phone: 'e.g. +33 1 23 45 67 89',
  email: 'e.g. jdoe@example.com',
  org: 'e.g. ACME Corp — keyword in the text',
};

/** Highlight matched spans inside a raw-text string. */
function HighlightedText({ text, matches }) {
  const spans = useMemo(
    () => (matches || [])
      .map((m) => ({ start: m.start ?? 0, end: m.end ?? 0, term: m.term ?? '' }))
      .filter((s) => s.end > s.start && s.start >= 0 && s.end <= (text?.length ?? 0))
      .sort((a, b) => a.start - b.start),
    [text, matches],
  );
  if (!text) return <span className="text-faint">(no content)</span>;
  if (!spans.length) return <span className="whitespace-pre-wrap break-words text-ink">{text}</span>;

  const nodes = [];
  let cursor = 0;
  spans.forEach((s, i) => {
    if (s.start > cursor) nodes.push(<span key={`t${i}`}>{text.slice(cursor, s.start)}</span>);
    nodes.push(
      <mark key={`m${i}`} className="rounded bg-rose-500/20 px-0.5 text-rose-400 ring-1 ring-rose-500/40">
        {text.slice(s.start, s.end)}
      </mark>,
    );
    cursor = s.end;
  });
  if (cursor < text.length) nodes.push(<span key="tail">{text.slice(cursor)}</span>);
  return <span className="whitespace-pre-wrap break-words text-ink">{nodes}</span>;
}

/**
 * ExposureWatchlist — Org Exposure Search & Watchlist.
 *  * Search: immediate, real matches over the ingested dark-web/telegram corpus
 *    (domain / phone / email / org), matched term highlighted. A zero-result
 *    search is reported honestly, never fabricated.
 *  * Watchlist: persist targets; every ingestion cycle re-scans new dark-web /
 *    telegram rows against them and records + alerts real matches through the
 *    existing notification pipeline.
 *  * Recorded matches: what the automatic sweep has flagged so far.
 */
export default function ExposureWatchlist() {
  // --- search panel -------------------------------------------------------
  const [stype, setStype] = useState('domain');
  const [svalue, setSvalue] = useState('');
  const [searchReq, setSearchReq] = useState(null);
  const search = useApi(
    () => unwrap(api.searchExposure(searchReq.type, searchReq.value)),
    { deps: [searchReq && `${searchReq.type}|${searchReq.value}`], auto: !!searchReq },
  );

  const runSearch = (e) => {
    e?.preventDefault();
    const v = svalue.trim();
    if (!v) return;
    setSearchReq({ type: stype, value: v });
  };

  // --- watchlist ----------------------------------------------------------
  const targets = useApi(() => unwrap(api.getWatchlist()));
  const matches = useApi(() => unwrap(api.getWatchlistMatches(50)));

  const [atype, setAtype] = useState('domain');
  const [avalue, setAvalue] = useState('');
  const [alabel, setAlabel] = useState('');
  const addTarget = useAsync((type, value, label) =>
    unwrap(api.addWatchlistTarget(type, value, label)));
  const deleteTarget = useAsync((id) => unwrap(api.deleteWatchlistTarget(id)));

  const submitAdd = async (e) => {
    e.preventDefault();
    if (!avalue.trim()) return;
    try {
      await addTarget.run(atype, avalue.trim(), alabel.trim());
      setAvalue('');
      setAlabel('');
      targets.reload();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      if (detail) window.alert(`Cannot add target: ${detail}`);
    }
  };

  const removeTarget = async (id) => {
    if (!window.confirm('Delete this watchlist target?')) return;
    try {
      await deleteTarget.run(id);
      targets.reload();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      if (detail) window.alert(`Cannot delete: ${detail}`);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-xl font-bold text-ink">Org Exposure &amp; Watchlist</h1>
        <p className="text-sm text-dim">
          Search the ingested dark-web / Telegram corpus for your company, domains,
          phones and emails — then keep them watched: every ingestion cycle
          re-scans and alerts on real matches.
        </p>
      </header>

      <div className="grid gap-4 xl:grid-cols-5">
        {/* ---------- Search ------------------------------------------------- */}
        <Card
          className="xl:col-span-3"
          title="Exposure search"
          subtitle="DARKWEB-ONION + Telegram rows already ingested"
          icon={Search}
        >
          <div className="flex flex-col gap-3">
            <form onSubmit={runSearch} className="flex flex-col gap-3 sm:flex-row">
              <Select value={stype} onValueChange={(v) => setStype(v)}>
                <SelectTrigger className="w-full sm:w-40">
                  <SelectValue placeholder="Type" />
                </SelectTrigger>
                <SelectContent>
                  {TARGET_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                value={svalue}
                onChange={(e) => setSvalue(e.target.value)}
                placeholder={TYPE_HINTS[stype]}
                className="flex-1"
              />
              <Button type="submit" variant="primary" loading={search.loading}>
                Search
              </Button>
            </form>
            <p className="text-[11px] text-faint">{TYPE_HINTS[stype]}</p>

            {search.error && <ErrorState message={errorText(search.error)} />}

            {search.data && search.data.total === 0 && (
              <EmptyState
                icon={EyeOff}
                title="No exposure found"
                message={`Honest zero: nothing in the scanned corpus matches "${search.data.value}" as ${search.data.type}. Try another spelling or value.`}
              />
            )}

            {search.data && search.data.total > 0 && (
              <div className="flex flex-col gap-2">
                <p className="text-xs text-dim">
                  <strong className="text-ink">{search.data.total}</strong> match(es) across{' '}
                  <strong className="text-ink">{search.data.items_matched}</strong> of{' '}
                  {search.data.scanned} scanned item(s) for{' '}
                  <code className="rounded bg-raised px-1 py-0.5 text-[11px]">{search.data.value}</code>
                </p>
                <div className="flex max-h-96 flex-col gap-2 overflow-y-auto pr-1">
                  {search.data.items.map((it, i) => (
                    <div key={`${it.source}-${it.url}-${i}`} className="rounded-lg border border-line bg-base/60 p-3">
                      <div className="mb-1.5 flex flex-wrap items-center gap-2 text-[11px] text-dim">
                        <Badge tone="blue">{it.source}</Badge>
                        <span className="font-semibold text-ink">{it.title}</span>
                        {it.url && (
                          <a href={it.url} target="_blank" rel="noreferrer" className="truncate text-primary hover:underline">
                            {it.url}
                          </a>
                        )}
                        <span className="ml-auto font-mono">{it.ts}</span>
                      </div>
                      <p className="text-[13px] leading-relaxed">
                        <HighlightedText text={it.raw_text} matches={it.matches} />
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!search.data && !search.error && (
              <EmptyState
                icon={Crosshair}
                title="Search the corpus"
                message="Run a one-off exposure check over the ingested dark-web and Telegram items — the matched term is highlighted where found."
              />
            )}
          </div>
        </Card>

        {/* ---------- Watchlist ---------------------------------------------- */}
        <Card
          className="xl:col-span-2"
          title="Watchlist"
          subtitle="Re-checked on every ingestion cycle; real matches alert via the existing notification pipeline"
          icon={Target}
        >
          <div className="flex flex-col gap-3">
            {targets.error && <ErrorState message={errorText(targets.error)} />}

            <form onSubmit={submitAdd} className="flex flex-col gap-2">
              <div className="flex gap-2">
                <Select value={atype} onValueChange={(v) => setAtype(v)}>
                  <SelectTrigger className="w-32">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    {TARGET_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={avalue}
                  onChange={(e) => setAvalue(e.target.value)}
                  placeholder={TYPE_HINTS[atype]}
                  className="flex-1"
                />
              </div>
              <Input
                value={alabel}
                onChange={(e) => setAlabel(e.target.value)}
                placeholder="Label (optional, e.g. Our primary domain)"
              />
              <Button type="submit" variant="primary" size="sm" icon={Plus} loading={addTarget.loading} className="self-start">
                Watch this value
              </Button>
            </form>

            {addTarget.data?.created === false && (
              <p className="text-[11px] text-faint">Already watched — not added twice.</p>
            )}

            <div className="flex max-h-56 flex-col gap-1.5 overflow-y-auto pr-1">
              {(targets.data?.items || []).map((t) => (
                <div key={t.id} className="flex items-center gap-2 rounded-lg border border-line bg-base/60 px-2.5 py-2 text-sm">
                  <Badge tone="blue" className="shrink-0">{t.type}</Badge>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] text-ink">{t.value}</p>
                    {t.label && <p className="truncate text-[11px] text-dim">{t.label}</p>}
                  </div>
                  <Button
                    variant="danger" size="sm"
                    icon={Trash2}
                    onClick={() => removeTarget(t.id)}
                    loading={deleteTarget.loading}
                  >
                    Remove
                  </Button>
                </div>
              ))}
              {!targets.loading && !targets.error && (targets.data?.items || []).length === 0 && (
                <EmptyState
                  icon={Target}
                  title="Nothing watched yet"
                  message="Add a domain, phone, email or org name above — future ingestion cycles check new dark-web/Telegram rows against it."
                />
              )}
            </div>
          </div>
        </Card>
      </div>

      {/* ---------- Recorded matches ----------------------------------------- */}
      <Card
        title="Recorded matches"
        subtitle="What the automatic sweep has flagged so far (newest first) — one row per target per item"
        icon={Bell}
      >
        <div className="flex flex-col gap-2">
          {matches.error && <ErrorState message={errorText(matches.error)} />}

          {(matches.data?.items || []).length === 0 && !matches.loading && !matches.error && (
            <EmptyState
              icon={RefreshCw}
              title="No recorded matches yet"
              message="Once a watched value genuinely appears in a new dark-web/Telegram item, it lands here and notifies through the existing alert pipeline."
            />
          )}

          <div className="flex max-h-72 flex-col gap-1.5 overflow-y-auto pr-1">
            {(matches.data?.items || []).map((m) => (
              <div key={m.id} className="rounded-lg border border-line bg-base/60 p-2.5 text-sm">
                <div className="mb-1 flex flex-wrap items-center gap-2 text-[11px] text-dim">
                  <Badge tone="blue">{m.target_type}</Badge>
                  <span className="font-semibold text-ink">{m.target_label || m.target_value}</span>
                  <Badge tone="neutral">{m.source}</Badge>
                  {m.url && (
                    <a href={m.url} target="_blank" rel="noreferrer" className="truncate text-primary hover:underline">
                      {m.url}
                    </a>
                  )}
                  <span className="ml-auto font-mono">{m.created_at}</span>
                </div>
                <p className="text-[12px] leading-relaxed text-dim">
                  Matched term: <code className="rounded bg-raised px-1 text-[11px] text-rose-400">{m.matched_term}</code>
                </p>
                {m.snippet && <p className="mt-1 text-[12px] leading-relaxed text-ink">{m.snippet}</p>}
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}