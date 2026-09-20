import React, { useEffect, useMemo, useState } from 'react';
import { RadioTower, SlidersHorizontal } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import FeedCard from '../components/feeds/FeedCard';
import FeedFilters from '../components/feeds/FeedFilters';
import Button from '../components/ui/Button';
import Loader from '../components/ui/Loader';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { useApi } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { onRefresh } from '../utils/events';
import { PAGE_SIZE } from '../config';

/**
 * Live Threat Feeds (/feeds) — filterable stream of raw intelligence items.
 */
export default function Feeds() {
  const [searchParams] = useSearchParams();
  const initialThreat = searchParams.get('threat') || '';
  const [source,   setSource]   = useState('');
  const [category, setCategory] = useState('');
  const [threat,   setThreat]   = useState(initialThreat);
  const [search,   setSearch]   = useState('');
  const [offset,   setOffset]   = useState(0);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);
  useEffect(() => setOffset(0), [source, category, threat, search]);

  const params = useMemo(
    () => ({
      source:   source   || undefined,
      category: category || undefined,
      threat:   threat   || undefined,
      search:   search   || undefined,
      limit:    PAGE_SIZE,
      offset,
    }),
    [source, category, threat, search, offset],
  );

  const sources = useApi(() => unwrap(api.getFeedSources()), { deps: [reloadKey], refreshMs: 60_000 });
  const feeds   = useApi(() => unwrap(api.getFeeds(params)), { deps: [JSON.stringify(params), reloadKey] });

  const items   = feeds.data?.items || [];
  const total   = feeds.data?.total ?? null;
  const hasMore = items.length === PAGE_SIZE;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
            <RadioTower size={16} className="text-primary" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">Live Threat Feeds</h1>
            <p className="text-xs text-faint">
              CISA · CERT-FR · CERT-EU · abuse.ch · Hacker News · dark web & Telegram
            </p>
          </div>
        </div>
        {total !== null && (
          <span className="rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-dim">
            {total.toLocaleString()} items
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-widest text-faint">
          <SlidersHorizontal size={12} />
          Filters
        </div>
        <FeedFilters
          source={source}
          setSource={setSource}
          category={category}
          setCategory={setCategory}
          threat={threat}
          setThreat={setThreat}
          search={search}
          setSearch={setSearch}
          sources={sources.data?.sources}
          onReset={() => {
            setSource('');
            setCategory('');
            setThreat('');
            setSearch('');
          }}
        />
      </div>

      {/* Content */}
      {feeds.loading && items.length === 0 ? (
        <Loader label="Fetching live feeds…" />
      ) : feeds.error ? (
        <ErrorState
          title="Failed to load feeds"
          message={errorText(feeds.error)}
          onRetry={feeds.reload}
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={RadioTower}
          title="No feed items match"
          message="Try widening the source or category filters, or trigger a Force Sync."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {items.map((f) => (
              <FeedCard key={f.ts + f.source + f.url} feed={f} />
            ))}
          </div>

          <div className="flex items-center justify-between border-t border-line pt-4">
            <span className="text-xs text-faint">
              Showing {offset + 1}–{offset + items.length}
              {total !== null ? ` of ${total.toLocaleString()}` : ''}
            </span>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                Previous
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={!hasMore}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Load more
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
