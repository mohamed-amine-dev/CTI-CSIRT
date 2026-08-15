import React, { useEffect, useMemo, useState } from 'react';
import { RadioTower } from 'lucide-react';
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
 * Live Threat Feeds (/feeds) — browse raw items from CISA, CERTs, abuse.ch,
 * Hacker News, dark web … Filter by source / category / threat / text,
 * paginate, and trigger on-demand Sheet generation from any item.
 * Supports a `?threat=` deep link (used by the Threat Landscape panel).
 */
export default function Feeds() {
  const [searchParams] = useSearchParams();
  const initialThreat = searchParams.get('threat') || '';
  const [source, setSource] = useState('');
  const [category, setCategory] = useState('');
  const [threat, setThreat] = useState(initialThreat);
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => onRefresh(() => setReloadKey((k) => k + 1)), []);
  // Reset pagination whenever a filter changes.
  useEffect(() => setOffset(0), [source, category, threat, search]);

  const params = useMemo(
    () => ({
      source: source || undefined,
      category: category || undefined,
      threat: threat || undefined,
      search: search || undefined,
      limit: PAGE_SIZE,
      offset,
    }),
    [source, category, threat, search, offset]
  );

  const sources = useApi(() => unwrap(api.getFeedSources()), { deps: [reloadKey], refreshMs: 60_000 });
  const feeds = useApi(() => unwrap(api.getFeeds(params)), { deps: [JSON.stringify(params), reloadKey] });

  const items = feeds.data?.items || [];
  const hasMore = items.length === PAGE_SIZE;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <RadioTower size={20} className="text-cyan-400" /> Live Threat Feeds
        </h1>
        <p className="text-xs text-dim">
          CISA · CERT-FR · CERT-EU · abuse.ch · Hacker News · dark web &amp; Telegram
        </p>
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

      {feeds.loading && items.length === 0 ? (
        <Loader label="Fetching live feeds…" />
      ) : feeds.error ? (
        <ErrorState title="Failed to load feeds" message={errorText(feeds.error)} onRetry={feeds.reload} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={RadioTower}
          title="No feed items match"
          message="Try widening the source or category filters."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {items.map((f) => (
              <FeedCard key={f.ts + f.source + f.url} feed={f} />
            ))}
          </div>

          <div className="flex justify-center gap-3 pt-2">
            <Button variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              Previous
            </Button>
            <span className="px-2 py-2 text-xs text-faint">
              showing {items.length} of {feeds.data?.total ?? '…'}
            </span>
            <Button variant="secondary" disabled={!hasMore} onClick={() => setOffset(offset + PAGE_SIZE)}>
              Load more
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
