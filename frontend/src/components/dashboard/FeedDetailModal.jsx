import React from 'react';
import { ExternalLink } from 'lucide-react';

import Modal from '../ui/Modal';
import Badge from '../ui/Badge';
import { categorySeverity, timeAgo } from '../../utils/format';

/**
 * FeedDetailModal — click-through view for a ticker / feed item. Shows the
 * structured fields (e.g. Shodan ports/CVEs), the full raw text, and a link
 * to the source page. Pure view over the data the API already provides.
 */
export default function FeedDetailModal({ feed, onClose }) {
  if (!feed) return null;
  const sev = categorySeverity(feed.category);

  const structuredRows = feed.structured
    ? Object.entries(feed.structured)
        .filter(([key, value]) => Array.isArray(value) ? value.length > 0 : Boolean(value))
        .map(([key, value]) => ({
          label: key,
          value: Array.isArray(value) ? value.join(', ') : String(value),
        }))
    : [];

  return (
    <Modal
      open={Boolean(feed)}
      onClose={onClose}
      title={feed.title || feed.raw_text?.slice(0, 80) || 'Feed item'}
      subtitle={`${feed.source} · ${timeAgo(feed.ts)}`}
      width="max-w-2xl"
    >
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Badge severity={sev}>{feed.category}</Badge>
          <span className="text-[11px] text-faint">{feed.ts}</span>
        </div>

        {structuredRows.length > 0 && (
          <div className="grid grid-cols-1 gap-x-6 gap-y-2 rounded-xl border border-line bg-base/40 px-4 py-3 sm:grid-cols-2">
            {structuredRows.map(({ label, value }) => (
              <div key={label} className="min-w-0">
                <dt className="font-mono text-[10px] uppercase tracking-wide text-faint">{label}</dt>
                <dd className="mt-0.5 break-words text-xs text-ink">{value}</dd>
              </div>
            ))}
          </div>
        )}

        {feed.url ? (
          <a
            href={feed.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-300 hover:text-cyan-200 hover:underline"
          >
            <ExternalLink size={13} /> Open source page
          </a>
        ) : null}

        <div>
          <h4 className="mb-1.5 font-mono text-[10px] uppercase tracking-wide text-faint">Raw record</h4>
          <pre className="whitespace-pre-wrap break-words rounded-xl border border-line bg-base/40 px-4 py-3 text-xs leading-relaxed text-dim">
            {feed.raw_text || 'No raw text for this item.'}
          </pre>
        </div>
      </div>
    </Modal>
  );
}
