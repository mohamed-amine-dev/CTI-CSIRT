import React from 'react';
import { Globe } from 'lucide-react';

import { StreamPage } from './stream/StreamPage';

/**
 * Dark Web Monitoring — hosts the ported stream view inside the platform
 * shell. Telegram monitoring was removed from the product; this page is the
 * dedicated onion-scrape surface (/darkweb-monitor).
 */
export default function StreamMonitor() {
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
            <Globe size={16} className="text-primary" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">Dark Web Monitoring</h1>
            <p className="text-xs text-faint">
              Onion-site search results ingested by the Dark Web collector
            </p>
          </div>
        </div>
      </div>
      <StreamPage />
    </div>
  );
}