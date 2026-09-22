import React from 'react';
import { Globe, Send } from 'lucide-react';

import { StreamPage } from './stream/StreamPage';

/**
 * Monitoring page that hosts the ported Dark Web / Telegram stream views inside
 * the platform shell. Two routes render this same component with a fixed
 * `kind`: /darkweb-monitor and /telegram-monitor.
 */
export default function StreamMonitor({ kind }) {
  const isTelegram = kind === 'telegram';
  const Icon = isTelegram ? Send : Globe;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-surface">
            <Icon size={16} className={isTelegram ? 'text-sky-400' : 'text-primary'} />
          </div>
          <div>
            <h1 className="text-base font-semibold text-ink">
              {isTelegram ? 'Telegram Monitoring' : 'Dark Web Monitoring'}
            </h1>
            <p className="text-xs text-faint">
              {isTelegram
                ? 'Channel messages ingested by the Telegram collector'
                : 'Onion-site search results ingested by the Dark Web collector'}
            </p>
          </div>
        </div>
      </div>
      <StreamPage kind={kind} />
    </div>
  );
}