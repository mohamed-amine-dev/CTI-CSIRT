import React from 'react';
import { Globe } from 'lucide-react';

import Card from '../ui/Card';

/**
 * RealTimeMap — live global attack map.
 *
 * Embeds the Kaspersky Cybermap dark-mode widget via its official embeddable
 * iframe. The map renders from Kaspersky's CDN in the browser (no backend call),
 * so it works even while ClickHouse ingestion is warming up.
 */
export default function RealTimeMap({ height = 600 }) {
  return (
    <Card title="Global Threat Activity" icon={Globe} subtitle="Kaspersky Cybermap · live attacks">
      <div className="overflow-hidden rounded-lg border border-line bg-black/70">
        <iframe
          title="Kaspersky Cybermap — global attack activity"
          src="https://cybermap.kaspersky.com/en/widget/dynamic/dark"
          width="100%"
          height={height}
          frameBorder="0"
          allowFullScreen
          loading="lazy"
          referrerPolicy="no-referrer-when-downgrade"
          className="block w-full"
        />
      </div>
      <p className="mt-2 text-[11px] text-faint">
        Live cyber-attacks visualised from Kaspersky Security Network telemetry — best viewed in dark mode.
      </p>
    </Card>
  );
}
