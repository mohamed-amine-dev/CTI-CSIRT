import React from 'react';

import { severityStyle } from '../../utils/format';

/**
 * Badge — small high-contrast pill. When `severity` is provided it uses the
 * CRITICAL/HIGH/MEDIUM/LOW/INFO colour system; otherwise a neutral cyan badge.
 */
export default function Badge({ severity, children, tone = 'cyan', className = '' }) {
  let classes = 'border border-cyan-500/40 bg-cyan-500/10 text-cyan-300';
  if (severity) classes = severityStyle(severity).badge;
  if (tone === 'neutral') classes = 'border border-line bg-raised text-dim';

  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${classes} ${className}`}
    >
      {children}
    </span>
  );
}
