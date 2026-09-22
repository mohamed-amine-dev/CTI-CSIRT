import React from 'react';
import { cn } from '../../lib/utils';
import { severityStyle } from '../../utils/format';

/**
 * Badge — compact pill for severity levels, types, and status.
 * Uses the CRITICAL/HIGH/MEDIUM/LOW/INFO colour system when `severity` is set.
 */
export default function Badge({ severity, children, tone = 'default', className = '' }) {
  let classes;

  if (severity) {
    classes = severityStyle(severity).badge;
  } else if (tone === 'neutral') {
    classes = 'border border-line bg-raised text-dim';
  } else if (tone === 'blue') {
    classes = 'border border-primary/30 bg-primary/10 text-primary';
  } else {
    // default (was cyan — now uses primary blue)
    classes = 'border border-primary/30 bg-primary/10 text-primary';
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide',
        classes,
        className,
      )}
    >
      {children}
    </span>
  );
}