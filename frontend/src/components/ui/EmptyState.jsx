import React from 'react';
import { Inbox } from 'lucide-react';

/**
 * EmptyState — friendly placeholder for empty lists / failed lookups.
 */
export default function EmptyState({ icon: Icon = Inbox, title, message, children }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-line bg-base/40 py-14 text-center">
      <Icon size={28} className="text-faint" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-ink">{title}</p>
        {message && <p className="mt-1 max-w-md text-xs text-dim">{message}</p>}
      </div>
      {children}
    </div>
  );
}
