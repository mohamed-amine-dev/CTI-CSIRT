import React from 'react';
import { AlertTriangle, RotateCw } from 'lucide-react';

/**
 * ErrorState — consistent inline error for a data-driven panel whose API call
 * failed (as opposed to ErrorBoundary, which catches render crashes). Includes
 * a retry action wired to the panel's `reload`.
 */
export default function ErrorState({ title = 'Failed to load data', message, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-6 py-10 text-center">
      <AlertTriangle size={26} className="text-red-400" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-ink">{title}</p>
        {message && <p className="mt-1 max-w-md text-xs text-dim">{message}</p>}
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="focus-neon flex items-center gap-1.5 rounded-lg border border-line bg-raised px-3 py-2 text-xs font-semibold text-ink transition-colors hover:border-cyan-500/40"
        >
          <RotateCw size={13} aria-hidden="true" /> Retry
        </button>
      )}
    </div>
  );
}
