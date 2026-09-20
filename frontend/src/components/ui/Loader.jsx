import React from 'react';
import { Loader2 } from 'lucide-react';

/**
 * Loader — centered spinner block, optionally with a label.
 */
export default function Loader({ label = 'Loading…', className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center gap-3 py-14 text-dim ${className}`}>
      <Loader2 size={24} className="animate-spin text-primary" aria-hidden="true" />
      <span className="text-xs tracking-wide">{label}</span>
    </div>
  );
}
