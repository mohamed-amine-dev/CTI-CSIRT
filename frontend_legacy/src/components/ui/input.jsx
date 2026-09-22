import React from 'react';
import { cn } from '../../lib/utils';

export function Input({ className, type, ...props }) {
  return (
    <input
      type={type}
      className={cn(
        'flex h-9 w-full rounded-md border border-input bg-surface px-3 py-1 text-sm text-ink shadow-sm transition-colors placeholder:text-faint focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    />
  );
}