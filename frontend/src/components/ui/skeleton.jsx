import React from 'react';
import { cn } from '../../lib/utils';

/** Skeleton — shimmering placeholder block for loading states. */
export function Skeleton({ className, ...props }) {
  return <div className={cn('animate-pulse rounded-md bg-muted', className)} {...props} />;
}