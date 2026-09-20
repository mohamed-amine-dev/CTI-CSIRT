import React from 'react';
import { cn } from '../../lib/utils';

/**
 * Card — the base surface for every dashboard widget.
 * Professional enterprise style: clean header, subtle shadow, consistent padding.
 */
export default function Card({
  title,
  subtitle,
  icon: Icon,
  actions,
  children,
  className = '',
  padded = true,
  bodyClassName = '',
  headerClassName = '',
}) {
  return (
    <div className={cn('rounded-xl border border-line bg-surface text-ink shadow-sm', className)}>
      {(title || actions) && (
        <div
          className={cn(
            'flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line px-5 py-3.5',
            headerClassName,
          )}
        >
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2.5 gap-y-0.5">
            {Icon && (
              <Icon size={15} className="shrink-0 text-primary/80" aria-hidden="true" />
            )}
            <h3 className="text-sm font-semibold text-ink">{title}</h3>
            {subtitle && (
              <span className="text-xs text-faint">{subtitle}</span>
            )}
          </div>
          {actions && (
            <div className="flex items-center gap-2">{actions}</div>
          )}
        </div>
      )}
      <div className={padded ? cn('p-5', bodyClassName) : bodyClassName}>
        {children}
      </div>
    </div>
  );
}