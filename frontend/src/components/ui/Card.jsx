import React from 'react';

/**
 * Card — the base surface for every dashboard widget.
 * Renders an optional header row (title / icon / actions) with a bottom border
 * and a body that is padded unless `padded={false}`.
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
}) {
  return (
    <div className={`rounded-xl border border-line bg-surface shadow-sm ${className}`}>
      {(title || actions) && (
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line px-5 py-3">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2.5 gap-y-0.5">
            {Icon && <Icon size={16} className="shrink-0 text-cyan-400" aria-hidden="true" />}
            <h3 className="text-sm font-semibold tracking-wide text-ink">{title}</h3>
            {subtitle && <span className="text-xs text-faint">{subtitle}</span>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={padded ? `p-5 ${bodyClassName}` : bodyClassName}>{children}</div>
    </div>
  );
}
