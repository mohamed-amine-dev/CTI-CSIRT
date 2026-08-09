import React from 'react';
import { Loader2 } from 'lucide-react';

const STYLES = {
  primary:
    'bg-cyan-500 text-slate-950 hover:bg-cyan-400 focus-visible:ring-cyan-400/60 font-semibold',
  secondary:
    'bg-raised text-ink border border-line hover:border-cyan-500/40 hover:text-cyan-300',
  danger: 'bg-red-500/10 text-red-400 border border-red-500/40 hover:bg-red-500/20',
  ghost: 'text-dim hover:text-ink hover:bg-raised',
};

/**
 * Button — variants (primary / secondary / danger / ghost), sizes and an
 * optional loading spinner (auto-disables while loading).
 */
export default function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  icon: Icon,
  children,
  className = '',
  disabled,
  ...rest
}) {
  const sizes = {
    sm: 'px-2.5 py-1.5 text-xs gap-1.5',
    md: 'px-3.5 py-2 text-sm gap-2',
    lg: 'px-5 py-2.5 text-sm gap-2',
  };
  return (
    <button
      className={`inline-flex items-center justify-center rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-50 ${STYLES[variant]} ${sizes[size]} ${className}`}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? (
        <Loader2 size={size === 'sm' ? 14 : 16} className="animate-spin" aria-hidden="true" />
      ) : (
        Icon && <Icon size={size === 'sm' ? 14 : 16} aria-hidden="true" />
      )}
      {children}
    </button>
  );
}
