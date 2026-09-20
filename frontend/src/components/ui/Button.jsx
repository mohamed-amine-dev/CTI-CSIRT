import React from 'react';
import { Loader2 } from 'lucide-react';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        primary:
          'bg-primary text-primary-foreground shadow-sm hover:bg-primary/90 font-semibold',
        secondary:
          'bg-raised text-ink border border-line hover:border-primary/40 hover:text-primary',
        danger:
          'bg-destructive/10 text-red-400 border border-destructive/30 hover:bg-destructive/15',
        ghost:
          'text-dim hover:text-ink hover:bg-raised',
        outline:
          'border border-primary/40 text-primary hover:bg-primary/10',
      },
      size: {
        sm: 'h-7 px-2.5 text-xs gap-1.5',
        md: 'h-9 px-3.5 text-sm gap-2',
        lg: 'h-10 px-5 text-sm gap-2',
      },
    },
    defaultVariants: {
      variant: 'secondary',
      size: 'md',
    },
  },
);

/**
 * Button — shadcn-style variants (primary / secondary / danger / ghost / outline),
 * sizes and an optional loading spinner.
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
  return (
    <button
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? (
        <Loader2 size={size === 'sm' ? 13 : 15} className="animate-spin" aria-hidden="true" />
      ) : (
        Icon && <Icon size={size === 'sm' ? 13 : 15} aria-hidden="true" />
      )}
      {children}
    </button>
  );
}

export { buttonVariants };