import React from 'react';
import { cn } from '../../lib/utils';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './dialog';

/**
 * Modal — accessible overlay dialog built on Radix Dialog.
 * Closes on Esc, on backdrop click, or via the X button. API unchanged.
 */
export default function Modal({ open, onClose, title, subtitle, children, footer, width = 'max-w-3xl' }) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className={cn('max-h-[85vh] overflow-hidden gap-0 p-0', width)}>
        <DialogHeader className="flex-row items-start justify-between gap-4 border-b border-line px-6 py-4">
          <div>
            <DialogTitle>{title}</DialogTitle>
            {subtitle && <DialogDescription className="mt-1 text-xs">{subtitle}</DialogDescription>}
          </div>
        </DialogHeader>
        <div className="max-h-[65vh] overflow-y-auto px-6 py-5">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-6 py-4">{footer}</div>}
      </DialogContent>
    </Dialog>
  );
}