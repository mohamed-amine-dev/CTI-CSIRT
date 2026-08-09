import React, { useCallback, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

/**
 * CopyButton — one-click copy with a brief "copied" confirmation.
 * Used heavily on extracted IoCs and CVE identifiers.
 */
export default function CopyButton({ value, label, className = '' }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef(null);

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Clipboard API unavailable (non-secure context): fallback.
      const ta = document.createElement('textarea');
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1500);
  }, [value]);

  return (
    <button
      onClick={onCopy}
      title={label || 'Copy'}
      className={`inline-flex items-center gap-1 rounded border border-line bg-raised px-1.5 py-0.5 text-[10px] text-dim transition-colors hover:border-cyan-500/40 hover:text-cyan-300 ${className}`}
    >
      {copied ? (
        <>
          <Check size={10} className="text-emerald-400" /> copied
        </>
      ) : (
        <>
          <Copy size={10} /> copy
        </>
      )}
    </button>
  );
}
