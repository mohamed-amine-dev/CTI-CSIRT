import React, { useMemo, useState } from 'react';
import { Copy, ExternalLink, ScanSearch, ShieldCheck } from 'lucide-react';

import Badge from '../ui/Badge';
import Button from '../ui/Button';
import CopyButton from '../ui/CopyButton';
import { categorySeverity, timeAgo } from '../../utils/format';
import { extractIoCs, IOC_TYPE_LABELS } from '../../utils/iocs';

/**
 * DarkWebCard — a professional threat-monitoring lead card for the Dark Web &
 * Telegram monitor. Unlike the generic FeedCard it presents the item as an
 * intelligence lead: source + category + recency in the header, the actor /
 * victim subject bolded in a high-contrast headline, a collapsible raw
 * snippet, and SOC-style actions (regex IoC extraction, copy raw report).
 */

// "source — headline" separators: a leading chunk that looks like a scraped
// news site (contains a dash, bullet or an archive/news site name).
const SOURCE_MARKER_RE =
  /[-–—•]|\barchives?\b|\bsecurity affairs\b|\bhuntress\b|\bcomparitech\b|\bdaily\b|\bcyber\b|\bnews\b/i;

// Words that typically follow a threat actor / victim brand name.
const ACTOR_TRIGGER_RE =
  /\b(?:leak|leaks|breach|breaches|data|ransomware|group|gang|attack|attacks|hack|hacked|hacker|exposes|exposed|stolen|steals|compromised|compromises|victim|victims|hit|hits|suffers|discloses|disclosed|infostealer|credentials?|accounts?|scraping|dump|dumps|profiles?)\b/i;

// Words that never start an actor/victim name, even when capitalised.
const LEADING_STOP = new Set([
  'what', 'how', 'the', 'why', 'when', 'where', 'inside', 'recent', 'recently',
  'massive', 'learn', 'phone', 'data', 'top', 'new', 'these', 'this',
  'credential', 'critical', 'huge', 'exclusive', 'dark', 'web', 'update',
]);

/** Pull a short headline out of a messy scraped blob. */
function extractHeadline(raw = '') {
  const text = String(raw || '').replace(/\s+/g, ' ').trim();
  const parts = text.split(/\s+—\s+/);
  let head = parts[0];
  if (parts.length >= 2 && SOURCE_MARKER_RE.test(head) && head.length < 60) {
    head = parts[1];
  }
  const dot = head.indexOf('. ');
  if (dot > 24) head = head.slice(0, dot);
  const words = head.trim().split(/\s+/);
  let out = '';
  for (const w of words) {
    if (out && out.length + w.length > 150) break;
    out += (out ? ' ' : '') + w;
  }
  return out.trim();
}

/** Find the actor / victim name to highlight in bold high-contrast text. */
function extractSubject(headline) {
  const trigger = headline.match(
    /\b([A-Z][A-Za-z0-9]+(?:\.[A-Za-z]{2,})?)\s+(?:leak|leaks|breach|breaches|data|ransomware|group|gang|attack|attacks|hack|hacked|exposes|exposed|stolen|compromised|victim|victims|hit|suffers|discloses|infostealer|credentials?|accounts?|scraping|dump|dumps)\b/i
  );
  if (trigger && !LEADING_STOP.has(trigger[1].toLowerCase())) return trigger[1];
  const colon = headline.indexOf(':');
  if (colon > 8 && colon < 90) return headline.slice(0, colon).trim();
  for (const w of headline.split(/\s+/)) {
    const clean = w.replace(/[^A-Za-z0-9.]/g, '');
    if (/^[A-Z][A-Za-z0-9]{2,}$/.test(clean) && !LEADING_STOP.has(clean.toLowerCase())) {
      return clean;
    }
  }
  return null;
}

const SOURCE_STYLES = {
  'DARKWEB-ONION': 'border-red-500/40 bg-red-500/10 text-red-300',
  TELEGRAM: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
};

export default function DarkWebCard({ feed }) {
  const [expanded, setExpanded] = useState(false);
  const [showIocs, setShowIocs] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyTimer, setCopyTimer] = useState(null);

  const headline = useMemo(() => extractHeadline(feed.raw_text), [feed.raw_text]);
  const subject = useMemo(() => extractSubject(headline), [headline]);
  const iocs = useMemo(() => extractIoCs(feed.raw_text), [feed.raw_text]);
  const sev = categorySeverity(feed.category);
  const isLong = (feed.raw_text || '').length > 240;

  const onCopyRaw = async () => {
    try {
      await navigator.clipboard.writeText(feed.raw_text || '');
    } catch {
      const ta = document.createElement('textarea');
      ta.value = feed.raw_text || '';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    clearTimeout(copyTimer);
    setCopyTimer(setTimeout(() => setCopied(false), 1500));
  };

  let subjectIdx = -1;
  if (subject) {
    subjectIdx = headline.indexOf(subject);
  }

  return (
    <article className="animate-fade-in flex flex-col rounded-xl border border-line bg-surface transition-colors hover:border-red-500/25">
      {/* Header: source · category · recency */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line/70 px-4 py-3">
        <span
          className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 font-mono text-[11px] font-bold tracking-wide ${
            SOURCE_STYLES[feed.source] || 'border border-line bg-raised text-dim'
          }`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
          {feed.source}
        </span>
        <Badge severity={sev}>{feed.category}</Badge>
        <span className="ml-auto shrink-0 font-mono text-[11px] text-faint">{timeAgo(feed.ts)}</span>
      </div>

      {/* Title with bold high-contrast actor/victim subject */}
      <div className="px-4 pt-3.5">
        <h2 className="text-sm leading-relaxed text-dim">
          {subjectIdx >= 0 ? (
            <>
              <span className="font-bold text-ink">{headline.slice(0, subjectIdx)}</span>
              <span className="font-bold text-cyan-200">{subject}</span>
              <span>{headline.slice(subjectIdx + subject.length)}</span>
            </>
          ) : (
            headline
          )}
        </h2>
      </div>

      {/* Body excerpt with expand/collapse */}
      <div className="px-4 pt-2.5">
        <p
          className={`whitespace-pre-line text-xs leading-relaxed text-dim ${expanded ? '' : 'line-clamp-3'}`}
        >
          {feed.raw_text}
        </p>
        {isLong && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="mt-2 inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-300 transition-colors hover:text-cyan-200"
          >
            <ShieldCheck size={12} />
            {expanded ? 'Hide Full Snippet' : 'Show Full Snippet'}
          </button>
        )}
      </div>

      {/* Extracted IoCs (revealed by the Extract IoCs action) */}
      {showIocs && (
        <div className="mt-3 px-4">
          {iocs.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {iocs.map((ioc) => (
                <span
                  key={`${ioc.type}-${ioc.value}`}
                  className="group inline-flex items-center gap-1.5 rounded border border-line bg-base px-2 py-1 font-mono text-[11px] text-cyan-300"
                >
                  <span className="text-[9px] uppercase tracking-wider text-faint">
                    {IOC_TYPE_LABELS[ioc.type] || ioc.type}
                  </span>
                  <span className="max-w-[200px] truncate">{ioc.value}</span>
                  <CopyButton value={ioc.value} />
                </span>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-faint">
              No hashes, wallets, IPs or other indicators matched in this snippet.
            </p>
          )}
        </div>
      )}

      {/* SOC actions */}
      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line/70 px-4 py-3">
        <Button
          size="sm"
          variant="secondary"
          icon={ScanSearch}
          onClick={() => setShowIocs((v) => !v)}
          title="Run the regex scanner for hashes, crypto wallets and IP addresses"
        >
          {showIocs ? 'Hide IoCs' : 'Extract IoCs'}
        </Button>
        <Button
          size="sm"
          variant="secondary"
          icon={Copy}
          onClick={onCopyRaw}
          title="Copy the full raw report to the clipboard"
        >
          {copied ? 'Copied' : 'Copy Raw Report'}
        </Button>

        {feed.url && (
          <a
            href={feed.url}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-[11px] text-faint transition-colors hover:text-cyan-300"
          >
            original <ExternalLink size={11} />
          </a>
        )}
      </div>
    </article>
  );
}
