import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ExternalLink, Sparkles } from 'lucide-react';

import Badge from '../ui/Badge';
import Button from '../ui/Button';
import CopyButton from '../ui/CopyButton';
import { api, errorText, unwrap } from '../../services/api';
import { categorySeverity, timeAgo } from '../../utils/format';
import { extractIoCs, IOC_TYPE_LABELS } from '../../utils/iocs';

/**
 * FeedCard — a single raw threat feed item: source tag, category + severity
 * badges, timestamp, extracted IoCs with one-click copy, and the
 * "Generate Alert Sheet" action. Generation is ASYNC: POST /api/v1/process
 * returns a job id immediately, then we poll the job until done/failed so the
 * HTTP request never times out while the local LLM works.
 */
export default function FeedCard({ feed }) {
  const navigate = useNavigate();
  const sev = categorySeverity(feed.category);
  const iocs = extractIoCs(feed.raw_text);
  const cve = iocs.find((i) => i.type === 'cve')?.value;
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => () => clearTimeout(pollRef.current), []);

  const onGenerate = async () => {
    setGenerating(true);
    setResult(null);
    setError(null);
    try {
      const { job_id } = await unwrap(api.processText(feed.raw_text, cve));
      const poll = async () => {
        try {
          const job = await unwrap(api.getProcessJob(job_id));
          if (job.status === 'done') {
            setResult(job.result);
            setGenerating(false);
          } else if (job.status === 'failed') {
            setError(job.error || 'Generation failed');
            setGenerating(false);
          } else {
            pollRef.current = setTimeout(poll, 3000);
          }
        } catch (e) {
          setError(errorText(e));
          setGenerating(false);
        }
      };
      poll();
    } catch (e) {
      setError(errorText(e));
      setGenerating(false);
    }
  };

  return (
    <article className="animate-fade-in rounded-xl border border-line bg-surface p-5 transition-colors hover:border-cyan-500/30">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[11px] font-bold tracking-wide text-cyan-300">
          {feed.source}
        </span>
        <Badge severity={sev}>{feed.category}</Badge>
        <span className="text-[11px] text-faint">{timeAgo(feed.ts)}</span>
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

      <p className="mt-3 line-clamp-4 text-sm leading-relaxed text-dim">{feed.raw_text}</p>

      {/* Extracted indicators */}
      {iocs.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {iocs.map((ioc) => (
            <span
              key={`${ioc.type}-${ioc.value}`}
              className="group inline-flex items-center gap-1.5 rounded border border-line bg-base px-2 py-1 font-mono text-[11px] text-cyan-300"
            >
              <span className="text-[9px] uppercase tracking-wider text-faint">{IOC_TYPE_LABELS[ioc.type]}</span>
              <span className="max-w-[220px] truncate">{ioc.value}</span>
              <CopyButton value={ioc.value} />
            </span>
          ))}
        </div>
      )}

      {/* Action + generation result */}
      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-line/70 pt-3">
        <Button
          size="sm"
          variant="primary"
          loading={generating}
          icon={Sparkles}
          onClick={onGenerate}
          disabled={!feed.raw_text || !cve || generating}
          title={!cve ? 'No CVE identifier in this item — an Alert Sheet requires a CVE' : 'Generate an Alert Sheet for this CVE'}
        >
          Generate Alert Sheet
        </Button>

        {feed.raw_text && !cve && (
          <span className="text-xs text-faint" title="Alert Sheets are generated per CVE; this item contains no CVE identifier">
            No CVE in this item
          </span>
        )}

        {generating && (
          <span className="text-xs text-cyan-300">
            Generating Alert Sheet… (local AI model, can take a minute)
          </span>
        )}

        {result?.generated && (
          <span className="text-xs text-emerald-400">
            Alert sheet generated for{' '}
            <button className="font-mono underline" onClick={() => navigate('/vulnerabilities')}>
              {result.cve}
            </button>
          </span>
        )}
        {result?.deduplicated && (
          <span className="text-xs text-amber-400">
            Already tracked · threat score bumped to {result.threat_score}
          </span>
        )}
        {result && result.generated === false && (
          <span className="text-xs text-dim">{result.reason || 'No CVE found in text'}</span>
        )}
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>
    </article>
  );
}
