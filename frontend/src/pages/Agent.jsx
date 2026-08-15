import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronUp,
  FlaskConical,
  ListChecks,
  ShieldCheck,
  Target,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { timeAgo } from '../utils/format';

const TYPES = ['IPv4', 'Domain', 'Hash', 'CVE'];

const EXAMPLE_CTX =
  'Honeypot logs: repeated SSH dictionary brute-force attempts from this IP.';

function riskTone(score) {
  if (score >= 70) return 'bg-red-500/10 text-red-400 border-red-500/40';
  if (score >= 40) return 'bg-amber-500/10 text-amber-300 border-amber-500/40';
  return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/40';
}

function JsonBlock({ value }) {
  if (value === undefined || value === null || value === '') return <span className="text-faint">—</span>;
  return (
    <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-base p-2.5 font-mono text-[11px] leading-relaxed text-cyan-200/90">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function TraceTimeline({ trace }) {
  if (!trace || trace.length === 0) {
    return <p className="text-xs text-faint">No trace recorded.</p>;
  }
  return (
    <ol className="relative space-y-3 border-l border-line pl-4">
      {trace.map((step, i) => (
        <li key={i} className="relative">
          <span className="absolute -left-[21px] top-1 h-3 w-3 rounded-full border-2 border-cyan-400/60 bg-base" />
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-cyan-300">{step.node}</span>
            {step.action && (
              <span className="rounded bg-raised px-1.5 py-0.5 font-mono text-[10px] text-dim">
                {step.action}
              </span>
            )}
            {step.note && <span className="text-[11px] text-faint">{step.note}</span>}
            <span className="ml-auto font-mono text-[10px] text-faint">
              {new Date(Math.floor(step.ts / 1000)).toLocaleTimeString()}
            </span>
          </div>
          <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
            {step.inputs && (
              <div>
                <p className="mb-0.5 text-[10px] uppercase tracking-wider text-faint">inputs</p>
                <JsonBlock value={step.inputs} />
              </div>
            )}
            {step.outputs && (
              <div>
                <p className="mb-0.5 text-[10px] uppercase tracking-wider text-faint">outputs</p>
                <JsonBlock value={step.outputs} />
              </div>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

function ResultPanel({ result, loading }) {
  if (loading) {
    return (
      <div className="flex h-full min-h-64 flex-col items-center justify-center gap-3 text-dim">
        <div className="flex items-center gap-2 text-sm">
          <Bot size={18} className="animate-pulse text-cyan-400" />
          Agent is triaging…
        </div>
        <p className="max-w-sm text-center text-xs text-faint">
          The local LLM is shared with the Alert Sheet scheduler, so this can take a
          minute or two. The sensor node scans the input for prompt injection first.
        </p>
      </div>
    );
  }
  if (!result) {
    return (
      <div className="flex h-full min-h-64 items-center justify-center">
        <EmptyState
          icon={Bot}
          title="No triage run yet"
          message="Fill in an indicator and the raw snippet it appeared in, then run the agent. Every step is shown in the execution trace."
        />
      </div>
    );
  }

  const flagged = result.is_flagged_unsafe;
  return (
    <div className="space-y-4">
      {/* Verdict banner */}
      {flagged ? (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3">
          <AlertTriangle size={18} className="mt-0.5 shrink-0 text-red-400" />
          <div>
            <p className="text-sm font-semibold text-red-300">
              Input quarantined before any tool or LLM ran
            </p>
            <p className="mt-0.5 font-mono text-xs text-red-300/80">
              {(result.quarantine_reasons || []).join(' · ') || 'detected signal'}
            </p>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-raised/50 px-4 py-3">
          <div className="flex items-center gap-2">
            <Target size={16} className="text-cyan-400" />
            <span className="font-mono text-sm text-ink">{result.indicator}</span>
            <Badge tone="neutral">{result.type}</Badge>
          </div>
          <span className="ml-auto text-[11px] uppercase tracking-wider text-faint">
            risk score
          </span>
          <span
            className={`rounded-lg border px-3 py-1 font-mono text-lg font-bold ${riskTone(result.risk_score)}`}
          >
            {result.risk_score}/100
          </span>
        </div>
      )}

      {/* Analysis + actions */}
      <Card title="Synthesis" icon={FlaskConical} padded={false}>
        <div className="space-y-3 p-4">
          {result.analysis ? (
            <p className="text-sm leading-relaxed text-dim">{result.analysis}</p>
          ) : (
            <p className="text-xs text-faint">
              No LLM synthesis — the agent kept the deterministic evidence-based score.
            </p>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                <ListChecks size={12} /> Key findings
              </p>
              {result.key_findings?.length ? (
                <ul className="space-y-1 text-xs text-dim">
                  {result.key_findings.map((f, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-cyan-400">›</span>
                      {f}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-faint">—</p>
              )}
            </div>
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
                <Activity size={12} /> Recommended actions
              </p>
              {result.recommended_actions?.length ? (
                <ul className="space-y-1 text-xs text-dim">
                  {result.recommended_actions.map((a, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-cyan-400">›</span>
                      {a}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-faint">—</p>
              )}
            </div>
          </div>
        </div>
      </Card>

      {/* Execution trace */}
      <Card
        title="Execution trace"
        icon={ShieldCheck}
        subtitle={`${result.execution_trace?.length || 0} step(s) · every decision recorded`}
        padded={false}
      >
        <div className="p-4">
          <TraceTimeline trace={result.execution_trace} />
        </div>
      </Card>
    </div>
  );
}

function HistoryRow({ run }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className="border-t border-line/60 text-left text-xs">
        <td className="px-3 py-2 font-mono text-cyan-300">{run.indicator}</td>
        <td className="px-3 py-2 text-dim">{run.type}</td>
        <td className="px-3 py-2">
          <span className={`font-mono font-bold ${run.risk_score >= 40 ? 'text-amber-300' : 'text-cyan-300'}`}>
            {run.risk_score}
          </span>
        </td>
        <td className="px-3 py-2">
          {run.is_flagged_unsafe ? (
            <span className="rounded bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold text-red-400">
              QUARANTINED
            </span>
          ) : (
            <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
              OK
            </span>
          )}
        </td>
        <td className="px-3 py-2 font-mono text-[11px] text-faint">{timeAgo(run.created_at)}</td>
        <td className="px-3 py-2 text-right">
          <button
            onClick={() => setOpen((v) => !v)}
            className="inline-flex items-center gap-1 text-[11px] text-dim transition-colors hover:text-cyan-300"
          >
            {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            {open ? 'Hide trace' : 'Trace'}
          </button>
        </td>
      </tr>
      {open && (
        <tr className="border-t border-line/40">
          <td colSpan={6} className="px-3 py-3">
            <TraceTimeline trace={run.execution_trace} />
          </td>
        </tr>
      )}
    </>
  );
}

export default function Agent() {
  const [indicator, setIndicator] = useState('');
  const [type, setType] = useState('IPv4');
  const [context, setContext] = useState('');
  const [formError, setFormError] = useState(null);

  const history = useApi(() => unwrap(api.getAgentHistory(15)), { deps: [], refreshMs: 30_000 });
  const triage = useAsync((payload) => unwrap(api.agentTriage(payload)));

  const onRun = async (e) => {
    e.preventDefault();
    setFormError(null);
    const ind = indicator.trim();
    const ctx = context.trim();
    if (!ind) return setFormError('An indicator is required.');
    if (!ctx) return setFormError("'context' is required — the agent needs the raw snippet it appeared in.");
    try {
      await triage.run({ indicator: ind, type, context: ctx });
      history.reload();
    } catch (err) {
      setFormError(errorText(err));
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <Bot size={20} className="text-cyan-400" /> Autonomous Triage Agent
        </h1>
        <p className="text-xs text-dim">
          One-shot investigator: sensor first, read-only tools, strict Alert Sheet — every
          step audited in the execution trace.
        </p>
      </div>

      <div className="grid gap-5 xl:grid-cols-5">
        <section className="xl:col-span-2">
          <Card title="Run a triage" icon={Target} padded={false}>
            <form onSubmit={onRun} className="space-y-3.5 p-4">
              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">
                  Indicator
                </label>
                <input
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  placeholder="104.210.140.133"
                  className="focus-neon w-full rounded-lg border border-line bg-surface px-3 py-2 font-mono text-sm text-ink placeholder:text-faint"
                />
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">
                  Type
                </label>
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className="focus-neon w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink"
                >
                  {TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-faint">
                  Raw context (required)
                </label>
                <textarea
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                  rows={4}
                  placeholder={EXAMPLE_CTX}
                  className="focus-neon w-full resize-y rounded-lg border border-line bg-surface px-3 py-2 font-mono text-xs text-ink placeholder:text-faint"
                />
                <p className="mt-1 text-[10px] leading-relaxed text-faint">
                  The sensor node sanitises this and scans for prompt injection before any
                  tool or LLM runs.
                </p>
              </div>

              {formError && <p className="text-xs text-red-400">{formError}</p>}

              <Button
                type="submit"
                variant="primary"
                loading={triage.loading}
                icon={ShieldCheck}
                className="w-full"
              >
                {triage.loading ? 'Triaging…' : 'Run autonomous triage'}
              </Button>
            </form>
          </Card>
        </section>

        <section className="xl:col-span-3">
          <Card
            title="Triage result"
            icon={FlaskConical}
            subtitle="risk · synthesis · execution trace"
            padded={false}
          >
            <div className="p-4">
              {triage.error ? (
                <ErrorState
                  title="Triage failed"
                  message={errorText(triage.error)}
                  onRetry={() => setFormError(null)}
                />
              ) : (
                <ResultPanel result={triage.data} loading={triage.loading} />
              )}
            </div>
          </Card>
        </section>
      </div>

      <Card
        title="Recent triage runs"
        icon={ListChecks}
        subtitle="audit trail · agent_triage_results · newest first"
        padded={false}
      >
        {history.loading && !history.data ? (
          <p className="p-4 text-xs text-faint">Loading history…</p>
        ) : history.error ? (
          <p className="p-4 text-xs text-red-400">
            Could not load history: {errorText(history.error)}
          </p>
        ) : !history.data?.items?.length ? (
          <p className="p-4 text-xs text-faint">No runs yet — run your first triage above.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-line text-left text-[10px] uppercase tracking-wider text-faint">
                <th className="px-3 py-2">Indicator</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">Verdict</th>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2 text-right">Trace</th>
              </tr>
            </thead>
            <tbody>
              {history.data.items.map((run, i) => (
                <HistoryRow key={i} run={run} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
