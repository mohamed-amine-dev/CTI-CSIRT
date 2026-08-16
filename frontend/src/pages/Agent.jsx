import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Code2,
  Eye,
  FileText,
  FlaskConical,
  ListChecks,
  ShieldCheck,
  Target,
  XCircle,
} from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import CopyButton from '../components/ui/CopyButton';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';
import { severityFromScore, timeAgo } from '../utils/format';

const TYPES = ['IPv4', 'Domain', 'Hash', 'CVE'];

const EXAMPLE_CTX =
  'Honeypot logs: repeated SSH dictionary brute-force attempts from this IP.';

function riskTone(score) {
  if (score >= 70) return 'bg-red-500/10 text-red-400 border-red-500/40';
  if (score >= 40) return 'bg-amber-500/10 text-amber-300 border-amber-500/40';
  return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/40';
}

// -----------------------------------------------------------------------------
// Execution-trace rendering.
// Two views of the same audit trail:
//   * CleanTimeline — vertical stepper with per-node human-readable verdict
//     badges (the default; the SOC view).
//   * RawTrace     — the original per-step JSON, for auditors (opt-in).
// -----------------------------------------------------------------------------

function stepTime(ts) {
  return new Date(Math.floor(ts / 1000)).toLocaleTimeString();
}

/** Small coloured pill (verdict / count / finding). */
function Chip({ children, className = '' }) {
  return (
    <span
      className={`inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] ${className}`}
    >
      {children}
    </span>
  );
}

const CHIP_NEUTRAL = 'border-line bg-raised text-dim';
const CHIP_CYAN = 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300';
const CHIP_EMERALD = 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
const CHIP_AMBER = 'border-amber-500/40 bg-amber-500/10 text-amber-300';
const CHIP_RED = 'border-red-500/40 bg-red-500/10 text-red-400';
const CHIP_RED_SOFT = 'border-red-500/30 bg-red-500/5 text-red-300/80';

function FindingsPills({ label, items, tone }) {
  if (!items || !items.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-wider text-faint">{label}</span>
      {items.map((v, i) => (
        <Chip key={i} className={tone}>
          {String(v)}
        </Chip>
      ))}
    </div>
  );
}

const TOOL_LABELS = {
  shodan_internetdb: 'Shodan InternetDB',
  clickhouse_knowledge: 'Corpus search',
};

function ToolFindings({ name, data }) {
  if (name === 'shodan_internetdb') {
    if (!data.found) {
      return (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-semibold text-cyan-300">Shodan InternetDB</span>
          <Chip className={CHIP_NEUTRAL}>no record</Chip>
          {data.detail && <span className="text-[11px] text-faint">{data.detail}</span>}
        </div>
      );
    }
    return (
      <div className="space-y-1.5">
        <span className="text-[11px] font-semibold text-cyan-300">Shodan InternetDB</span>
        <FindingsPills label="open ports" items={data.ports} tone={CHIP_CYAN} />
        <FindingsPills label="CVEs" items={data.cves} tone={CHIP_RED} />
        <FindingsPills label="hostnames" items={data.hostnames} tone={CHIP_NEUTRAL} />
        <FindingsPills label="tags" items={data.tags} tone={CHIP_NEUTRAL} />
        <FindingsPills label="CPEs" items={data.cpes} tone={CHIP_NEUTRAL} />
      </div>
    );
  }

  if (name === 'clickhouse_knowledge') {
    const p = data.processed || {};
    const rm = data.raw_matches || {};
    const sev = p.max_severity != null ? severityFromScore(p.max_severity) : null;
    return (
      <div className="space-y-1.5">
        <span className="text-[11px] font-semibold text-cyan-300">Corpus search</span>
        <div className="flex flex-wrap items-center gap-1.5">
          {p.found ? (
            <Chip className={CHIP_AMBER}>seen before · {p.sightings}×</Chip>
          ) : (
            <Chip className={CHIP_NEUTRAL}>no prior sightings</Chip>
          )}
          {sev && <Chip className={sev.badge}>{sev.label}</Chip>}
          {p.last_seen && <span className="text-[11px] text-faint">last {timeAgo(p.last_seen)}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {rm.found ? (
            <Chip className={CHIP_CYAN}>
              {rm.records} raw mention{rm.records !== 1 ? 's' : ''} · {rm.sources} source{rm.sources !== 1 ? 's' : ''} · {rm.window_days}d window
            </Chip>
          ) : (
            <Chip className={CHIP_NEUTRAL}>no raw mentions</Chip>
          )}
        </div>
      </div>
    );
  }

  return null;
}

/** Human-readable verdict badges for one trace step. */
function StepSummary({ step }) {
  const node = step.node;
  const out = step.outputs || {};
  const inp = step.inputs || {};

  if (node === 'sensor_sanitizer') {
    if (out.risky) {
      return (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Chip className={`${CHIP_RED} font-semibold`}>
            <AlertTriangle size={11} /> Prompt injection detected
          </Chip>
          {(out.reasons || []).map((r) => (
            <Chip key={r} className={CHIP_RED_SOFT}>
              {r}
            </Chip>
          ))}
        </div>
      );
    }
    return (
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Chip className={`${CHIP_EMERALD} font-semibold`}>
          <CheckCircle2 size={11} /> Input clean
        </Chip>
        <Chip className={CHIP_NEUTRAL}>{out.chars_out ?? inp.chars_in} chars</Chip>
        {step.note && <span className="text-[11px] text-faint">{step.note}</span>}
      </div>
    );
  }

  if (node === 'triage_evaluator') {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-faint">baseline risk</span>
        <Chip className={CHIP_CYAN}>{out.baseline_risk ?? '—'}/100</Chip>
        <span className="text-[10px] uppercase tracking-wider text-faint">tool plan</span>
        {(out.tool_plan || []).map((t) => (
          <Chip key={t} className={CHIP_NEUTRAL}>
            {t}
          </Chip>
        ))}
        {step.note && <span className="text-[11px] text-faint">{step.note}</span>}
      </div>
    );
  }

  if (node === 'tools_execution') {
    const tools = Object.entries(out).filter(([, v]) => v && typeof v === 'object');
    if (!tools.length) return <div className="mt-2 text-[11px] text-faint">{step.note}</div>;
    return (
      <div className="mt-2 space-y-2">
        {tools.map(([n, t]) => (
          <ToolFindings key={n} name={n} data={t} />
        ))}
      </div>
    );
  }

  if (node === 'synthesis') {
    if (out.fallback) {
      return (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Chip className={`${CHIP_AMBER} font-semibold`}>
            <AlertTriangle size={11} /> LLM unavailable
          </Chip>
          <Chip className={CHIP_NEUTRAL}>deterministic baseline kept</Chip>
        </div>
      );
    }
    return (
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Chip className={`${CHIP_CYAN} font-semibold`}>
          <FlaskConical size={11} /> Synthesis complete
        </Chip>
        <Chip className={CHIP_NEUTRAL}>{inp.engine}</Chip>
        <Chip className={CHIP_CYAN}>risk {out.risk_score}/100</Chip>
      </div>
    );
  }

  if (node === 'sheet_generator') {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {out.sheet ? (
          <Chip className={`${CHIP_EMERALD} font-semibold`}>
            <FileText size={11} /> Alert sheet generated
          </Chip>
        ) : (
          <Chip className={CHIP_NEUTRAL}>No sheet produced</Chip>
        )}
        {step.note && <span className="text-[11px] text-faint">{step.note}</span>}
      </div>
    );
  }

  if (node === 'quarantine') {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Chip className={`${CHIP_RED} font-semibold`}>
          <XCircle size={11} /> Quarantined
        </Chip>
        {(out.reasons || []).map((r) => (
          <Chip key={r} className={CHIP_RED_SOFT}>
            {r}
          </Chip>
        ))}
      </div>
    );
  }

  return null;
}

/** Colour of the stepper node dot for a given step. */
function dotTone(step) {
  const risky = (step.outputs || {}).risky;
  if (step.node === 'quarantine' || (step.node === 'sensor_sanitizer' && risky)) {
    return 'border-red-500/60 bg-red-500/10 text-red-400';
  }
  if (step.node === 'sheet_generator') return 'border-emerald-500/60 bg-emerald-500/10 text-emerald-400';
  return 'border-cyan-500/60 bg-cyan-500/10 text-cyan-300';
}

function CleanTimeline({ trace }) {
  return (
    <ol className="relative space-y-4">
      {trace.map((step, i) => (
        <li key={i} className="flex gap-3">
          <div className="flex flex-col items-center">
            <span
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 font-mono text-[11px] font-bold ${dotTone(step)}`}
            >
              {i + 1}
            </span>
            {i < trace.length - 1 && <span className="mt-1 w-px flex-1 bg-line" aria-hidden="true" />}
          </div>
          <div className="min-w-0 flex-1 pb-4">
            <div className="rounded-lg border border-line bg-raised/40 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold text-ink">{step.node}</span>
                {step.action && (
                  <span className="rounded bg-base px-1.5 py-0.5 font-mono text-[10px] text-dim">
                    {step.action}
                  </span>
                )}
                <span className="ml-auto font-mono text-[10px] text-faint">{stepTime(step.ts)}</span>
              </div>
              <StepSummary step={step} />
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

function RawTrace({ trace }) {
  return (
    <div className="space-y-2.5">
      {trace.map((step, i) => (
        <div key={i} className="rounded-lg border border-line bg-base/60">
          <div className="flex items-center justify-between border-b border-line/60 px-3 py-1.5">
            <span className="font-mono text-[11px] font-bold text-cyan-300">
              {i + 1}. {step.node}
            </span>
            <CopyButton value={JSON.stringify(step, null, 2)} label="Copy step JSON" />
          </div>
          <pre className="max-h-72 overflow-auto p-3 font-mono text-[11px] leading-relaxed text-cyan-200/90">
            {JSON.stringify(step, null, 2)}
          </pre>
        </div>
      ))}
    </div>
  );
}

/** Trace with a "clean timeline / raw JSON" toggle. Clean is the default. */
function TraceView({ trace }) {
  const [raw, setRaw] = useState(false);
  if (!trace || trace.length === 0) {
    return <p className="text-xs text-faint">No trace recorded.</p>;
  }
  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <span className="mr-auto text-[10px] uppercase tracking-wider text-faint">
          {trace.length} step{trace.length !== 1 ? 's' : ''}
        </span>
        <button
          onClick={() => setRaw((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-raised px-2.5 py-1.5 text-[11px] font-semibold text-dim transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
        >
          {raw ? <Eye size={13} /> : <Code2 size={13} />}
          {raw ? 'View clean timeline' : 'View raw trace'}
        </button>
      </div>
      {raw ? <RawTrace trace={trace} /> : <CleanTimeline trace={trace} />}
    </div>
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
          <TraceView trace={result.execution_trace} />
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
            <TraceView trace={run.execution_trace} />
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
