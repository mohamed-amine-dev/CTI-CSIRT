import React from 'react';
import { Boxes, Crosshair, FlaskConical, ShieldAlert } from 'lucide-react';

import Badge from '../ui/Badge';
import RemediationTable from './RemediationTable';
import { SEVERITY } from '../../utils/format';

/**
 * SectionBlock — a numbered section of the Alert Sheet template.
 * Renders a number + title + icon header with a consistent inner layout.
 */
export function SectionBlock({ num, title, icon: Icon, children }) {
  return (
    <section className="overflow-hidden rounded-xl border border-line bg-base/40">
      <header className="flex items-center gap-2.5 border-b border-line bg-raised/50 px-4 py-2.5">
        <span className="flex h-6 w-6 items-center justify-center rounded-md border border-cyan-500/40 bg-cyan-500/10 font-mono text-xs font-bold text-cyan-300">
          {num}
        </span>
        {Icon && <Icon size={15} className="text-cyan-400" />}
        <h4 className="text-sm font-semibold text-ink">{title}</h4>
      </header>
      <div className="space-y-3 px-4 py-4">{children}</div>
    </section>
  );
}

/** Bullet list shared by several sections. */
export function BulletList({ items = [] }) {
  if (!items.length) return <p className="text-sm italic text-faint">Not specified in the advisory</p>;
  return (
    <ul className="space-y-1.5">
      {items.map((it, i) => (
        <li key={i} className="flex items-start gap-2 text-sm leading-relaxed text-dim">
          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
          <span className="font-mono text-[13px]">{it}</span>
        </li>
      ))}
    </ul>
  );
}

/** Labeled paragraph used for prose fields (check_procedure, conditions, …). */
export function Field({ label, children }) {
  return (
    <div>
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-faint">{label}</p>
      <p className="text-sm leading-relaxed text-dim">
        {children || <span className="italic text-faint">Not specified in the advisory</span>}
      </p>
    </div>
  );
}

const ICONS = { 1: Boxes, 2: ShieldAlert, 3: FlaskConical, 4: Crosshair };

/**
 * AlertSheetView — renders the complete supervisor-required 4-point sheet:
 *   1. Environmental impact   (versions, check procedure, evidence)
 *   2. Risk & exploitation    (severity, exploit paths, compromise impact)
 *   3. Exploitability & PoC   (public PoC? conditions)
 *   4. Remediation matrix     (patch / hardening / isolation / access)
 * Plus a top summary table and the analyst summary. Reused by the list page
 * (in a modal) and the dedicated sheet route.
 */
export default function AlertSheetView({ sheet }) {
  const env = sheet.environmental_impact || {};
  const risk = sheet.risk_level || {};
  const explo = sheet.exploitation_status || {};
  const remed = sheet.remediation_solutions || {};
  const severity = SEVERITY[sheet.risk_level_label] || SEVERITY.INFO;

  const summaryRows = [
    ['CVE', sheet.vuln_cve],
    ['Risk level', sheet.risk_level_label],
    ['Threat score', String(sheet.threat_score)],
    ['Public PoC', explo.public_poc_available ? 'Yes' : 'No'],
    ['Last updated', new Date(sheet.ts).toLocaleString()],
  ];

  return (
    <div className="space-y-4">
      {/* Top summary table */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {summaryRows.map(([k, v]) => (
          <div key={k} className="rounded-lg border border-line bg-raised/50 px-3 py-2.5">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-faint">{k}</p>
            {k === 'Risk level' ? (
              <Badge severity={sheet.risk_level_label}>{v}</Badge>
            ) : (
              <p className="mt-0.5 truncate font-mono text-sm font-semibold" style={{ color: k === 'Public PoC' && v === 'Yes' ? '#f97316' : undefined }}>
                {v}
              </p>
            )}
          </div>
        ))}
      </div>

      {/* Analyst summary */}
      <div className="rounded-xl border border-line bg-raised/40 px-4 py-3">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-faint">Analyst Summary</p>
        <p className="text-sm leading-relaxed text-ink">{sheet.ai_summary}</p>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {/* Section 1 — Environmental impact */}
        <SectionBlock num={1} title="Environmental Impact" icon={ICONS[1]}>
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Affected versions / components</p>
            <BulletList items={env.affected_versions} />
          </div>
          <Field label="Check procedure">{env.check_procedure}</Field>
          <Field label="Evidence">{env.evidence}</Field>
        </SectionBlock>

        {/* Section 2 — Risk & exploitation */}
        <SectionBlock num={2} title="Risk & Exploitation" icon={ICONS[2]}>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: severity.hex }} />
            <span className="text-sm font-semibold" style={{ color: severity.hex }}>
              {sheet.risk_level_label}
            </span>
          </div>
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Exploit paths</p>
            <BulletList items={risk.exploit_paths} />
          </div>
          <Field label="Compromise impact (CIA)">{risk.compromise_impact}</Field>
        </SectionBlock>

        {/* Section 3 — Exploitability & PoC */}
        <SectionBlock num={3} title="Exploitability & PoC" icon={ICONS[3]}>
          <div className="flex flex-wrap items-center gap-3">
            <Badge severity={explo.public_poc_available ? 'HIGH' : 'LOW'}>
              {explo.public_poc_available ? 'Public PoC available' : 'No public PoC'}
            </Badge>
            {explo.poc_url && (
              <a
                href={explo.poc_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-cyan-300 underline"
              >
                {explo.poc_url} ↗
              </a>
            )}
          </div>
          <Field label="Exploitation conditions">{explo.conditions}</Field>
        </SectionBlock>

        {/* Section 4 — Remediation matrix */}
        <SectionBlock num={4} title="Remediation Matrix" icon={ICONS[4]}>
          <RemediationTable remediation={remed} />
        </SectionBlock>
      </div>
    </div>
  );
}
