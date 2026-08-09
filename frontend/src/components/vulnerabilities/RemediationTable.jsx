import React from 'react';
import { ShieldCheck, FileDown, Link as LinkIcon } from 'lucide-react';

/**
 * RemediationTable — the point-4 remediation matrix as a 2-column table:
 * Measure (patch / hardening / isolation / access restriction) | Details.
 */
export default function RemediationTable({ remediation = {} }) {
  const rows = [
    { measure: 'Patch / Upgrade', detail: remediation.patch, icon: FileDown },
    { measure: 'Hardening', detail: remediation.hardening, icon: ShieldCheck },
    { measure: 'Network Isolation', detail: remediation.isolation, icon: LinkIcon },
    { measure: 'Access Restriction', detail: remediation.access_restriction, icon: ShieldCheck },
  ];

  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line bg-raised/60">
            <th className="w-1/4 px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
              Measure
            </th>
            <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
              Details
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.measure} className="border-b border-line/60 align-top last:border-0">
              <td className="px-4 py-3 font-medium text-ink">{r.measure}</td>
              <td className="px-4 py-3 text-sm leading-relaxed text-dim">
                {r.detail || <span className="italic text-faint">Not specified in the advisory</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
