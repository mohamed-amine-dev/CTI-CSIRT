// -----------------------------------------------------------------------------
// Export helpers for Fiches d'Alerte.
//   * exportPdf(fiche)   -> opens a clean printable window and triggers print
//   * exportStix21(fiche)-> downloads a STIX 2.1 "vulnerability" SDO bundle
// -----------------------------------------------------------------------------

function downloadFile(name, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function esc(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function listHtml(items = []) {
  if (!items.length) return '<p class="muted">Not specified in the advisory</p>';
  return `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`;
}

/** Build a self-contained printable HTML document from a fiche. */
function ficheHtml(fiche) {
  const env = fiche.environmental_impact || {};
  const risk = fiche.risk_level || {};
  const explo = fiche.exploitation_status || {};
  const remed = fiche.remediation_solutions || {};

  return `
  <h1>Fiche d'Alerte — ${esc(fiche.vuln_cve)}</h1>
  <table class="summary">
    <tr><td>CVE</td><td><b>${esc(fiche.vuln_cve)}</b></td>
        <td>Risk level</td><td><b>${esc(fiche.risk_level_label)}</b></td>
        <td>Threat score</td><td><b>${esc(String(fiche.threat_score))}</b></td></tr>
    <tr><td>Public PoC</td><td><b>${explo.public_poc_available ? 'Yes' : 'No'}</b></td>
        <td>Updated</td><td>${esc(new Date(fiche.ts).toLocaleString())}</td>
        <td>PoC URL</td><td>${esc(explo.poc_url || '—')}</td></tr>
  </table>

  <h2>Analyst summary</h2><p>${esc(fiche.ai_summary)}</p>

  <h2>1. Environmental Impact</h2>
  <h3>Affected versions / components</h3>${listHtml(env.affected_versions)}
  <h3>Check procedure</h3><p>${esc(env.check_procedure)}</p>
  <h3>Evidence</h3><p>${esc(env.evidence)}</p>

  <h2>2. Risk & Exploitation</h2>
  <h3>Exploit paths</h3>${listHtml(risk.exploit_paths)}
  <h3>Compromise impact (CIA)</h3><p>${esc(risk.compromise_impact)}</p>

  <h2>3. Exploitability & PoC</h2>
  <p><b>Public PoC:</b> ${explo.public_poc_available ? 'Available' : 'Not available'}</p>
  <h3>Exploitation conditions</h3><p>${esc(explo.conditions)}</p>

  <h2>4. Remediation Matrix</h2>
  <table class="matrix">
    <tr><th>Measure</th><th>Details</th></tr>
    <tr><td>Patch / Upgrade</td><td>${esc(remed.patch)}</td></tr>
    <tr><td>Hardening</td><td>${esc(remed.hardening)}</td></tr>
    <tr><td>Network isolation</td><td>${esc(remed.isolation)}</td></tr>
    <tr><td>Access restriction</td><td>${esc(remed.access_restriction)}</td></tr>
  </table>`;
}

/** Open a clean print window for the fiche (saves as PDF via the browser). */
export function exportPdf(fiche) {
  const win = window.open('', '_blank', 'width=920,height=720');
  if (!win) return; // popup blocked
  win.document.write(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>${esc(fiche.vuln_cve)} — Fiche d'Alerte</title>
<style>
  body{font-family:system-ui,sans-serif;color:#0f172a;max-width:820px;margin:32px auto;padding:0 24px;line-height:1.5}
  h1{font-size:22px;border-bottom:3px solid #22d3ee;padding-bottom:8px}
  h2{font-size:15px;margin-top:26px;color:#155e75;border-left:4px solid #22d3ee;padding-left:8px}
  h3{font-size:13px;margin:14px 0 4px;color:#334155}
  p,li{font-size:13px;color:#1e293b}
  ul{margin:6px 0;padding-left:18px}
  .summary{border-collapse:collapse;width:100%;font-size:12px;margin:14px 0}
  .summary td{border:1px solid #cbd5e1;padding:6px 8px}
  .matrix{border-collapse:collapse;width:100%;font-size:12px}
  .matrix th{background:#f1f5f9;text-align:left}
  .matrix th,.matrix td{border:1px solid #cbd5e1;padding:8px;vertical-align:top}
  .muted{color:#94a3b8;font-style:italic}
  @media print{body{margin:12mm auto}}
</style></head><body>${ficheHtml(fiche)}</body></html>`);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 350);
}

/** Download a STIX 2.1 bundle describing the fiche's vulnerability. */
export function exportStix21(fiche) {
  const now = new Date().toISOString();
  const vulnId = `vulnerability--${crypto.randomUUID()}`;
  const objects = [
    {
      type: 'vulnerability',
      spec_version: '2.1',
      id: vulnId,
      created: now,
      modified: now,
      name: fiche.vuln_cve,
      description: fiche.ai_summary,
      external_references: [
        { source_name: 'cve', external_id: fiche.vuln_cve, url: `https://nvd.nist.gov/vuln/detail/${fiche.vuln_cve}` },
      ],
    },
  ];
  if (fiche.exploitation_status?.poc_url) {
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${crypto.randomUUID()}`,
      created: now,
      modified: now,
      relationship_type: 'related-to',
      source_ref: vulnId,
      target_ref: 'indicator--unknown',
      description: `Public PoC: ${fiche.exploitation_status.poc_url}`,
    });
  }
  const bundle = {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    objects,
  };
  downloadFile(`${fiche.vuln_cve}-stix21.json`, JSON.stringify(bundle, null, 2), 'application/json');
}
