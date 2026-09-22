// -----------------------------------------------------------------------------
// Full platform report -> printable PDF.
//   * exportFullReportPdf()  -> fetches every summary endpoint in parallel,
//     renders a self-contained printable HTML document and opens the browser
//     print dialog (Save as PDF). Zero extra dependencies — same pattern as the
//     per-sheet exportPdf (src/utils/export.js).
//
// Coverage: threat landscape (categories + severity), most frequent CVEs,
// top exposed ports, recent Alert Sheets and recent feed activity.
// -----------------------------------------------------------------------------

import { api, unwrap } from '../services/api';
import { formatDate, severityStyle, threatColor } from './format';

function esc(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Pull every summary needed by the report in one parallel batch. */
async function fetchReportData() {
  const [
    sources,
    alertStats,
    iocStats,
    landscape,
    ports,
    cves,
    alerts,
    feeds,
  ] = await Promise.all([
    unwrap(api.getFeedSources()),
    unwrap(api.getAlertStats()),
    unwrap(api.getIocStats()),
    unwrap(api.getThreatLandscape(90)),
    unwrap(api.getTopPorts(90)),
    unwrap(api.getTopCves(90)),
    unwrap(api.getAlerts({ limit: 10 })),
    unwrap(api.getFeeds({ limit: 10 })),
  ]);
  return { sources, alertStats, iocStats, landscape, ports, cves, alerts, feeds };
}

function summaryRow(kpis) {
  return kpis.map(([label, value]) => `
    <td class="kpi">
      <div class="kpi-value">${esc(String(value))}</div>
      <div class="kpi-label">${esc(label)}</div>
    </td>`).join('');
}

function riskChip(label) {
  const s = severityStyle(label);
  return `<span class="chip" style="color:${s.hex};border-color:${s.hex}55;background:${s.hex}14">${esc(label)}</span>`;
}

function buildReportHtml(d) {
  const now = new Date();
  const sourcesMap = d.sources?.sources || {};
  const totalItems = Object.values(sourcesMap).reduce((s, n) => s + n, 0);
  const byRisk = d.alertStats?.by_risk_level || {};
  const totalRisk = Object.values(byRisk).reduce((s, n) => s + n, 0);
  const totalIocs = Object.values(d.iocStats?.by_type || {}).reduce((s, n) => s + n, 0);
  const darkWebCount = (sourcesMap['DARKWEB-ONION'] || 0) + (sourcesMap.TELEGRAM || 0);
  const ranked = d.landscape?.ranked || [];
  const totalThreat = ranked.reduce((s, r) => s + r.count, 0);
  const ports = d.ports?.ports || [];
  const cves = d.cves?.cves || [];
  const alertItems = d.alerts?.items || [];
  const feedItems = d.feeds?.items || [];
  const topSources = Object.entries(sourcesMap).sort((a, b) => b[1] - a[1]).slice(0, 10);

  const pct = (n, t) => (t ? `${((n / t) * 100).toFixed(1)}%` : '—');

  const landscapeRows = ranked.map((r) => `
    <tr>
      <td><span class="dot" style="background:${threatColor(r.category)}"></span>${esc(r.category)}</td>
      <td class="num">${r.count.toLocaleString()}</td>
      <td class="num">${pct(r.count, totalThreat)}</td>
      <td class="bar"><div style="width:${pct(r.count, totalThreat)};background:${threatColor(r.category)}"></div></td>
    </tr>`).join('');

  const severityRows = Object.entries(byRisk)
    .sort((a, b) => (b[1] || 0) - (a[1] || 0))
    .map(([label, n]) => `
    <tr>
      <td>${riskChip(label)}</td>
      <td class="num">${n.toLocaleString()}</td>
      <td class="num">${pct(n, totalRisk)}</td>
    </tr>`).join('');

  const cveRows = cves.map((c) => `
    <tr>
      <td class="mono">${esc(c.cve)}</td>
      <td class="num">${c.count.toLocaleString()}</td>
      <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}">nvd.nist.gov/vuln/detail/${esc(c.cve)}</a></td>
    </tr>`).join('');

  const portRows = ports.map((p) => `
    <tr>
      <td class="mono">${p.port}</td>
      <td>${esc(p.service)}</td>
      <td class="num">${p.count.toLocaleString()}</td>
    </tr>`).join('');

  const alertRows = alertItems.map((a) => `
    <tr>
      <td class="mono">${esc(a.vuln_cve)}</td>
      <td>${riskChip(a.risk_level_label)}</td>
      <td class="num">${esc(String(a.threat_score ?? '—'))}</td>
      <td>${esc((a.ai_summary || '').slice(0, 160))}</td>
    </tr>`).join('');

  const feedRows = feedItems.map((f) => `
    <tr>
      <td>${esc(f.source)}</td>
      <td class="mono">${esc((f.title || (f.raw_text || '').slice(0, 90) || f.url || '—'))}</td>
      <td>${f.url ? `<a href="${esc(f.url)}">${esc(f.url.slice(0, 64))}</a>` : '—'}</td>
    </tr>`).join('');

  const sourceRows = topSources.map(([src, n]) => `
    <tr><td>${esc(src)}</td><td class="num">${n.toLocaleString()}</td></tr>`).join('');

  return `
  <h1>Argus CTI — Full Threat Intelligence Report</h1>
  <p class="meta">Generated ${esc(formatDate(now.toISOString(), { withSeconds: true }))} · 90-day window · live ClickHouse corpus</p>

  <h2>1. Executive Summary</h2>
  <table class="kpis">
    <tr>${summaryRow([
      ['Threat items ingested', totalItems],
      ['Critical CVEs', byRisk.CRITICAL || 0],
      ['Active indicators', totalIocs],
      ['Dark web / Telegram', darkWebCount],
    ])}</tr>
  </table>

  <h2>2. Threat &amp; Malware Category Landscape</h2>
  ${ranked.length ? `
  <table class="tbl">
    <tr><th>Category</th><th>Records</th><th>Share</th><th></th></tr>
    ${landscapeRows}
  </table>` : '<p class="muted">No threat-classified records in the window.</p>'}

  <h3>Severity distribution (Alert Sheets)</h3>
  ${severityRows ? `
  <table class="tbl">
    <tr><th>Risk level</th><th>Sheets</th><th>Share</th></tr>
    ${severityRows}
  </table>` : '<p class="muted">No alert sheets generated yet.</p>'}

  <h2>3. Most Frequent CVEs</h2>
  ${cveRows ? `
  <table class="tbl">
    <tr><th>CVE</th><th>Occurrences</th><th>Reference</th></tr>
    ${cveRows}
  </table>` : '<p class="muted">No CVEs observed in the window.</p>'}

  <h2>4. Top Exposed Ports</h2>
  ${portRows ? `
  <table class="tbl">
    <tr><th>Port</th><th>Service</th><th>Records</th></tr>
    ${portRows}
  </table>` : '<p class="muted">No Shodan InternetDB enrichment data.</p>'}

  <h2>5. Recent Alert Sheets</h2>
  ${alertRows ? `
  <table class="tbl">
    <tr><th>CVE</th><th>Risk</th><th>Score</th><th>Summary</th></tr>
    ${alertRows}
  </table>` : '<p class="muted">No sheets generated yet.</p>'}

  <h2>6. Recent Threat Feed Activity</h2>
  ${feedRows ? `
  <table class="tbl">
    <tr><th>Source</th><th>Item</th><th>Link</th></tr>
    ${feedRows}
  </table>` : '<p class="muted">No feed activity in the window.</p>'}

  <h3>Top sources (all time)</h3>
  ${sourceRows ? `
  <table class="tbl">
    <tr><th>Source</th><th>Records</th></tr>
    ${sourceRows}
  </table>` : '<p class="muted">No ingestion recorded.</p>'}

  <p class="footer">Generated automatically by the Argus CTI platform. Raw sources: CISA-KEV · CERT-FR · CERT-EU · NVD · URLhaus · ThreatFox · Shodan InternetDB · Dark Web (Tor) · News RSS.</p>`;
}

/**
 * Fetch the full platform summaries and open the browser print dialog
 * (Save as PDF). Rejects if any summary endpoint fails.
 */
export async function exportFullReportPdf() {
  const data = await fetchReportData();
  const win = window.open('', '_blank', 'width=980,height=760');
  if (!win) throw new Error('Popup blocked — allow popups to export the report.');
  win.document.write(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Argus CTI — Full Threat Intelligence Report</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;color:#0f172a;max-width:900px;margin:28px auto;padding:0 28px;line-height:1.5}
  h1{font-size:24px;border-bottom:3px solid #06b6d4;padding-bottom:10px;margin-bottom:4px}
  h2{font-size:16px;margin-top:30px;color:#155e75;border-left:4px solid #06b6d4;padding-left:10px}
  h3{font-size:13px;margin:18px 0 6px;color:#334155}
  p,li{font-size:12.5px;color:#1e293b}
  .meta{color:#64748b;font-size:12px;margin:0}
  .muted{color:#94a3b8;font-style:italic}
  .num{text-align:right;font-variant-numeric:tabular-nums}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
  table{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0}
  th,td{border:1px solid #cbd5e1;padding:6px 9px;vertical-align:top;text-align:left}
  th{background:#f1f5f9}
  a{color:#0369a1;word-break:break-all}
  .kpis{width:100%}
  .kpis td.kpi{border:1px solid #cbd5e1;padding:10px;text-align:center;background:#f8fafc}
  .kpi-value{font-size:22px;font-weight:700;color:#0f172a}
  .kpi-label{font-size:11px;color:#64748b;margin-top:2px}
  .chip{display:inline-block;border:1px solid;border-radius:999px;padding:1px 8px;font-size:11px;font-weight:600;white-space:nowrap}
  .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle}
  .bar{width:140px}
  .bar div{height:9px;border-radius:4px;min-width:2px}
  .footer{margin-top:34px;padding-top:10px;border-top:1px solid #cbd5e1;color:#94a3b8;font-size:11px}
  section{page-break-inside:avoid}
  @media print{body{margin:12mm auto}}
</style></head><body>${buildReportHtml(data)}</body></html>`);
  win.document.close();
  win.focus();
  await new Promise((r) => setTimeout(r, 400));
  win.print();
}
