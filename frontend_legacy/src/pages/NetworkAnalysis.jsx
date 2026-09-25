import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Link } from 'react-router-dom';
import {
  Activity,
  Archive,
  Copy,
  Download,
  FileSearch,
  Globe,
  Network,
  Play,
  Pause,
  Radar,
  Shield,
  Sparkles,
  UploadCloud,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import { api, errorText, unwrap } from '../services/api';
import { compactNumber, formatDate } from '../utils/format';

const PROTO_COLORS = { tcp: '#38bdf8', udp: '#a78bfa', icmp: '#34d399' };
const protoColor = (p) => PROTO_COLORS[p] || '#64748b';

const TOOLTIP_STYLE = {
  backgroundColor: 'rgb(22 27 42)',
  border: '1px solid rgb(37 46 68)',
  borderRadius: '8px',
  color: 'rgb(241 245 249)',
  fontSize: '12px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
  padding: '10px 12px',
};
const AXIS = { stroke: 'rgb(71 85 105)', fontSize: 11 };
const GRID_COLOR = 'rgb(37 46 68)';

const bytesLabel = (n) => {
  const v = Number(n) || 0;
  if (v >= 1e9) return `${(v / 1e9).toFixed(2)} GB`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)} MB`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} kB`;
  return `${v} B`;
};

const hms = (ms) => {
  const d = new Date(Number(ms) || 0);
  if (!d || Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString([], { hour12: false });
};

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={TOOLTIP_STYLE}>
      {label && <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-faint">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} className="flex items-center gap-2 text-[12px]">
          <span className="inline-block h-2 w-2 rounded-full flex-shrink-0" style={{ background: p.color || p.payload?.fill }} />
          <span className="text-dim">{p.name}:</span>
          <span className="ml-auto font-mono font-semibold text-ink">
            {p.name === 'Bytes' ? bytesLabel(p.value) : compactNumber(p.value)}
          </span>
        </p>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// d3-force connection graph (stage 2) — no graph library, just d3 which the
// bundle already carries.
// ---------------------------------------------------------------------------
const GRAPH_W = 940;
const GRAPH_H = 520;

function ConnGraph({ nodes, edges, flagged }) {
  const svgRef = useRef(null);
  const [tMin, setTMin] = useState(0);
  const [tMax, setTMax] = useState(0);
  const [tNow, setTNow] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [selected, setSelected] = useState(null);

  const allMs = useMemo(() => edges.flatMap((e) => [e.ts0, e.ts1]), [edges]);

  useEffect(() => {
    if (!allMs.length) return;
    const lo = Math.min(...allMs);
    const hi = Math.max(...allMs);
    setTMin(lo);
    setTMax(hi);
    setTNow(hi);
  }, [allMs]);

  useEffect(() => {
    if (!playing) return undefined;
    const step = Math.max(1, (tMax - tMin) / 120);
    const timer = setInterval(() => {
      setTNow((t) => {
        const next = t + step;
        if (next >= tMax) {
          setPlaying(false);
          return tMax;
        }
        return next;
      });
    }, 33);
    return () => clearInterval(timer);
  }, [playing, tMin, tMax]);

  const visibleEdges = useMemo(() => edges.filter((e) => e.ts0 <= tNow), [edges, tNow]);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    if (!nodes.length || !visibleEdges.length) {
      svg.append('text')
        .attr('x', GRAPH_W / 2).attr('y', GRAPH_H / 2 - 10)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b').attr('font-size', 12)
        .text('No connection edges to draw (try a capture with TCP/UDP traffic).');
      return undefined;
    }

    const byIp = new Map(nodes.map((n) => [n.id, n]));
    const links = visibleEdges
      .filter((e) => byIp.has(e.source) && byIp.has(e.target))
      .map((e, i) => ({ ...e, index: i }));

    const maxBytes = Math.max(1, ...links.map((l) => l.bytes || 0));
    const deg = new Map();
    for (const l of links) {
      deg.set(l.source, (deg.get(l.source) || 0) + 1);
      deg.set(l.target, (deg.get(l.target) || 0) + 1);
    }

    const g = svg.append('g');
    const linkSel = g.append('g').selectAll('line').data(links).join('line');
    const nodeSel = g.append('g').selectAll('g').data(nodes).join('g');

    linkSel
      .attr('stroke', '#334155')
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', (d) => 0.6 + 3 * (Math.log1p(d.bytes || 0) / Math.log1p(maxBytes)));

    nodeSel
      .attr('cursor', 'pointer')
      .append('circle')
      .attr('r', (d) => 6 + 2 * Math.min(4, deg.get(d.id) || 0))
      .attr('fill', (d) => (d.flagged ? '#ef4444' : d.internal ? '#475569' : '#a78bfa'))
      .attr('stroke', '#0f172a')
      .attr('stroke-width', (d) => (d.flagged ? 2 : 1))
      .on('click', (ev, d) => setSelected(d.id))
      .on('mouseover', function () { d3.select(this).attr('stroke', '#f8fafc'); })
      .on('mouseout', function () { d3.select(this).attr('stroke', '#0f172a'); });

    nodeSel
      .append('text')
      .attr('dy', 16)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', 9)
      .text((d) => (nodes.length < 80 ? d.id : d.internal ? d.id : ''));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(70).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-160))
      .force('center', d3.forceCenter(GRAPH_W / 2, GRAPH_H / 2))
      .force('collide', d3.forceCollide(14))
      .on('tick', () => {
        linkSel
          .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
          .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
        nodeSel.attr('transform', (d) => `translate(${d.x},${d.y})`);
      });

    const drag = d3.drag()
      .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; });
    nodeSel.call(drag);

    return () => sim.stop();
  }, [nodes, visibleEdges, tNow]);

  const sel = nodes.find((n) => n.id === selected);
  const flaggedUsed = useMemo(
    () => (flagged || []).filter((f) => f?.indicator),
    [flagged],
  );
  // Per-node threat intel: IP match on the node itself, domain/url match on
  // any of its zeek_dns/HTTP-Host hostnames (same rule the flags use).
  const selIpMatches = useMemo(
    () => (sel ? flaggedUsed.filter((f) => f.type === 'ipv4' || f.type === 'ipv6').filter((f) => f.indicator === sel.id) : []),
    [sel, flaggedUsed],
  );
  const selDomMatches = useMemo(
    () => (sel ? flaggedUsed.filter((f) => f.type === 'domain' || f.type === 'url').filter((f) => (sel.hostnames || []).includes(f.indicator)) : []),
    [sel, flaggedUsed],
  );
  const hostFlags = useMemo(() => new Set(selDomMatches.map((f) => f.indicator)), [selDomMatches]);
  const when = (iso) => (iso ? new Date(iso).toLocaleDateString() : '—');
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Button size="sm" icon={playing ? Pause : Play} onClick={() => setPlaying((p) => !p)}>
          {playing ? 'Pause' : 'Replay'}
        </Button>
        <span className="text-[11px] text-faint">Time</span>
        <input
          type="range"
          min={tMin - (tMax > tMin ? 1 : 0)}
          max={tMax}
          value={tNow}
          disabled={tMax <= tMin}
          onChange={(e) => setTNow(Number(e.target.value))}
          className="flex-1"
        />
        <span className="w-20 text-right font-mono text-[11px] text-dim">
          {tMax > tMin ? hms(tNow) : '—'}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-faint">
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-red-500" /> flagged IOC</span>
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-violet-400" /> external IP</span>
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-slate-500" /> internal/host IP</span>
        <span className="ml-auto">{visibleEdges.length} of {edges.length} edges</span>
      </div>
      <div className="mt-2 grid gap-4 lg:grid-cols-[1fr_290px]">
        <svg ref={svgRef} viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`} className="w-full rounded-lg border border-line bg-black/20" />
        <div className="rounded-lg border border-line bg-black/20 p-3 text-xs" data-testid="conn-inspector">
          {sel ? (
            <div className="space-y-3">
              <div>
                <p className="break-all font-mono text-[12px] font-semibold text-ink">{sel.id}</p>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <Badge tone={sel.internal ? 'amber' : 'blue'}>{sel.internal ? 'internal' : 'external'}</Badge>
                  <Badge tone={sel.flagged ? 'red' : 'green'}>{sel.flagged ? 'flagged IOC' : 'no corpus hit'}</Badge>
                </div>
              </div>

              {selIpMatches.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-faint">Threat intel · IP match</p>
                  {selIpMatches.map((f, i) => (
                    <div key={i} className="mt-1.5 rounded-md border border-red-500/25 bg-red-500/5 px-2 py-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-ink">{f.indicator}</span>
                        <Badge severity={f.severity >= 7 ? 'critical' : f.severity >= 4 ? 'high' : 'medium'}>
                          sev {f.severity.toFixed(1)}
                        </Badge>
                      </div>
                      <p className="mt-1 text-[10px] text-faint">first seen {when(f.ts)}</p>
                      {f.family && (
                        <p className="mt-1 text-[11px] text-dim">
                          family{' '}
                          {f.malware_id ? (
                            <Link to={`/malware/${f.malware_id}`} className="font-semibold text-primary hover:underline">
                              {f.family}
                            </Link>
                          ) : (
                            <span className="font-semibold text-ink">{f.family}</span>
                          )}
                        </p>
                      )}
                      {!!f.actors?.length && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {f.actors.map((a) => (
                            <Link
                              key={a}
                              to={`/actors?actor=${encodeURIComponent(a)}`}
                              className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 hover:underline"
                            >
                              {a}
                            </Link>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {selDomMatches.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-faint">Threat intel · Hostname match</p>
                  {selDomMatches.map((f, i) => (
                    <div key={i} className="mt-1.5 rounded-md border border-red-500/25 bg-red-500/5 px-2 py-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-ink">{f.indicator}</span>
                        <Badge severity={f.severity >= 7 ? 'critical' : f.severity >= 4 ? 'high' : 'medium'}>
                          sev {f.severity.toFixed(1)}
                        </Badge>
                      </div>
                      <p className="mt-1 text-[10px] text-faint">via DNS/HTTP hostname · first seen {when(f.ts)}</p>
                      {f.family && (
                        <p className="mt-1 text-[11px] text-dim">
                          family{' '}
                          {f.malware_id ? (
                            <Link to={`/malware/${f.malware_id}`} className="font-semibold text-primary hover:underline">
                              {f.family}
                            </Link>
                          ) : (
                            <span className="font-semibold text-ink">{f.family}</span>
                          )}
                        </p>
                      )}
                      {!!f.actors?.length && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {f.actors.map((a) => (
                            <Link
                              key={a}
                              to={`/actors?actor=${encodeURIComponent(a)}`}
                              className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 hover:underline"
                            >
                              {a}
                            </Link>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-faint">Hostnames</p>
                {!!sel.hostnames?.length ? (
                  <ul className="mt-1 space-y-1">
                    {sel.hostnames.slice(0, 10).map((h) => (
                      <li key={h} className="flex items-center gap-1.5 break-all leading-snug">
                        <span
                          className={`h-1.5 w-1.5 shrink-0 rounded-full ${hostFlags.has(h) ? 'bg-red-500' : 'bg-slate-500'}`}
                        />
                        <span className={hostFlags.has(h) ? 'font-semibold text-red-400' : 'text-dim'}>{h}</span>
                      </li>
                    ))}
                    {sel.hostnames.length > 10 && (
                      <li className="text-[10px] text-faint">+{sel.hostnames.length - 10} more</li>
                    )}
                  </ul>
                ) : (
                  <p className="mt-1 text-faint">no DNS / HTTP host resolved</p>
                )}
              </div>

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-faint">Geolocation</p>
                {sel.geo ? (
                  <p className="mt-1 text-dim">
                    {sel.geo.country_name} <span className="font-mono text-faint">({sel.geo.country_code})</span>
                  </p>
                ) : (
                  <p className="mt-1 text-faint">
                    {sel.internal ? 'private/reserved — never geolocated' : 'public IP · not resolved yet'}
                  </p>
                )}
              </div>

              <Link
                to={`/ioc-search?q=${encodeURIComponent(sel.id)}`}
                className="block text-[11px] font-semibold text-primary hover:underline"
              >
                Inspect in IoC Lookup →
              </Link>
            </div>
          ) : (
            <p className="text-faint">Select a node to inspect it.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function NetworkAnalysis() {
  const [status, setStatus] = useState(null);
  const [captures, setCaptures] = useState([]);
  const [captureId, setCaptureId] = useState(null);
  const [capture, setCapture] = useState(null);
  const [charts, setCharts] = useState(null);
  const [files, setFiles] = useState([]);
  const [graph, setGraph] = useState(null);
  const [summary, setSummary] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [fileName, setFileName] = useState('');
  const fileInputRef = useRef(null);

  const [extraIocs, setExtraIocs] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [drafts, setDrafts] = useState(null);
  const [genError, setGenError] = useState(null);

  useEffect(() => {
    api.getPcapStatus().then((r) => setStatus(r.data)).catch(() => setStatus(null));
    refreshList();
  }, []);

  const refreshList = useCallback(async () => {
    try {
      const res = await unwrap(api.listPcaps());
      setCaptures(res.captures);
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  const loadCapture = useCallback(async (id) => {
    setCaptureId(id);
    setCapture(null);
    setCharts(null);
    setGraph(null);
    setSummary(null);
    setDrafts(null);
    setError(null);
    try {
      const [detail, g] = await Promise.all([unwrap(api.getPcap(id)), unwrap(api.getPcapGraph(id))]);
      setCapture(detail.capture);
      setCharts(detail.charts);
      setFiles(detail.files || []);
      setGraph(g);
      const flagged = (g?.ioc?.flagged || []).map((f) => ({ type: f.type === 'domain' ? 'domain' : 'ipv4', value: f.indicator }));
      setExtraIocs(flagged.map((f) => ({ ...f })));
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  const pickFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileName(f.name);
    setCapture(null);
    setError(null);
  };

  const analyze = async () => {
    const f = fileInputRef.current?.files?.[0];
    if (!f) return;
    setAnalyzing(true);
    setProgress(0);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('file', f);
      const result = await unwrap(api.analyzePcap(fd, setProgress));
      await refreshList();
      await loadCapture(result.pcap_id);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setAnalyzing(false);
    }
  };

  const generateSummary = async () => {
    if (!captureId) return;
    setSummaryLoading(true);
    setError(null);
    try {
      const res = await unwrap(api.getPcapSummary(captureId));
      setSummary(res);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSummaryLoading(false);
    }
  };

  const generateRules = async () => {
    if (!captureId) return;
    setGenerating(true);
    setGenError(null);
    try {
      const iocs = extraIocs.filter((r) => r.value.trim());
      if (!iocs.length) throw new Error('Add at least one IOC.');
      const res = await unwrap(api.generatePcapRules(captureId, iocs));
      setDrafts(res);
    } catch (err) {
      setGenError(errorText(err));
    } finally {
      setGenerating(false);
    }
  };

  const setIoc = (idx, patch) => setExtraIocs((prev) => prev.map((row, i) => (i === idx ? { ...row, ...patch } : row)));
  const addIoc = () => setExtraIocs((prev) => [...prev, { type: 'ipv4', value: '' }]);
  const removeIoc = (idx) => setExtraIocs((prev) => prev.filter((_, i) => i !== idx));

  const protocolData = (charts?.protocol || []).map((p) => ({ name: p.proto || '?', value: p.bytes, n: p.n }));
  const timelineData = (charts?.timeline || []).map((t) => ({ ...t, label: t.bucket_ms ? hms(t.bucket_ms) : t.bucket }));
  const talkerData = (charts?.top_talkers || []).map((t) => ({
    name: `${t.src}→${t.dst}`,
    bytes: t.bytes,
    n: t.n,
  }));
  const maliciousFiles = files.filter((f) => f.verdict === 'malicious');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-ink">Network Analysis</h1>
        <p className="mt-0.5 text-sm text-dim">
          Upload a packet capture — it is quarantined (0700), fingerprinted (SHA-256) and replayed
          offline through <span className="font-mono text-xs">zeek -C -r</span>. Zeek's typed logs
          (conn / http / dns / files) are stored in ClickHouse and rendered as protocol &amp;
          bandwidth charts, a connection graph and IOC cross-references. The capture is never executed.
        </p>
      </div>

      {status && (
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge tone={status?.zeek?.present ? 'green' : 'red'}>
            zeek {status?.zeek?.present ? '8.x ✓' : 'missing ✗'}
          </Badge>
          <Badge tone="green">{bytesLabel(status?.max_upload_bytes)} max upload</Badge>
          <Badge tone={status?.extraction_enabled && status?.yara_present ? 'green' : 'amber'}>
            file extraction {status?.extraction_enabled ? 'on' : 'off'}{status?.yara_present ? ' · yara ✓' : ''}
          </Badge>
        </div>
      )}

      <Card title="1 · Upload a capture" icon={UploadCloud}>
        <div className="flex flex-wrap items-center gap-3">
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng"
            className="block w-full max-w-md text-xs text-dim file:mr-3 file:rounded-lg file:border-0 file:bg-raised file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-ink hover:file:bg-line"
            onChange={pickFile}
          />
          <Button variant="primary" icon={FileSearch} onClick={analyze} loading={analyzing}>
            {analyzing ? `Analysing… ${progress}%` : 'Analyse capture'}
          </Button>
        </div>
        {error && <p className="mt-3 text-xs text-red-400">{error}</p>}
      </Card>

      {capture && (
        <>
          {/* stage 1 — charts */}
          <Card
            title="2 · Capture analysis"
            icon={Activity}
            actions={<Badge tone={capture?.status === 'done' ? 'green' : 'red'}>{capture?.status?.toUpperCase()}</Badge>}
          >
            <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat label="Connections" value={compactNumber(capture?.counts?.conn)} sub={fileNameTimeout(capture)} />
              <Stat label="HTTP requests" value={compactNumber(capture?.counts?.http)} sub="zeek http.log" />
              <Stat label="DNS queries" value={compactNumber(capture?.counts?.dns)} sub="zeek dns.log" />
              <Stat label="Recovered payloads" value={compactNumber(capture?.counts?.extracted)} sub={`${capture?.counts?.malicious_files || 0} flagged`} />
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card title="Protocol bytes" className="lg:col-span-1" padded={false}>
                <div className="h-56 px-3 py-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={protocolData} dataKey="value" nameKey="name" innerRadius="52%" outerRadius="80%" paddingAngle={2}>
                        {protocolData.map((p) => <Cell key={p.name} fill={protoColor(p.name)} />)}
                      </Pie>
                      <Tooltip content={<ChartTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-2 border-t border-line px-4 py-3">
                  {protocolData.map((p) => (
                    <span key={p.name} className="flex items-center gap-1.5 text-[11px] text-dim">
                      <i className="h-2 w-2 rounded-full" style={{ background: protoColor(p.name) }} />
                      {p.name} · {bytesLabel(p.value)}
                    </span>
                  ))}
                </div>
              </Card>

              <Card title="Bandwidth over time" className="lg:col-span-2" padded={false}>
                <div className="h-64 px-3 py-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="band" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
                          <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke={GRID_COLOR} strokeDasharray="3 3" />
                      <XAxis dataKey="label" tick={AXIS} tickLine={false} />
                      <YAxis tick={AXIS} tickLine={false} tickFormatter={(v) => compactNumber(v)} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area type="monotone" dataKey="bytes" name="Bytes" stroke="#38bdf8" fill="url(#band)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <Card title="Top talkers (bytes)" padded={false}>
                <div className="h-64 px-3 py-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={talkerData} layout="vertical" margin={{ left: 20, right: 20 }}>
                      <CartesianGrid stroke={GRID_COLOR} strokeDasharray="3 3" />
                      <XAxis type="number" tick={AXIS} tickLine={false} tickFormatter={(v) => compactNumber(v)} />
                      <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false} width={135} />
                      <Tooltip content={<ChartTooltip />} />
                      <Bar dataKey="bytes" name="Bytes" fill="#a78bfa" radius={[0, 3, 3, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              <div className="space-y-4">
                {!!charts?.services?.length && (
                  <Card title="Services observed" padded={false}>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 p-4 text-xs">
                      {charts.services.map((s, i) => (
                        <span key={i} className="flex items-center justify-between">
                          <span className="text-dim">{s.service || '?'}</span>
                          <span className="font-mono text-ink">{s.n}</span>
                        </span>
                      ))}
                    </div>
                  </Card>
                )}
                <Card title="Capture metadata" padded={false}>
                  <div className="space-y-1.5 p-4 text-xs">
                    <Meta label="Filename" value={capture?.filename} />
                    <Meta label="SHA-256" value={capture?.sha256} mono />
                    <Meta label="Uploaded" value={formatDate(capture?.ts)} />
                    <Meta label="Span" value={charts?.span_sec ? `${charts.span_sec.toFixed(1)}s across ${charts?.timeline?.length} buckets` : '—'} />
                  </div>
                </Card>
              </div>
            </div>
          </Card>

          {/* stage 2 — graph + IOC cross-ref */}
          <Card
            title="3 · Connection graph"
            icon={Network}
            subtitle="d3-force · drag nodes · scrub the time slider"
            actions={graph?.ioc?.count ? (
              <Badge tone="red">{graph.ioc.count} IOC hit{graph.ioc.count === 1 ? '' : 's'}</Badge>
            ) : (
              <Badge tone="green">no corpus hits</Badge>
            )}
          >
            <ConnGraph nodes={graph?.nodes || []} edges={graph?.edges || []} flagged={graph?.ioc?.flagged || []} />
            {graph?.capped && <p className="mt-2 text-[11px] text-faint">Graph limited to the 400 busiest connection pairs.</p>}
          </Card>

          <Card title="4 · IOC cross-reference" icon={Radar}>
            <p className="mb-3 text-xs text-dim">
              Real matches against the platform's own ingested corpus (<span className="font-mono">processed_iocs</span>) —
              feeds such as URLhaus, ThreatFox, blocklist.de, OTX and Spamhaus populate it continuously.
            </p>
            {graph?.ioc?.flagged?.length ? (
              <div className="space-y-2">
                {graph.ioc.flagged.map((f, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-raised px-3 py-2 text-xs">
                    <span className="font-mono text-ink">{f.indicator}</span>
                    <Badge tone="blue">{f.type}</Badge>
                    <Badge tone="red">sev {f.severity.toFixed(1)}</Badge>
                    {f.family && <Badge tone="amber">{f.family}</Badge>}
                    {f.actors?.map((a) => <Badge key={a} tone="red">{a}</Badge>)}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-faint">No capture IP/domain matches an indicator in the ingested corpus.</p>
            )}
          </Card>

          {/* stage 4 — extracted files */}
          {files.length > 0 && (
            <Card
              title="5 · Recovered payloads (quarantined + YARA)"
              icon={Globe}
              actions={<Badge tone={maliciousFiles.length ? 'red' : 'green'}>{maliciousFiles.length ? `${maliciousFiles.length} malicious` : 'all clean'}</Badge>}
            >
              <div className="overflow-auto">
                <table className="w-full min-w-[640px] text-xs">
                  <thead>
                    <tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-faint">
                      <th className="py-2 pr-3">source</th><th className="py-2 pr-3">mime</th>
                      <th className="py-2 pr-3">size</th><th className="py-2 pr-3">verdict</th>
                      <th className="py-2 pr-3">sha-256</th><th className="py-2 pr-3">reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((f, i) => (
                      <tr key={i} className="border-b border-line/50 last:border-0">
                        <td className="py-2 pr-3 text-dim">{f.source}·{f.uid.slice(0, 8)}</td>
                        <td className="py-2 pr-3 text-dim">{f.mime_type || '—'}</td>
                        <td className="py-2 pr-3 font-mono text-ink">{bytesLabel(f.size_bytes)}</td>
                        <td className="py-2 pr-3"><Badge tone={f.verdict === 'malicious' ? 'red' : 'green'}>{f.verdict}</Badge></td>
                        <td className="max-w-[180px] truncate py-2 pr-3 font-mono text-dim">{f.sha256}</td>
                        <td className="py-2 pr-3 text-faint">{f.verdict_reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* stage 5 — AI summary */}
          <Card
            title="6 · AI investigation summary"
            icon={Sparkles}
            actions={
              <Button size="sm" variant="outline" icon={Sparkles} onClick={generateSummary} loading={summaryLoading}>
                {summaryLoading ? 'Summarising…' : summary ? 'Regenerate' : 'Generate summary'}
              </Button>
            }
          >
            <p className="mb-3 text-xs text-dim">
              The local LLM (Ollama, free Gemini/Groq fallback) writes a short analyst report from a
              fact sheet — every claim stays within the facts the pipeline gathered; the sheet is
              rendered below for auditability.
            </p>
            {summary?.status === 'error' && (
              <p className="text-xs text-amber-400">LLM unavailable: {summary.reason}</p>
            )}
            {summary?.summary && (
              <div className="rounded-lg border border-line bg-black/30 p-4 text-sm leading-relaxed text-slate-200">
                {summary.summary}
              </div>
            )}
            {summary?.facts && (
              <details className="mt-3">
                <summary className="cursor-pointer text-[11px] text-faint">grounding fact sheet</summary>
                <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-line bg-black/30 p-3 text-[10px] leading-relaxed text-slate-400">
                  {JSON.stringify(summary.facts, null, 2)}
                </pre>
              </details>
            )}
          </Card>

          {/* stage 5 — rule drafts */}
          <Card title="7 · Detection rule drafts (review only)" icon={Shield}>
            <p className="mb-3 text-xs text-dim">
              Deterministic Suricata / Snort / ModSecurity / firewall / YARA drafts from the IOC set
              below (pre-filled with the cross-referenced hits). Drafts only — nothing is auto-deployed.
            </p>
            <div className="space-y-2">
              {extraIocs.map((row, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <select
                    className="h-9 w-36 rounded-lg border border-line bg-raised px-2 text-xs text-ink"
                    value={row.type}
                    onChange={(e) => setIoc(idx, { type: e.target.value })}
                  >
                    {['ipv4', 'ipv6', 'domain', 'url', 'ja3', 'sha256'].map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <input
                    className="h-9 flex-1 rounded-lg border border-line bg-raised px-3 text-xs text-ink placeholder:text-faint"
                    placeholder="indicator value"
                    value={row.value}
                    onChange={(e) => setIoc(idx, { value: e.target.value })}
                  />
                  <Button size="sm" variant="ghost" onClick={() => removeIoc(idx)}>×</Button>
                </div>
              ))}
            </div>
            <div className="mt-3 flex items-center gap-2">
              <Button size="sm" onClick={addIoc}>Add IOC</Button>
              <Button size="sm" variant="primary" icon={Sparkles} onClick={generateRules} loading={generating}>
                {generating ? 'Generating…' : 'Generate drafts'}
              </Button>
            </div>
            {genError && <p className="mt-3 text-xs text-red-400">{genError}</p>}
            {drafts && (
              <div className="mt-4 space-y-4">
                {[
                  { title: 'Suricata (IDS/IPS)', content: drafts.suricata },
                  { title: 'Snort 2.9 compatible', content: drafts.snort },
                  { title: 'ModSecurity (WAF)', content: drafts.modsecurity },
                  { title: 'Firewall / blocklist', content: drafts.firewall },
                  { title: 'YARA (requires a sample hash)', content: drafts.yara },
                ].map((b) => <DraftBlock key={b.title} {...b} />)}
              </div>
            )}
          </Card>
        </>
      )}

      {/* recent captures */}
      <Card title="Recent captures" icon={Archive}>
        {captures.length ? (
          <div className="space-y-1.5">
            {captures.map((c) => (
              <button
                key={c.id}
                onClick={() => loadCapture(c.id)}
                className={`flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2 text-left text-xs transition-colors ${
                  captureId === c.id ? 'border-primary/40 bg-primary/5' : 'border-line bg-raised hover:border-primary/30'
                }`}
              >
                <Badge tone={c.status === 'done' ? 'green' : 'red'}>{c.status}</Badge>
                <span className="font-medium text-ink">{c.filename}</span>
                <span className="font-mono text-[10px] text-faint">{bytesLabel(c.size_bytes)}</span>
                <span className="text-faint">{formatDate(c.ts)}</span>
                <span className="ml-auto font-mono text-[10px] text-dim">
                  {c.counts.conn} conn · {c.counts.http} http · {c.counts.dns} dns{c.counts.extracted ? ` · ${c.counts.extracted} files` : ''}
                </span>
              </button>
            ))}
          </div>
        ) : (
          <p className="text-xs text-faint">No captures analysed yet — upload a .pcap above.</p>
        )}
      </Card>
    </div>
  );
}

function fileNameTimeout(capture) {
  return capture?.filename ? truncText(capture.filename, 26) : '—';
}

function truncText(s, max) {
  if (!s || s.length <= max) return s || '';
  return `${s.slice(0, max - 3)}…`;
}

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-line bg-raised px-4 py-3">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-faint">{label}</p>
      <p className="mt-1 text-xl font-bold text-ink">{value}</p>
      <p className="text-[10px] text-faint">{sub}</p>
    </div>
  );
}

function Meta({ label, value, mono = false }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-20 shrink-0 font-medium text-faint">{label}</span>
      <code className={mono ? 'truncate font-mono text-[11px] text-primary' : 'break-all text-dim'}>{value || '—'}</code>
    </div>
  );
}

function DraftBlock({ title, content }) {
  const copy = () => navigator.clipboard.writeText(content);
  const download = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `argus_pcap_${title.replace(/\W+/g, '_').toLowerCase()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <p className="text-xs font-semibold text-ink">{title}</p>
        <Button size="sm" icon={Copy} onClick={copy}>Copy</Button>
        <Button size="sm" icon={Download} onClick={download}>Download</Button>
      </div>
      <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-black/30 p-3 text-[11px] leading-relaxed text-slate-300">
        {content}
      </pre>
    </div>
  );
}