import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Copy, Download, FileSearch, Fingerprint, Plus, ShieldCheck, Sparkles, Trash2, UploadCloud } from 'lucide-react';

import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import { api, errorText, unwrap } from '../services/api';

const IOC_TYPES = [
  { key: 'ipv4',  label: 'IP address' },
  { key: 'ipv6',  label: 'IPv6 address' },
  { key: 'domain', label: 'Domain' },
  { key: 'url',   label: 'URL' },
  { key: 'ja3',   label: 'JA3 fingerprint' },
];

function verdictTone(verdict) {
  return verdict === 'malicious' ? 'red' : verdict === 'suspect' ? 'amber' : 'green';
}

function SecBlock({ title, engine, content, noValidate }) {
  const [valid, setValid] = useState(null);   // null | true | false
  const [output, setOutput] = useState('');
  const [checking, setChecking] = useState(false);

  const runValidate = useCallback(async () => {
    setChecking(true);
    setValid(null);
    setOutput('');
    try {
      const res = await unwrap(api.validateSampleRules(engine, content));
      setValid(res.valid);
      setOutput(res.output || '');
    } catch (err) {
      setValid(false);
      setOutput(errorText(err));
    } finally {
      setChecking(false);
    }
  }, [engine, content]);

  const copy = () => navigator.clipboard.writeText(content);
  const download = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `argus_${engine}_draft.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card title={title} className="mb-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {!noValidate && (
          <Button size="sm" icon={ShieldCheck} onClick={runValidate} loading={checking}>
            Validate with engine parser
          </Button>
        )}
        <Button size="sm" icon={Copy} onClick={copy}>Copy</Button>
        <Button size="sm" icon={Download} onClick={download}>Download</Button>
        {valid !== null && (
          <span className={`text-xs font-medium ${valid ? 'text-emerald-400' : 'text-red-400'}`}>
            {checking ? 'checking...' : valid ? '✓ passes syntax check' : '✗ fails syntax check'}
          </span>
        )}
      </div>
      <pre className="max-h-80 overflow-auto rounded-lg border border-line bg-black/30 p-3 text-[11px] leading-relaxed text-slate-300">
        {content}
      </pre>
      {output && (
        <pre className="mt-3 max-h-32 overflow-auto rounded-lg border border-line bg-black/30 p-3 text-[11px] text-slate-400">
          {output}
        </pre>
      )}
    </Card>
  );
}

export default function SampleScanner() {
  const [status, setStatus] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [fileName, setFileName] = useState('');
  const fileInputRef = useRef(null);

  const [extraIocs, setExtraIocs] = useState([{ type: 'ipv4', value: '' }]);
  const [generating, setGenerating] = useState(false);
  const [drafts, setDrafts] = useState(null);
  const [genError, setGenError] = useState(null);

  useEffect(() => {
    api.getSamplesStatus().then((r) => setStatus(r.data)).catch(() => setStatus(null));
  }, []);

  const pickFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileName(f.name);
    setResult(null);
    setDrafts(null);
    setScanError(null);
  };

  const scan = async () => {
    const f = fileInputRef.current?.files?.[0];
    if (!f) return;
    setScanning(true);
    setProgress(0);
    setScanError(null);
    setDrafts(null);
    try {
      const fd = new FormData();
      fd.append('file', f);
      const res = await unwrap(api.scanSample(fd, setProgress));
      setResult(res);
    } catch (err) {
      setScanError(errorText(err));
    } finally {
      setScanning(false);
    }
  };

  const addIocField = () => setExtraIocs((prev) => [...prev, { type: 'ipv4', value: '' }]);
  const removeIocField = (idx) => setExtraIocs((prev) => prev.filter((_, i) => i !== idx));
  const setIoc = (idx, patch) => setExtraIocs((prev) => prev.map((row, i) => (i === idx ? { ...row, ...patch } : row)));

  const generate = async () => {
    if (!result) return;
    setGenerating(true);
    setGenError(null);
    try {
      const iocs = extraIocs.filter((r) => r.value.trim());
      const res = await unwrap(api.generateSampleRules(result.quarantine_id, iocs));
      setDrafts(res);
    } catch (err) {
      setGenError(errorText(err));
    } finally {
      setGenerating(false);
    }
  };

  const allEngineBlocks = drafts
    ? [
        { id: 'suricata', title: 'Suricata (IDS/IPS)', engine: 'suricata', content: drafts.suricata },
        { id: 'snort', title: 'Snort 2.9 compatible', engine: 'snort', content: drafts.snort },
        { id: 'yara', title: 'YARA (sample signature)', engine: 'yara', content: drafts.yara },
        { id: 'modsecurity', title: 'ModSecurity (WAF)', engine: 'modsec', content: drafts.modsecurity, noValidate: true },
      ]
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-ink">Sample Scanner</h1>
        <p className="mt-0.5 text-sm text-dim">
          Upload a file — it is quarantined (0700), fingerprinted (SHA-256 / MD5), compared
          against the platform's processed-IOC corpus and scanned with our pinned
          Neo23x0/signature-base YARA bundle (734 rules). It is never executed.
        </p>
      </div>

      {status && (
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge tone={status?.yara?.present ? 'green' : 'red'}>
            YARA bundle {status?.yara?.size_bytes ? `${(status.yara.size_bytes / 1048576).toFixed(1)} MiB` : ''}
          </Badge>
          <Badge tone={status?.yara_binary ? 'green' : 'red'}>yara {status?.yara_binary ? '✓' : '✗'}</Badge>
          <Badge tone={status?.suricata_binary ? 'green' : 'red'}>suricata -T {status?.suricata_binary ? '✓' : '✗'}</Badge>
          <Badge tone={status?.quarantine_writeable ? 'green' : 'red'}>quarantine {status?.quarantine_writeable ? '✓' : '✗'}</Badge>
        </div>
      )}

      <Card title="1 · Upload a sample" icon={UploadCloud}>
        <div className="flex flex-wrap items-center gap-3">
          <input
            ref={fileInputRef}
            type="file"
            className="block w-full max-w-md text-xs text-dim file:mr-3 file:rounded-lg file:border-0 file:bg-raised file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-ink hover:file:bg-line"
            onChange={pickFile}
          />
          <Button variant="primary" icon={FileSearch} onClick={scan} loading={scanning}>
            {scanning ? `Scanning… ${progress}%` : 'Scan sample'}
          </Button>
        </div>
        {scanError && <p className="mt-3 text-xs text-red-400">{scanError}</p>}
      </Card>

      {result && (
        <Card
          title="2 · Scan result"
          icon={Fingerprint}
          actions={<Badge tone={verdictTone(result.verdict)}>{result.verdict.toUpperCase()}</Badge>}
        >
          <div className="mb-4 grid gap-x-6 gap-y-1.5 text-xs md:grid-cols-2">
            <Meta label="Filename" value={result.filename} />
            <Meta label="Size" value={`${result.size} bytes`} />
            <Meta label="Quarantine id" value={result.quarantine_id} mono />
            <Meta label="SHA-256" value={result.hashes.sha256} mono />
            <Meta label="MD5" value={result.hashes.md5} mono />
          </div>

          <Section label="Corpus hash match" tone="neutral">
            {result.corpus_matches?.length ? (
              result.corpus_matches.map((c, i) => (
                <Badge key={i} tone="red">{c.type}:{c.indicator}</Badge>
              ))
            ) : (
              <span className="text-xs text-faint">No processed-IOC match (normal for an unknown sample).</span>
            )}
          </Section>

          <Section label="YARA rules matched" tone="neutral">
            {result.yara_rules?.length ? (
              result.yara_rules.map((r) => <Badge key={r} tone="red">{r}</Badge>)
            ) : (
              <span className="text-xs text-faint">No YARA rule matched.</span>
            )}
          </Section>

          <Section label="Threat family cross-link" tone="neutral">
            {result.family_links?.length ? (
              result.family_links.map((fl, i) => (
                <Badge key={i} tone="amber" title={fl.link_source || ''}>{fl.name}</Badge>
              ))
            ) : (
              <span className="text-xs text-faint">No family association known for this sample.</span>
            )}
          </Section>

          <p className="mb-3 text-xs text-faint">
            Verdict: <span className="text-dim">{result.verdict_reason}</span>
          </p>
        </Card>
      )}

      {result && result.verdict === 'malicious' && (
        <Card title="3 · Generate detection rules (review drafts only)" icon={Sparkles}>
          <p className="mb-4 text-xs text-dim">
            Draft deterministic Suricata / Snort / ModSecurity / firewall / YARA rules from this
            confirmed malicious sample. Output is for analyst review &amp; staging validation —
            nothing is auto-deployed.
          </p>

          <div className="space-y-2">
            {extraIocs.map((row, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <select
                  className="h-9 w-36 rounded-lg border border-line bg-raised px-2 text-xs text-ink"
                  value={row.type}
                  onChange={(e) => setIoc(idx, { type: e.target.value })}
                >
                  {IOC_TYPES.map((t) => (
                    <option key={t.key} value={t.key}>{t.label}</option>
                  ))}
                </select>
                <input
                  className="h-9 flex-1 rounded-lg border border-line bg-raised px-3 text-xs text-ink placeholder:text-faint"
                  placeholder="optional extra indicator (IP / domain / URL / JA3)"
                  value={row.value}
                  onChange={(e) => setIoc(idx, { value: e.target.value })}
                />
                {idx > 0 && (
                  <Button size="sm" variant="ghost" icon={Trash2} onClick={() => removeIocField(idx)} aria-label="Remove" />
                )}
              </div>
            ))}
          </div>

          <div className="mt-3 flex items-center gap-2">
            <Button size="sm" icon={Plus} onClick={addIocField}>Add IOC</Button>
            <Button variant="primary" icon={Sparkles} onClick={generate} loading={generating}>
              {generating ? 'Generating…' : 'Generate detection rules'}
            </Button>
          </div>

          {genError && <p className="mt-3 text-xs text-red-400">{genError}</p>}

          {drafts && (
            <div className="mt-5">
              <p className="mb-3 text-xs text-faint">
                matched YARA: {drafts.yara_rules_matched?.join(', ') || '—'} · {drafts.validated_with || ''}
              </p>
              {allEngineBlocks.map((b) => (
                <SecBlock key={b.id} {...b} />
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function Meta({ label, value, mono = false }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-32 shrink-0 font-medium text-faint">{label}</span>
      <code className={mono ? 'truncate font-mono text-[11px] text-primary' : 'text-dim break-all'}>{value}</code>
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div className="mb-4">
      <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">{label}</p>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}