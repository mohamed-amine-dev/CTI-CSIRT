import React, { useEffect, useState } from 'react';
import { BookOpenText, FileText } from 'lucide-react';

import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import { useApi } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';

// -----------------------------------------------------------------------------
// Minimal, dependency-free markdown renderer.
//
// The ADRs are Uber/MADR-format markdown (headings, bold/italic, inline code,
// bullet + numbered lists). This renders exactly those features to React nodes.
// No dangerouslySetInnerHTML is used anywhere: plain text is always a string
// (auto-escaped by React), so the raw file can never inject markup.
// -----------------------------------------------------------------------------

const HEADING_CLASSES = {
  1: 'font-mono text-xl font-bold text-ink',
  2: 'mt-6 text-base font-semibold text-cyan-300',
  3: 'mt-4 text-sm font-semibold text-cyan-300/90',
  4: 'mt-3 text-sm font-semibold text-ink',
  5: 'mt-3 text-xs font-bold uppercase tracking-wider text-dim',
};

function inline(text) {
  const parts = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const tok = m[0];
    const key = parts.length;
    if (tok.startsWith('**') && tok.endsWith('**')) {
      parts.push(
        <strong key={key} className="font-semibold text-ink">
          {tok.slice(2, -2)}
        </strong>
      );
    } else if (tok.startsWith('*') && tok.endsWith('*') && tok.length > 2) {
      parts.push(
        <em key={key} className="italic text-ink/90">
          {tok.slice(1, -1)}
        </em>
      );
    } else {
      const link = /\[([^\]]+)\]\(([^)\s]+)\)/.exec(tok);
      parts.push(
        <a
          key={key}
          href={link[2]}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-2 hover:text-cyan-300"
        >
          {link[1]}
        </a>
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts.length ? parts : text;
}

function renderMarkdown(md) {
  const lines = String(md || '').replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }

    if (/^```/.test(line.trim())) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) {
        buf.push(lines[i]);
        i++;
      }
      i++;
      blocks.push(
        <pre key={blocks.length} className="my-3 overflow-auto rounded-lg border border-line bg-base p-3 font-mono text-xs leading-relaxed text-cyan-200/90">
          <code>{buf.join('\n')}</code>
        </pre>
      );
      continue;
    }

    const hm = /^(#{1,5})\s+(.*)$/.exec(line.trim());
    if (hm) {
      const level = hm[1].length;
      blocks.push(
        <h4
          key={blocks.length}
          className={`mb-2 ${HEADING_CLASSES[level]}`}
        >
          {inline(hm[2].trim())}
        </h4>
      );
      i++;
      continue;
    }

    if (/^\s*(---+|\*\*\*+|___+)\s*$/.test(line)) {
      blocks.push(<hr key={blocks.length} className="my-4 border-line" />);
      i++;
      continue;
    }

    if (line.trim().startsWith('>')) {
      const buf = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        buf.push(lines[i].trim().replace(/^>\s?/, ''));
        i++;
      }
      blocks.push(
        <blockquote
          key={blocks.length}
          className="my-3 border-l-2 border-cyan-500/40 pl-3 text-sm italic text-dim"
        >
          {inline(buf.join(' '))}
        </blockquote>
      );
      continue;
    }

    const isList = /^\s*[-*+]\s+/.test(line) || /^\s*\d+[.)]\s+/.test(line);
    if (isList) {
      const items = [];
      let cur = null;
      while (i < lines.length && lines[i].trim()) {
        const l = lines[i];
        let match = /^\s*[-*+]\s+/.exec(l);
        if (match) {
          if (cur) items.push(cur);
          cur = { ordered: false, text: l.slice(match[0].length).trim() };
        } else {
          match = /^\s*\d+[.)]\s+/.exec(l);
          if (match) {
            if (cur) items.push(cur);
            cur = { ordered: true, text: l.slice(match[0].length).trim() };
          } else if (cur) {
            cur.text += ` ${l.trim()}`;
          }
        }
        i++;
      }
      if (cur) items.push(cur);
      const ordered = items.some((it) => it.ordered);
      const ListTag = ordered ? 'ol' : 'ul';
      const liClass = ordered
        ? 'my-1 list-decimal pl-5 text-sm leading-relaxed text-dim marker:text-cyan-400'
        : 'my-1 list-disc pl-5 text-sm leading-relaxed text-dim marker:text-cyan-400';
      blocks.push(
        <ListTag key={blocks.length} className="my-2">
          {items.map((it, j) => (
            <li key={j} className={liClass}>
              {inline(it.text)}
            </li>
          ))}
        </ListTag>
      );
      continue;
    }

    const para = [];
    while (i < lines.length && lines[i].trim()) {
      para.push(lines[i].trim());
      i++;
    }
    blocks.push(
      <p key={blocks.length} className="my-2 text-sm leading-relaxed text-dim">
        {inline(para.join(' '))}
      </p>
    );
  }
  return blocks;
}

function shortTitle(title) {
  return title.replace(/^\d{4}:\s*/, '');
}

export default function Docs() {
  const [selected, setSelected] = useState(null);
  const list = useApi(() => unwrap(api.getAdrList()), { deps: [] });
  const doc = useApi(() => unwrap(api.getAdr(selected)), { deps: [selected], auto: !!selected });

  useEffect(() => {
    if (!selected && list.data?.items?.length) {
      setSelected(list.data.items[0].num);
    }
  }, [list.data, selected]);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
          <BookOpenText size={20} className="text-cyan-400" /> Architecture Decision Records
        </h1>
        <p className="text-xs text-dim">
          Uber/MADR-format records of the platform's architectural choices — the
          “why” behind every stack decision (report §5.13).
        </p>
      </div>

      <div className="grid items-start gap-5 xl:grid-cols-5">
        <section className="xl:col-span-2">
          <Card title="Records" subtitle={`${list.data?.count ?? 0} ADRs`} icon={FileText} padded={false}>
            {list.loading && !list.data ? (
              <p className="p-4 text-xs text-faint">Loading records…</p>
            ) : list.error ? (
              <p className="p-4 text-xs text-red-400">
                Could not load ADRs: {errorText(list.error)}
              </p>
            ) : !list.data?.items?.length ? (
              <p className="p-4 text-xs text-faint">No ADRs published yet.</p>
            ) : (
              <ul className="max-h-[calc(100vh-19rem)] overflow-y-auto p-2">
                {list.data.items.map((adr) => {
                  const active = adr.num === selected;
                  return (
                    <li key={adr.num}>
                      <button
                        onClick={() => setSelected(adr.num)}
                        className={`flex w-full items-start gap-2.5 rounded-lg px-3 py-2 text-left transition-colors ${
                          active
                            ? 'bg-cyan-500/10 ring-1 ring-cyan-500/40'
                            : 'hover:bg-raised'
                        }`}
                      >
                        <span className="mt-0.5 shrink-0 rounded bg-raised px-1.5 py-0.5 font-mono text-[10px] font-bold text-cyan-300">
                          ADR-{adr.num}
                        </span>
                        <span className={`text-xs leading-snug ${active ? 'text-cyan-200' : 'text-dim'}`}>
                          {shortTitle(adr.title)}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        </section>

        <section className="xl:col-span-3">
          {selected ? (
            <Card
              title={doc.data ? shortTitle(doc.data.title) : '…'}
              icon={BookOpenText}
              subtitle={doc.data?.file || `ADR-${selected}`}
              padded={false}
            >
              <div className="p-5">
                {doc.loading && !doc.data ? (
                  <p className="text-xs text-faint">Rendering record…</p>
                ) : doc.error ? (
                  <ErrorState
                    title="Could not load this record"
                    message={errorText(doc.error)}
                    onRetry={doc.reload}
                  />
                ) : doc.data ? (
                  <div>{renderMarkdown(doc.data.content)}</div>
                ) : (
                  <EmptyState icon={FileText} title="Select a record" message="Pick an ADR from the list on the left." />
                )}
              </div>
            </Card>
          ) : (
            <EmptyState
              icon={BookOpenText}
              title="No record selected"
              message="Pick an ADR from the list on the left to read the decision, its drivers and its consequences."
            />
          )}
        </section>
      </div>
    </div>
  );
}
