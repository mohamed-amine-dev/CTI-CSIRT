// -----------------------------------------------------------------------------
// Tiny safe STIX-markdown renderer. MITRE descriptions are markdown-ish:
// citations, [text](url) links, **bold**, *italics*, `code` and paragraph breaks.
// We escape everything first, then convert a small, safe subset — never raw HTML.
// -----------------------------------------------------------------------------

export function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Render actor/malware/TTP STIX descriptions into React elements. */
export default function renderStixMarkdown(text) {
  if (!text) return null;

  let html = escapeHtml(text);
  html = html.replace(/\(Citation:\s*[^)]*\)/gi, '');
  html = html.replace(/\[([^\]]{1,150})\]\(([^)\s]+)\)/g, (_m, t, u) =>
    `<a href="${u}" target="_blank" rel="noreferrer" class="text-primary hover:underline">${t}</a>`,
  );
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/(^|[\s(])\*([^*\n]+)\*(?=$|[\s).,;:!?])/g, '$1<em>$2</em>');
  html = html.replace(/`([^`]+)`/g, '<code class="rounded bg-raised px-1 py-px font-mono text-[0.85em] text-primary">$1</code>');

  const paragraphs = html
    .split(/\n{2,}/)
    .map((p) => p.replace(/\n/g, '<br/>').trim())
    .filter(Boolean);

  return (
    <div className="space-y-2">
      {paragraphs.map((p, i) => (
        <p key={i} className="text-sm leading-relaxed text-ink [&_a]:break-all" dangerouslySetInnerHTML={{ __html: p }} />
      ))}
    </div>
  );
}