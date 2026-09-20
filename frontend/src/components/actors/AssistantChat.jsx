import React, { useRef, useState } from 'react';
import { Bot, Eraser, Send, Sparkles } from 'lucide-react';

import Button from '../ui/Button';
import Card from '../ui/Card';
import { useAsync } from '../../hooks/useApi';
import { api, errorText, unwrap } from '../../services/api';
import renderStixMarkdown from '../../utils/stix.jsx';

const STARTERS = [
  'Tell me about APT28',
  'Who uses Cobalt Strike?',
  'What is T1055?',
  'Explain the Initial Access tactic',
  'Which actors target the energy sector?',
  'What does Kimsuky cover?',
];

/**
 * AssistantChat — knowledge-base teaching chatbot.
 *
 * The server retrieves ATT&CK facts from ClickHouse, then a LOCAL Ollama model
 * (with no cloud dependency) synthesises the answer strictly from those facts.
 * When Ollama is unavailable the deterministic KB answer is returned instead,
 * so the chat never fails and never invents data.
 */
export default function AssistantChat() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text:
        'Hi! I answer questions about the ATT&CK knowledge base — threat actors, TTPs, tactics, malware and tools.\n\nAsk me things like *"Who uses Cobalt Strike?"*, *"What is T1055?"* or *"Which actors target the energy sector?"*',
    },
  ]);
  const [input, setInput] = useState('');
  const [chips, setChips] = useState(STARTERS);
  const listRef = useRef(null);
  const ask = useAsync(api.askActors);

  const scrollDown = () => {
    requestAnimationFrame(() => {
      const el = listRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    });
  };

  const send = async (text) => {
    const q = text.trim();
    if (!q || ask.loading) return;
    setMessages((m) => [...m, { role: 'user', text: q }]);
    setInput('');
    scrollDown();
    try {
      const res = await ask.run(q);
      const data = res.data || {};
      setMessages((m) => [...m, { role: 'assistant', text: data.answer || 'No answer.' }]);
      if (Array.isArray(data.suggestions) && data.suggestions.length) setChips(data.suggestions);
    } catch (e) {
      setMessages((m) => [
        ...m,
        {
          role: 'assistant',
          text: `Sorry — I could not build an answer from the knowledge base right now (${errorText(e)}).`,
        },
      ]);
    } finally {
      scrollDown();
    }
  };

  const clear = () => {
    setMessages([
      {
        role: 'assistant',
        text: 'New conversation. Ask me anything about the ATT&CK knowledge base.',
      },
    ]);
    setChips(STARTERS);
  };

  return (
    <Card
      padded={false}
      className="flex min-h-0 flex-1 flex-col overflow-hidden"
      bodyClassName="flex min-h-0 flex-1 flex-col"
    >
      <div className="flex shrink-0 items-center justify-between border-b border-line p-3">
        <div className="flex items-center gap-2">
          <Bot size={16} className="text-primary" />
          <span className="text-sm font-semibold text-ink">ATT&CK Assistant</span>
          <span className="hidden items-center gap-1 rounded-md border border-line bg-raised px-2 py-0.5 text-[10px] text-faint sm:flex">
            <Sparkles size={10} className="text-primary" /> grounded in local data
          </span>
        </div>
        {messages.length > 1 && (
          <Button variant="ghost" size="sm" icon={Eraser} onClick={clear}>
            Clear
          </Button>
        )}
      </div>

      <div ref={listRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
        {messages.map((m, i) =>
          m.role === 'assistant' ? (
            <div key={i} className="flex gap-2.5">
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-line bg-raised">
                <Bot size={14} className="text-primary" />
              </div>
              <div className="max-w-[82%] rounded-xl rounded-tl-sm border border-line bg-surface px-3.5 py-2.5">
                <div className="[&_strong]:text-ink [&_ul]:list-disc [&_ul]:space-y-1 [&_ul]:pl-4 [&_a]:text-primary [&_a]:hover:underline [&_code]:rounded [&_code]:bg-raised [&_code]:px-1 [&_code]:py-px [&_code]:font-mono [&_code]:text-[11px] [&_code]:text-primary">
                  <div className="text-sm leading-relaxed text-dim"> {renderStixMarkdown(m.text)} </div>
                </div>
              </div>
            </div>
          ) : (
            <div key={i} className="flex justify-end">
              <div className="max-w-[82%] rounded-xl rounded-tr-sm border border-primary/25 bg-primary/10 px-3.5 py-2.5 text-sm text-ink">
                {m.text}
              </div>
            </div>
          ),
        )}
        {ask.loading && (
          <div className="flex gap-2.5">
            <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-line bg-raised">
              <Bot size={14} className="animate-pulse text-primary" />
            </div>
            <div className="rounded-xl rounded-tl-sm border border-line bg-surface px-3.5 py-3">
              <span className="flex items-center gap-1.5 text-xs text-faint">
                Searching the knowledge base<span className="animate-pulse">…</span>
              </span>
            </div>
          </div>
        )}
      </div>

      {chips.length > 0 && (
        <div className="flex shrink-0 flex-wrap gap-1.5 border-t border-line/60 px-4 py-2.5">
          {chips.slice(0, 6).map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => send(c)}
              disabled={ask.loading}
              className="rounded-full border border-line bg-base/70 px-3 py-1 text-xs text-dim transition-colors hover:border-primary/40 hover:text-primary disabled:cursor-not-allowed disabled:opacity-50"
            >
              {c}
            </button>
          ))}
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
        className="flex shrink-0 items-center gap-2 border-t border-line p-3"
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder='Ask about an APT, technique (e.g. "T1055"), tactic, malware or a sector…'
          className="focus-ring w-full rounded-lg border border-line bg-base px-3 py-2 text-sm text-ink placeholder:text-faint focus:border-primary focus:outline-none"
        />
        <Button type="submit" variant="primary" size="sm" icon={Send} disabled={ask.loading || !input.trim()}>
          Send
        </Button>
      </form>
    </Card>
  );
}