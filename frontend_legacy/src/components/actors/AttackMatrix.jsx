import React, { useMemo, useState } from 'react';
import { ExternalLink, Grid3X3, RefreshCw, ShieldQuestion } from 'lucide-react';

import ErrorState from '../ui/ErrorState';
import { Skeleton } from '../ui/skeleton';
import { useApi } from '../../hooks/useApi';
import { api, errorText, unwrap } from '../../services/api';
import { tacticColor, tacticLabel } from '../../utils/tactics';
import renderStixMarkdown from '../../utils/stix.jsx';

const HIGHLIGHT = [79, 142, 247]; // #4F8EF7 primary

/**
 * AttackMatrix — per-actor ATT&CK matrix (simple custom grid, no Navigator).
 *
 * 14 tactic columns (MITRE order); every technique in the imported
 * enterprise-attack KB is a small tile. Tiles are highlighted ONLY for
 * techniques the actor<->technique relationship data records; every other
 * tile is dimmed. Clicking a highlighted tile opens its ID, name and
 * description below the grid. Nothing here is guessed from text.
 */
export default function AttackMatrix({ actor }) {
  const [selected, setSelected] = useState(null);

  const matrix = useApi(
    () => (actor?.stix_id ? unwrap(api.getActorAttackMatrix(actor.stix_id)) : Promise.resolve(null)),
    { deps: [actor?.stix_id] },
  );

  const data = matrix.data;
  const techniques = data?.techniques || [];

  const byTactic = useMemo(() => {
    const groups = {};
    for (const t of techniques) (groups[t.tactic] ||= []).push(t);
    return groups;
  }, [techniques]);

  const usedCount = data?.highlights?.used ?? techniques.filter((t) => t.used).length;

  const openTechnique = (t) => setSelected(t);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 border-b border-line px-5 py-3.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
              <Grid3X3 size={15} className="text-primary" /> ATT&CK Matrix
            </h2>
            <p className="mt-0.5 text-xs text-faint">
              Tiles = techniques in the imported ATT&CK KB, grouped by tactic. Highlighting comes only
              from real actor↔technique relationships.
            </p>
          </div>
          <button
            type="button"
            onClick={() => { setSelected(null); matrix.reload(); }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-raised px-2.5 py-1.5 text-xs font-medium text-dim transition-colors hover:text-ink"
          >
            <RefreshCw size={12} /> Reload
          </button>
        </div>
        <div className="mt-2.5 flex flex-wrap items-center gap-2 text-[11px] text-dim">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-1">
            <span className="h-2 w-2 rounded-full" style={{ background: `rgba(${HIGHLIGHT.join(',')},0.9)` }} />
            <span className="font-mono font-bold text-ink">{usedCount}</span> used by {actor?.name}
          </span>
          <span className="rounded-md border border-line bg-raised px-2 py-1">
            <span className="font-mono font-bold text-ink">{data ? techniques.length : '…'}</span> in KB
          </span>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {matrix.loading && !data ? (
          <div className="space-y-4 p-5">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-24 w-full rounded-xl" />
            ))}
          </div>
        ) : matrix.error ? (
          <div className="p-5">
            <ErrorState
              title="Failed to load the ATT&CK matrix"
              message={errorText(matrix.error)}
              onRetry={() => { setSelected(null); matrix.reload(); }}
            />
          </div>
        ) : (
          <div className="flex gap-3 p-5">
            {data.tactics.map((tactic) => {
              const list = byTactic[tactic] || [];
              const used = list.filter((t) => t.used).length;
              return (
                <div key={tactic} className="w-[168px] shrink-0 rounded-xl border border-line bg-surface">
                  <div className="flex items-center gap-1.5 border-b border-line px-2.5 py-2">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: tacticColor(tactic) }}
                    />
                    <span className="min-w-0 flex-1 truncate text-[11px] font-semibold uppercase tracking-wide text-dim">
                      {tacticLabel(tactic)}
                    </span>
                    {used > 0 && (
                      <span className="shrink-0 rounded-md border border-primary/30 bg-primary/10 px-1 py-px font-mono text-[10px] font-bold text-primary">
                        {used}
                      </span>
                    )}
                  </div>
                  <div className="max-h-[520px] overflow-y-auto p-2">
                    <div className="flex flex-wrap gap-1">
                      {list.map((t) => (
                        t.used ? (
                          <button
                            key={t.stix_id}
                            type="button"
                            onClick={() => openTechnique(t)}
                            title={`${t.x_mitre_id} — ${t.name}`}
                            className={`cursor-pointer rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold transition-colors ${
                              selected?.stix_id === t.stix_id
                                ? 'border-primary bg-primary text-white'
                                : 'border-primary/40 bg-primary/10 text-primary hover:bg-primary/20'
                            }`}
                          >
                            {t.x_mitre_id}
                          </button>
                        ) : (
                          <span
                            key={t.stix_id}
                            title={`${t.x_mitre_id} — ${t.name}`}
                            className="rounded border border-transparent bg-base/50 px-1.5 py-0.5 font-mono text-[10px] text-faint"
                          >
                            {t.x_mitre_id}
                          </span>
                        )
                      ))}
                      {list.length === 0 && (
                        <span className="px-1 py-0.5 text-[10px] text-faint">—</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {selected && (
        <div className="shrink-0 border-t border-line bg-base/40 px-5 py-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-[11px] font-bold text-primary">
                  {selected.x_mitre_id}
                </span>
                <span className="text-sm font-semibold text-ink">{selected.name}</span>
                <span
                  className="inline-flex items-center gap-1.5 rounded-md border border-line bg-raised px-2 py-0.5 text-[11px] text-dim"
                >
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: tacticColor(selected.tactic) }} />
                  {tacticLabel(selected.tactic)}
                </span>
                {selected.url && (
                  <a
                    href={selected.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline"
                  >
                    View on MITRE <ExternalLink size={11} />
                  </a>
                )}
              </div>
              <div className="mt-2 max-h-44 overflow-y-auto rounded-lg border border-line bg-surface p-3 text-xs leading-relaxed text-dim [&_a]:break-all">
                {renderStixMarkdown(selected.description) || (
                  <span className="text-faint">No description in the knowledge base.</span>
                )}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="shrink-0 rounded-md border border-line bg-raised px-2 py-1 text-[11px] font-medium text-dim transition-colors hover:text-ink"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {!selected && !matrix.loading && data && (
        <div className="flex shrink-0 items-center gap-1.5 border-t border-line px-5 py-2.5 text-[11px] text-faint">
          <ShieldQuestion size={12} className="text-primary/70" />
          Click a highlighted tile for the technique’s ID, name and description.
        </div>
      )}
    </div>
  );
}