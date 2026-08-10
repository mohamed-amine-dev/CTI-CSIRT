import React, { useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Columns3,
  Database,
  Play,
  ShieldCheck,
  Table2,
} from 'lucide-react';

import Button from '../components/ui/Button';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import Loader from '../components/ui/Loader';
import Table from '../components/ui/Table';
import { useApi, useAsync } from '../hooks/useApi';
import { api, errorText, unwrap } from '../services/api';

const PAGE_SIZE = 25;

function cellText(v) {
  if (v === null || v === undefined) return '∅';
  const s = String(v);
  return s.length > 160 ? `${s.slice(0, 160)}…` : s;
}

function rowsToObjects(columns, rows) {
  return (rows || []).map((r) => Object.fromEntries(columns.map((c, i) => [c, r[i]])));
}

function dynamicColumns(columns) {
  return columns.map((c) => ({
    key: c,
    label: c,
    className: 'max-w-[300px]',
    render: (row) => <span className="block truncate font-mono text-xs" title={cellText(row[c])}>{cellText(row[c])}</span>,
  }));
}

/**
 * Data Explorer (/explore) — read-only access to the raw ClickHouse schema.
 * Every query runs through the SELECT-only `cti_ro` account (readonly=1), so
 * even the ad-hoc query box cannot mutate data.
 */
export default function DataExplorer() {
  const tables = useApi(() => unwrap(api.getExploreTables()), { deps: [], refreshMs: 30_000 });

  const [table, setTable] = useState(null);
  const [page, setPage] = useState(0);

  const columns = useApi(() => (table ? unwrap(api.getExploreColumns(table)) : null), {
    deps: [table],
    auto: !!table,
  });
  const rows = useApi(
    () => (table ? unwrap(api.getExploreRows(table, { limit: PAGE_SIZE, offset: page * PAGE_SIZE })) : null),
    { deps: [table, page], auto: !!table },
  );

  const run = useAsync((sql) => unwrap(api.runExploreQuery(sql)));
  const [sql, setSql] = useState('SELECT * FROM cti.raw_threat_intel FINAL LIMIT 10');

  const selectTable = (name) => {
    setTable(name);
    setPage(0);
  };

  const onRunQuery = async (e) => {
    e?.preventDefault();
    const q = sql.trim();
    if (!q) return;
    run.setData(null);
    try {
      await run.run(q);
    } catch { /* error surfaced via run.error */ }
  };

  const isLastPage = rows.data && rows.data.rows && rows.data.rows.length < PAGE_SIZE;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-mono text-xl font-bold text-ink">
            <Database size={20} className="text-cyan-400" /> Data Explorer
          </h1>
          <p className="text-xs text-dim">
            Browse every ClickHouse table and run ad-hoc read-only queries
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-semibold text-emerald-300">
          <ShieldCheck size={13} /> Read-only · cti_ro user
        </span>
      </div>

      {/* --- Table picker ---------------------------------------------------- */}
      <Card title="Tables" icon={Table2} subtitle="platform database, live row counts">
        {tables.loading ? (
          <Loader label="Loading tables…" />
        ) : tables.error ? (
          <ErrorState title="Could not load tables" message={errorText(tables.error)} onRetry={tables.reload} />
        ) : !tables.data?.tables?.length ? (
          <EmptyState icon={Table2} title="No tables found" message="The schema has not been initialised yet." />
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {tables.data.tables.map((t) => (
              <button
                key={t.name}
                onClick={() => selectTable(t.name)}
                className={`rounded-lg border px-3 py-2.5 text-left transition-colors ${
                  table === t.name
                    ? 'border-cyan-500/40 bg-cyan-500/10'
                    : 'border-line bg-base/50 hover:border-cyan-500/30'
                }`}
              >
                <p className={`font-mono text-sm font-semibold ${table === t.name ? 'text-cyan-300' : 'text-ink'}`}>
                  {t.name}
                </p>
                <p className="mt-0.5 flex items-center gap-2 text-[11px] text-faint">
                  <span>{t.engine}</span>
                  <span className="ml-auto font-mono">{t.rows.toLocaleString()} rows</span>
                </p>
              </button>
            ))}
          </div>
        )}
      </Card>

      {/* --- Schema + rows for the selected table ------------------------------ */}
      {table && (
        <Card
          title={table}
          icon={Columns3}
          subtitle="schema · newest-first preview"
          action={
            <div className="flex items-center gap-2">
              <Button size="sm" variant="ghost" icon={ChevronLeft} disabled={page === 0} onClick={() => setPage(page - 1)}>
                Prev
              </Button>
              <span className="font-mono text-xs text-faint">page {page + 1}</span>
              <Button size="sm" variant="ghost" icon={ChevronRight} disabled={isLastPage} onClick={() => setPage(page + 1)}>
                Next
              </Button>
            </div>
          }
        >
          {columns.loading ? (
            <Loader label="Loading schema…" />
          ) : (
            columns.data?.columns?.length > 0 && (
              <div className="mb-4 flex flex-wrap gap-1.5">
                {columns.data.columns.map((c) => (
                  <span key={c.name} className="rounded border border-line bg-raised px-2 py-0.5 font-mono text-[11px]">
                    <span className="text-cyan-300">{c.name}</span>
                    <span className="ml-1.5 text-faint">{c.type}</span>
                  </span>
                ))}
              </div>
            )
          )}

          {rows.loading ? (
            <Loader label="Loading rows…" />
          ) : rows.error ? (
            <ErrorState title="Failed to load rows" message={errorText(rows.error)} onRetry={rows.reload} />
          ) : (
            <Table
              columns={dynamicColumns(rows.data?.columns || [])}
              data={rowsToObjects(rows.data?.columns || [], rows.data?.rows || [])}
              emptyText="This table is empty."
            />
          )}
        </Card>
      )}

      {/* --- Ad-hoc read-only query box --------------------------------------- */}
      <Card title="Query" icon={Play} subtitle="free SELECT (FINAL dedups upserts) — read-only">
        <form onSubmit={onRunQuery} className="space-y-3">
          <textarea
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            rows={4}
            spellCheck={false}
            className="focus-neon w-full rounded-lg border border-line bg-surface p-3 font-mono text-xs text-ink placeholder:text-faint"
            placeholder="SELECT * FROM cti.vulnerability_alerts FINAL LIMIT 10"
          />
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" icon={Play} loading={run.loading}>
              Run Query
            </Button>
            <span className="text-[11px] text-faint">
              Write statements (INSERT / ALTER / DROP …) are rejected server-side by the cti_ro account.
            </span>
          </div>
        </form>

        {run.error && (
          <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {errorText(run.error)}
          </div>
        )}

        {run.data && (
          <div className="mt-3 overflow-hidden rounded-lg border border-line">
            <Table
              columns={dynamicColumns(run.data.columns || [])}
              data={rowsToObjects(run.data.columns || [], run.data.rows || [])}
              emptyText="Query returned no rows."
            />
          </div>
        )}
      </Card>
    </div>
  );
}
