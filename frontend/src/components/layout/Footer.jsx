import React from 'react';

/**
 * Footer — compact CSIRT/SOC status bar. Shows the TLP handling marker, the
 * operations label, the engine identity and live platform/database status.
 */
export default function Footer() {
  return (
    <footer className="shrink-0 border-t border-line bg-surface/80 backdrop-blur">
      <div className="mx-auto flex w-full max-w-screen-2xl flex-col items-center justify-between gap-x-6 gap-y-1.5 px-4 py-2.5 text-[10px] font-medium tracking-wide sm:px-6 md:flex-row">
        <div className="flex items-center gap-2.5">
          <span className="rounded border border-amber-400/60 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-bold tracking-widest text-amber-300">
            TLP:AMBER
          </span>
          <span className="uppercase tracking-widest text-dim">Internal Security Operations</span>
        </div>

        <span className="text-faint">Argus CTI Engine · Real-Time Threat Telemetry</span>

        <span className="text-faint">
          Database: ClickHouse OLAP <span className="font-semibold text-emerald-400">(Active)</span>{' '}
          · System Status: <span className="font-semibold text-emerald-400">Operational</span>
        </span>
      </div>
    </footer>
  );
}
