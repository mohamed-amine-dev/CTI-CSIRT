import { useState } from "react";
import { createRoot } from "react-dom/client";
import { StreamPage } from "./StreamPage";
import "./index.css";

type Kind = "darkweb" | "telegram";

const NAV: [Kind, string][] = [
  ["darkweb", "Dark Web Monitoring"],
  ["telegram", "Telegram Monitoring"],
];

export function App() {
  const [view, setView] = useState<Kind>("darkweb");
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900 py-3">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4">
          <span className="font-semibold text-slate-200">CTI • Phase 1</span>
          <nav className="flex gap-1">
            {NAV.map(([k, label]) => (
              <button
                key={k}
                className={`btn ${view === k ? "on" : ""}`}
                onClick={() => setView(k)}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-4">
        <StreamPage kind={view} />
      </main>
    </div>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(<App />);
