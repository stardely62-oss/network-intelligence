import { Activity, Cable, FileText, LayoutGrid, ListTree, Settings as Cog, ShieldCheck, ShieldOff, X } from "lucide-react";
import type { ReactNode } from "react";
import { cx } from "./components/ui";
import { AppProvider, useApp, type Page } from "./lib/app";
import { duration } from "./lib/format";
import { Connections } from "./pages/Connections";
import { Diagnostics } from "./pages/Diagnostics";
import { Overview } from "./pages/Overview";
import { Reports } from "./pages/Reports";
import { Settings } from "./pages/Settings";
import { Timeline } from "./pages/Timeline";
import { useNow } from "./lib/useNow";

const NAV: { id: Page; label: string; icon: ReactNode }[] = [
  { id: "overview", label: "Обзор", icon: <LayoutGrid size={16} /> },
  { id: "connections", label: "Соединения", icon: <Cable size={16} /> },
  { id: "diagnostics", label: "Диагностика", icon: <Activity size={16} /> },
  { id: "timeline", label: "Хронология", icon: <ListTree size={16} /> },
  { id: "reports", label: "Отчёты", icon: <FileText size={16} /> },
  { id: "settings", label: "Настройки", icon: <Cog size={16} /> },
];

function Shell() {
  const { page, go, info, recordingId, sessions, error, setError } = useApp();
  const now = useNow(1000, !!recordingId);
  const rec = sessions.find((s) => s.meta.id === recordingId);
  return (
    <div className="flex h-screen bg-bg text-fg">
      <aside className="flex w-[208px] shrink-0 flex-col border-r border-line bg-panel">
        <div className="flex items-center gap-2.5 px-4 pb-4 pt-4">
          <Logo />
          <div className="leading-tight">
            <div className="text-[13px] font-semibold">Network</div>
            <div className="text-[13px] font-semibold text-muted">Intelligence</div>
          </div>
        </div>
        <nav className="flex flex-col gap-0.5 px-2">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => go(n.id)}
              className={cx(
                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors",
                page === n.id ? "bg-raised text-fg" : "text-muted hover:bg-white/[0.03] hover:text-fg",
              )}
            >
              <span className={page === n.id ? "text-accent" : ""}>{n.icon}</span>
              {n.label}
              {n.id === "diagnostics" && recordingId && <span className="ml-auto h-1.5 w-1.5 animate-pulse2 rounded-full bg-bad" />}
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-2 border-t border-line px-4 py-3 text-2xs text-muted">
          {recordingId && (
            <button onClick={() => go("diagnostics")} className="flex w-full items-center gap-2 text-left text-fg">
              <span className="h-2 w-2 animate-pulse2 rounded-full bg-bad" />
              <span className="truncate">Запись {rec ? duration(now - rec.meta.startedAt) : ""}</span>
            </button>
          )}
          {info && (
            <div className="flex items-center gap-1.5" title="Права текущего процесса Network Intelligence">
              {info.elevated ? <ShieldCheck size={12} className="text-warn" /> : <ShieldOff size={12} />}
              {info.elevated == null ? "права неизвестны" : info.elevated ? "запущено от администратора" : "без прав администратора"}
            </div>
          )}
          {info && <div>v{info.version} · без телеметрии</div>}
        </div>
      </aside>
      <main className="flex min-w-0 flex-1 flex-col">
        {error && (
          <div className="flex items-start gap-3 border-b border-bad/30 bg-bad/[0.08] px-5 py-2 text-xs text-[#f0bdb8]">
            <span className="flex-1">{error}</span>
            <button onClick={() => setError(null)} className="text-muted hover:text-fg">
              <X size={14} />
            </button>
          </div>
        )}
        <div key={page} className="flex min-h-0 flex-1 animate-fade-in flex-col">
          {page === "overview" && <Overview />}
          {page === "connections" && <Connections />}
          {page === "diagnostics" && <Diagnostics />}
          {page === "timeline" && <Timeline />}
          {page === "reports" && <Reports />}
          {page === "settings" && <Settings />}
        </div>
      </main>
    </div>
  );
}

function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
      <rect x="1" y="1" width="30" height="30" rx="8" fill="#161b22" stroke="#2a313a" />
      <path d="M10 21 L16 10 L22 20 Z" fill="none" stroke="#5f6b78" strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx="16" cy="10" r="4.4" fill="none" stroke="#4fb3a9" strokeOpacity=".5" strokeWidth="1" />
      <circle cx="16" cy="10" r="2.6" fill="#4fb3a9" />
      <circle cx="10" cy="21" r="2.1" fill="#d6dee6" />
      <circle cx="22" cy="20" r="2.1" fill="#d6dee6" />
    </svg>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
