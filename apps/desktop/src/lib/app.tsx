import { listen } from "@tauri-apps/api/event";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, errorText, inTauri } from "./api";
import type { AppInfo, AppSettings, LiveStatus, SessionSummary } from "./types";

export type Page = "overview" | "connections" | "diagnostics" | "timeline" | "reports" | "settings";

interface Ctx {
  page: Page;
  go: (p: Page) => void;
  info: AppInfo | null;
  settings: AppSettings | null;
  saveSettings: (s: AppSettings) => Promise<void>;
  sessions: SessionSummary[];
  refreshSessions: () => Promise<void>;
  selectedId: string | null;
  select: (id: string | null) => void;
  selected: SessionSummary | null;
  /** Live status of the recording session (throttled to ~1/s by the backend). */
  live: LiveStatus | null;
  recordingId: string | null;
  setRecordingId: (id: string | null) => void;
  error: string | null;
  setError: (e: unknown) => void;
}

const AppCtx = createContext<Ctx | null>(null);

export function useApp(): Ctx {
  const c = useContext(AppCtx);
  if (!c) throw new Error("AppProvider missing");
  return c;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [page, setPage] = useState<Page>("overview");
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [live, setLive] = useState<LiveStatus | null>(null);
  const [recordingId, setRecordingId] = useState<string | null>(null);
  const [error, setErr] = useState<string | null>(null);

  const setError = useCallback((e: unknown) => setErr(e == null ? null : errorText(e)), []);

  const refreshSessions = useCallback(async () => {
    try {
      setSessions(await api.listSessions());
    } catch (e) {
      setError(e);
    }
  }, [setError]);

  useEffect(() => {
    if (!inTauri) {
      setErr("Интерфейс открыт вне приложения Network Intelligence — данных нет.");
      return;
    }
    void (async () => {
      try {
        const [i, s] = await Promise.all([api.appInfo(), api.getSettings()]);
        setInfo(i);
        setSettings(s);
        setRecordingId(i.activeSession);
        if (i.activeSession) setSelectedId(i.activeSession);
        await refreshSessions();
      } catch (e) {
        setError(e);
      }
    })();
    const un = listen<LiveStatus>("live-status", (e) => setLive(e.payload));
    return () => {
      void un.then((f) => f());
    };
  }, [refreshSessions, setError]);

  // Session list counters are refreshed while recording, at a low rate.
  useEffect(() => {
    if (!recordingId) return;
    const t = setInterval(() => void refreshSessions(), 3000);
    return () => clearInterval(t);
  }, [recordingId, refreshSessions]);

  const saveSettings = useCallback(
    async (s: AppSettings) => {
      try {
        setSettings(await api.setSettings(s));
      } catch (e) {
        setError(e);
      }
    },
    [setError],
  );

  const selected = useMemo(() => sessions.find((s) => s.meta.id === selectedId) ?? null, [sessions, selectedId]);

  const value: Ctx = {
    page,
    go: setPage,
    info,
    settings,
    saveSettings,
    sessions,
    refreshSessions,
    selectedId,
    select: setSelectedId,
    selected,
    live: live && live.sessionId === recordingId ? live : null,
    recordingId,
    setRecordingId,
    error,
    setError,
  };
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}

/** Re-runs `load` on mount, when deps change, and every `ms` while `active`. */
export function usePolling(load: () => void | Promise<void>, active: boolean, ms: number, deps: unknown[]) {
  useEffect(() => {
    void load();
    if (!active) return;
    let busy = false;
    const t = setInterval(async () => {
      if (busy || document.hidden) return;
      busy = true;
      try {
        await load();
      } finally {
        busy = false;
      }
    }, ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, ms, ...deps]);
}
