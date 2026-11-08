import { invoke } from "@tauri-apps/api/core";
import type {
  AddressGroup,
  AppInfo,
  AppSettings,
  EndpointRecord,
  EventFilter,
  EventPage,
  ExportOptions,
  Finding,
  LiveStatus,
  ProbeRecord,
  ProbeRequest,
  ProcessList,
  RuleInfo,
  SessionMeta,
  SessionSettings,
  SessionSummary,
  SnapshotRow,
  TrackedProcess,
} from "./types";

/** Whether the page runs inside the Tauri shell (false in a plain browser). */
export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri) {
    return Promise.reject(new Error("Интерфейс запущен вне приложения: данные доступны только в Network Intelligence для Windows."));
  }
  return invoke<T>(cmd, args);
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),
  listProcesses: () => call<ProcessList>("list_processes"),
  processIcon: (path: string) => call<string | null>("process_icon", { path }),
  startSession: (pid: number, createdKey: string | null, settings: SessionSettings) =>
    call<SessionMeta>("start_session", { req: { pid, createdKey, settings } }),
  stopSession: () => call<SessionMeta | null>("stop_session"),
  liveStatus: () => call<LiveStatus | null>("live_status"),
  addMarker: (sessionId: string, label: string) => call<void>("add_marker", { sessionId, label }),
  setNote: (sessionId: string, note: string) => call<void>("set_note", { sessionId, note }),
  renameSession: (sessionId: string, title: string) => call<void>("rename_session", { sessionId, title }),
  listSessions: () => call<SessionSummary[]>("list_sessions"),
  getSession: (sessionId: string) => call<SessionSummary>("get_session", { sessionId }),
  deleteSession: (sessionId: string) => call<void>("delete_session", { sessionId }),
  deleteAllHistory: () => call<void>("delete_all_history"),
  groups: (sessionId: string) => call<AddressGroup[]>("session_groups", { sessionId }),
  endpoints: (sessionId: string) => call<EndpointRecord[]>("session_endpoints", { sessionId }),
  events: (sessionId: string, filter: EventFilter) => call<EventPage>("session_events", { sessionId, filter }),
  snapshots: (sessionId: string) => call<SnapshotRow[]>("session_snapshots", { sessionId }),
  processes: (sessionId: string) => call<TrackedProcess[]>("session_processes", { sessionId }),
  probes: (sessionId: string | null) => call<ProbeRecord[]>("session_probes", { sessionId }),
  runProbe: (req: ProbeRequest) => call<ProbeRecord>("run_probe", { req }),
  analyze: (sessionId: string) => call<Finding[]>("analyze_session", { sessionId }),
  findings: (sessionId: string) => call<Finding[]>("session_findings", { sessionId }),
  ruleCatalog: () => call<RuleInfo[]>("rule_catalog"),
  exportSession: (sessionId: string, options: ExportOptions, path: string) =>
    call<{ path: string; bytes: number }>("export_session", { sessionId, options, path }),
  getSettings: () => call<AppSettings>("get_settings"),
  setSettings: (settings: AppSettings) => call<AppSettings>("set_settings", { settings }),
};

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e);
}
