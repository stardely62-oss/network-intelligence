import type { Confidence, DataSource, EventKind, Scope, Severity, TcpState } from "./types";

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

export function time(ms: number | null | undefined, withMs = false): string {
  if (ms == null) return "—";
  const d = new Date(ms);
  const base = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return withMs ? `${base}.${pad(d.getMilliseconds(), 3)}` : base;
}

export function dateTime(ms: number | null | undefined): string {
  if (ms == null) return "—";
  const d = new Date(ms);
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${time(ms)}`;
}

export function duration(ms: number | null | undefined): string {
  if (ms == null || !isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} мс`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${(ms / 1000).toFixed(1)} с`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} мин ${pad(s % 60)} с`;
  return `${Math.floor(m / 60)} ч ${pad(m % 60)} мин`;
}

export function offset(ms: number, start: number): string {
  const d = (ms - start) / 1000;
  return `${d >= 0 ? "+" : "−"}${Math.abs(d).toFixed(1)} с`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
  return `${(n / 1024 / 1024).toFixed(1)} МБ`;
}

/** "1.2.3.4:443" / "[2001:db8::1]:443"; port optional. */
export function sock(addr: string | null, port: number | null | undefined): string {
  if (!addr) return "—";
  const a = addr.includes(":") ? `[${addr}]` : addr;
  return port == null ? addr : `${a}:${port}`;
}

export const scopeLabel: Record<Scope, string> = {
  unspecified: "не задан",
  loopback: "loopback",
  private: "частная сеть",
  sharedCgnat: "CGNAT",
  linkLocal: "link-local",
  multicast: "multicast",
  broadcast: "broadcast",
  documentation: "документационный",
  global: "интернет",
};

export const sourceLabel: Record<DataSource, string> = {
  observed_process: "процесс",
  active_probe: "проверка NI",
  system_snapshot: "снимок системы",
  etw: "ETW",
  user: "пользователь",
};

export const confidenceLabel: Record<Confidence, string> = {
  veryLow: "очень низкая",
  low: "низкая",
  medium: "средняя",
  high: "высокая",
};

export const severityLabel: Record<Severity, string> = {
  info: "сведения",
  notice: "замечание",
  warning: "предупреждение",
  problem: "проблема",
};

export function stateTone(s: TcpState | null): "ok" | "warn" | "bad" | "muted" | "info" {
  switch (s) {
    case "ESTABLISHED":
      return "ok";
    case "SYN_SENT":
    case "SYN_RCVD":
      return "warn";
    case "LISTEN":
      return "info";
    case null:
      return "muted";
    default:
      return "muted";
  }
}

export const eventKindLabel: Record<EventKind["type"], string> = {
  sessionStarted: "Начало записи",
  sessionStopped: "Конец записи",
  processTracked: "Процесс отслеживается",
  processExited: "Процесс завершился",
  pidReused: "PID переиспользован",
  endpointAppeared: "Endpoint появился",
  endpointStateChanged: "Смена состояния",
  endpointDisappeared: "Endpoint исчез",
  sourceError: "Ошибка источника",
  probeStarted: "Проверка начата",
  probeFinished: "Проверка завершена",
  userMarker: "Маркер",
};

/** snake_case names used by the storage filter. */
export const eventKindFilterName: Record<EventKind["type"], string> = {
  sessionStarted: "session_started",
  sessionStopped: "session_stopped",
  processTracked: "process_tracked",
  processExited: "process_exited",
  pidReused: "pid_reused",
  endpointAppeared: "endpoint_appeared",
  endpointStateChanged: "endpoint_state_changed",
  endpointDisappeared: "endpoint_disappeared",
  sourceError: "source_error",
  probeStarted: "probe_started",
  probeFinished: "probe_finished",
  userMarker: "user_marker",
};

export function describeEvent(k: EventKind): string {
  switch (k.type) {
    case "sessionStarted":
      return "Запись начата";
    case "sessionStopped":
      return `Запись остановлена (${k.reason === "user" ? "пользователем" : k.reason})`;
    case "processTracked":
      return `${k.name}, PID ${k.identity.pid} — ${k.reason === "root" ? "выбранный процесс" : k.reason === "child" ? "дочерний процесс" : "тот же исполняемый файл"}`;
    case "processExited":
      return `PID ${k.identity.pid} отсутствует в списке процессов (последний раз виден в ${time(k.lastSeen, true)})`;
    case "pidReused":
      return `PID ${k.old.pid} теперь принадлежит другому процессу (${k.newName}); он не объединяется с исходным`;
    case "endpointAppeared":
      return `${k.endpoint.protocol.toUpperCase()} ${sock(k.endpoint.localAddr, k.endpoint.localPort)} → ${k.endpoint.remoteAddr ? sock(k.endpoint.remoteAddr, k.endpoint.remotePort) : "без удалённого адреса"}${k.state ? ` · ${k.state}` : ""}${k.episode > 1 ? ` · эпизод ${k.episode}` : ""}`;
    case "endpointStateChanged":
      return `${sock(k.endpoint.remoteAddr ?? k.endpoint.localAddr, k.endpoint.remotePort ?? k.endpoint.localPort)}: ${k.from} → ${k.to}`;
    case "endpointDisappeared":
      return `${k.endpoint.protocol.toUpperCase()} ${k.endpoint.remoteAddr ? sock(k.endpoint.remoteAddr, k.endpoint.remotePort) : sock(k.endpoint.localAddr, k.endpoint.localPort)} нет в снимке; последний раз в ${time(k.lastSeen, true)}${k.lastState ? ` (${k.lastState})` : ""}`;
    case "sourceError":
      return `${k.component}: ${k.message}`;
    case "probeStarted":
      return `${k.kind.toUpperCase()} → ${k.target}`;
    case "probeFinished":
      return `${k.kind.toUpperCase()} → ${k.target}: ${k.summary}`;
    case "userMarker":
      return k.label;
  }
}

/** Rows whose text fields contain every whitespace-separated term. */
export function matchesQuery(fields: (string | number | null | undefined)[], query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = fields
    .filter((f) => f != null)
    .join(" ")
    .toLowerCase();
  return terms.every((t) => hay.includes(t));
}

/** Numeric-aware comparison of IP strings (IPv4 before IPv6). */
export function compareIp(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  const v4 = (s: string) => /^\d+\.\d+\.\d+\.\d+$/.test(s);
  if (v4(a) && v4(b)) {
    const pa = a.split(".").map(Number);
    const pb = b.split(".").map(Number);
    for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
    return 0;
  }
  if (v4(a)) return -1;
  if (v4(b)) return 1;
  return a.localeCompare(b);
}
