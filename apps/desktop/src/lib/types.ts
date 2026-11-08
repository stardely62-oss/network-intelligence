// Mirrors of the Rust serde shapes (camelCase). Keep in sync with ni-core.

export type Family = "ipv4" | "ipv6";
export type Protocol = "tcp" | "udp";
export type Scope =
  | "unspecified"
  | "loopback"
  | "private"
  | "sharedCgnat"
  | "linkLocal"
  | "multicast"
  | "broadcast"
  | "documentation"
  | "global";
export type DataSource = "observed_process" | "active_probe" | "system_snapshot" | "etw" | "user";
export type ProcessAccess = "full" | "denied" | "system";

export interface ProcessIdentity {
  pid: number;
  created: number | null;
}

export interface ProcessRow {
  pid: number;
  createdKey: string | null;
  createdAt: number | null;
  parentPid: number | null;
  name: string;
  path: string | null;
  access: ProcessAccess;
  threads: number;
  tcp: number;
  tcpEstablished: number;
  tcpListen: number;
  tcpSynSent: number;
  udp: number;
}

export interface ProcessList {
  ts: number;
  processes: ProcessRow[];
  processError: string | null;
  tcpError: string | null;
  udpError: string | null;
}

export interface ProcessInfo {
  identity: ProcessIdentity;
  parentPid: number | null;
  name: string;
  path: string | null;
  access: ProcessAccess;
  threads: number;
  createdAt: number | null;
}

export interface TrackedProcess {
  info: ProcessInfo;
  reason: "root" | "child" | "sameImage";
  firstSeen: number;
  lastSeen: number;
  exitedAt: number | null;
}

export interface TargetSpec {
  root: ProcessIdentity;
  name: string;
  path: string | null;
  includeChildren: boolean;
  includeSameImage: boolean;
}

export interface SessionSettings {
  pollIntervalMs: number;
  includeChildren: boolean;
  includeSameImage: boolean;
  includeListeners: boolean;
}

export interface Coverage {
  provider: string;
  pollIntervalMs: number;
  snapshotsOk: number;
  snapshotsFailed: number;
  maxGapMs: number;
  pidOnlyIdentities: number;
  tcpAvailable: boolean;
  udpAvailable: boolean;
  etwAvailable: boolean;
  limitations: string[];
  lastError: string | null;
}

export type SessionStatus = "recording" | "completed" | "interrupted";

export interface SessionMeta {
  id: string;
  schema: number;
  title: string;
  startedAt: number;
  endedAt: number | null;
  status: SessionStatus;
  target: TargetSpec;
  settings: SessionSettings;
  coverage: Coverage;
  note: string;
  appVersion: string;
}

export interface SessionCounts {
  endpoints: number;
  tcpEndpoints: number;
  udpEndpoints: number;
  presentEndpoints: number;
  remoteAddresses: number;
  events: number;
  processes: number;
  probes: number;
}

export interface SessionSummary {
  meta: SessionMeta;
  counts: SessionCounts;
}

export interface LiveStatus {
  sessionId: string;
  ts: number;
  snapshotsOk: number;
  snapshotsFailed: number;
  lastSnapshotMs: number;
  trackedAlive: number;
  processes: TrackedProcess[];
  counts: SessionCounts;
  lastError: string | null;
  running: boolean;
}

export type TcpState =
  | "CLOSED"
  | "LISTEN"
  | "SYN_SENT"
  | "SYN_RCVD"
  | "ESTABLISHED"
  | "FIN_WAIT_1"
  | "FIN_WAIT_2"
  | "CLOSE_WAIT"
  | "CLOSING"
  | "LAST_ACK"
  | "TIME_WAIT"
  | "DELETE_TCB"
  | "UNKNOWN";

export interface EndpointKey {
  protocol: Protocol;
  localAddr: string;
  localPort: number;
  remoteAddr: string | null;
  remotePort: number | null;
  process: ProcessIdentity;
}

export interface EndpointRecord {
  id: number;
  key: EndpointKey;
  socketFamily: Family;
  remoteFamily: Family | null;
  remoteScope: Scope | null;
  state: TcpState | null;
  statesSeen: TcpState[];
  firstSeen: number;
  lastSeen: number;
  observations: number;
  episodes: number;
  present: boolean;
  goneAt: number | null;
  socketCreatedAt: number | null;
  source: DataSource;
  confidence: "high" | "medium";
  snapshotsInState: number;
  stateSince: number;
}

export interface AddressGroup {
  remoteAddr: string | null;
  family: Family | null;
  scope: Scope | null;
  endpoints: number;
  tcp: number;
  udp: number;
  ports: number[];
  pids: number[];
  states: TcpState[];
  firstSeen: number;
  lastSeen: number;
  observations: number;
  episodes: number;
  present: number;
}

export interface EndpointRef {
  endpointId: number;
  protocol: Protocol;
  pid: number;
  localAddr: string;
  localPort: number;
  remoteAddr: string | null;
  remotePort: number | null;
}

export type EventKind =
  | { type: "sessionStarted" }
  | { type: "sessionStopped"; reason: string }
  | { type: "processTracked"; identity: ProcessIdentity; name: string; path: string | null; reason: TrackedProcess["reason"] }
  | { type: "processExited"; identity: ProcessIdentity; lastSeen: number }
  | { type: "pidReused"; old: ProcessIdentity; new: ProcessIdentity; newName: string }
  | { type: "endpointAppeared"; endpoint: EndpointRef; state: TcpState | null; episode: number; socketCreatedAt: number | null }
  | { type: "endpointStateChanged"; endpoint: EndpointRef; from: TcpState; to: TcpState }
  | { type: "endpointDisappeared"; endpoint: EndpointRef; lastSeen: number; lastState: TcpState | null }
  | { type: "sourceError"; component: string; message: string }
  | { type: "probeStarted"; probeId: string; kind: string; target: string }
  | { type: "probeFinished"; probeId: string; kind: string; target: string; summary: string; ok: boolean }
  | { type: "userMarker"; label: string };

export interface StoredEvent {
  id: number;
  ts: number;
  source: DataSource;
  kind: EventKind;
}

export interface EventFilter {
  kinds?: string[];
  protocol?: string | null;
  addr?: string | null;
  pid?: number | null;
  from?: number | null;
  to?: number | null;
  sources?: string[];
  limit?: number;
  offset?: number;
}

export interface EventPage {
  total: number;
  events: StoredEvent[];
}

export interface SnapshotRow {
  ts: number;
  durationMs: number;
  ok: boolean;
  tcpRows: number;
  udpRows: number;
  attributed: number;
  error: string | null;
}

export interface OsError {
  code: number | null;
  name: string | null;
  message: string;
}

export type TcpOutcome =
  | { outcome: "connected"; elapsedMs: number; local: string }
  | { outcome: "refused"; elapsedMs: number; error: OsError }
  | { outcome: "timedOut"; timeoutMs: number }
  | { outcome: "unreachable"; elapsedMs: number; error: OsError }
  | { outcome: "failed"; elapsedMs: number; error: OsError };

export type UdpOutcome =
  | { outcome: "reply"; elapsedMs: number; bytes: number }
  | { outcome: "noReply"; timeoutMs: number }
  | { outcome: "portUnreachable"; elapsedMs: number; error: OsError }
  | { outcome: "failed"; error: OsError };

export type DnsOutcome =
  | { outcome: "resolved"; ipv4: string[]; ipv6: string[] }
  | { outcome: "failed"; error: OsError }
  | { outcome: "timedOut"; timeoutMs: number };

export interface DnsResult {
  name: string;
  resolver: string;
  elapsedMs: number;
  outcome: DnsOutcome;
}

export interface TcpAttempt {
  addr: string;
  family: Family;
  port: number;
  startedAt: number;
  outcome: TcpOutcome;
}

export interface UdpAttempt {
  addr: string;
  family: Family;
  port: number;
  payloadLen: number;
  startedAt: number;
  outcome: UdpOutcome;
}

export type ProbeReport =
  | ({ kind: "dns" } & DnsResult)
  | { kind: "tcp"; target: string; dns: DnsResult | null; attempts: TcpAttempt[] }
  | { kind: "udp"; target: string; dns: DnsResult | null; attempts: UdpAttempt[] };

export interface ProbeRecord {
  id: string;
  sessionId: string | null;
  startedAt: number;
  finishedAt: number;
  report: ProbeReport;
}

export type PayloadSpec =
  | { type: "empty" }
  | { type: "text"; value: string }
  | { type: "dnsQuery"; value: string }
  | { type: "stun" };

export interface ProbeRequest {
  kind: "dns" | "tcp" | "udp";
  target: string;
  port: number | null;
  ipv4: boolean;
  ipv6: boolean;
  timeoutMs: number;
  payload: PayloadSpec | null;
  sessionId: string | null;
}

export type Confidence = "veryLow" | "low" | "medium" | "high";
export type Severity = "info" | "notice" | "warning" | "problem";

export interface Finding {
  id: string;
  rule: string;
  category: string;
  severity: Severity;
  title: string;
  observations: { text: string; confidence: Confidence; source: DataSource }[];
  evidence: ({ type: "endpoint"; endpointId: number } | { type: "probe"; probeId: string } | { type: "event"; ts: number; kind: string })[];
  hypotheses: { text: string; confidence: Confidence }[];
  alternativeExplanations: string[];
  confidence: Confidence;
  limitations: string[];
  suggestedChecks: string[];
}

export interface RuleInfo {
  id: string;
  category: string;
  title: string;
  status: "implemented" | "planned";
  requires: string[];
}

export interface ExportOptions {
  redactPrivateIps: boolean;
  redactLocalAddresses: boolean;
  redactPaths: boolean;
  includeNotes: boolean;
  includeEvents: boolean;
}

export interface AppSettings {
  session: SessionSettings;
  retentionDays: number;
  export: ExportOptions;
}

export interface AppInfo {
  version: string;
  platform: string;
  elevated: boolean | null;
  dataDir: string;
  dbSize: number;
  provider: string;
  collectorAvailable: boolean;
  activeSession: string | null;
}
