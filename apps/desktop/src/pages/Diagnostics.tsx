import { Bookmark, FlaskConical, Play, Square, Stethoscope } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { ProcessIcon } from "../components/ProcessIcon";
import { Badge, Button, Card, ConfidenceBadge, Empty, Input, Notice, Segmented, Select, SourceBadge, Stat, Toggle, cx } from "../components/ui";
import { api } from "../lib/api";
import { useApp, usePolling } from "../lib/app";
import { dateTime, duration, severityLabel, sock, time } from "../lib/format";
import { useNow } from "../lib/useNow";
import type { AddressGroup, Finding, PayloadSpec, ProbeRecord, ProbeRequest, RuleInfo, Severity } from "../lib/types";

export function Diagnostics() {
  const { selectedId, selected, recordingId, setRecordingId, live, refreshSessions, setError, go } = useApp();
  const recording = !!selectedId && selectedId === recordingId;
  const now = useNow(1000, recording);
  const [marker, setMarker] = useState("");
  const [note, setNote] = useState("");
  const [stopping, setStopping] = useState(false);

  useEffect(() => setNote(selected?.meta.note ?? ""), [selected?.meta.id, selected?.meta.note]);

  async function stop() {
    setStopping(true);
    try {
      await api.stopSession();
      setRecordingId(null);
      await refreshSessions();
    } catch (e) {
      setError(e);
    } finally {
      setStopping(false);
    }
  }

  async function addMarker() {
    if (!selectedId) return;
    try {
      await api.addMarker(selectedId, marker || `Маркер ${time(Date.now())}`);
      setMarker("");
      await refreshSessions();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <PageHeader title="Диагностика" subtitle="Запись, маркеры, контрольные проверки и выводы" sessionPicker />
      {!selected ? (
        <Empty icon={<Stethoscope size={28} />} title="Нет выбранной сессии">
          Выберите приложение на странице «Обзор» и нажмите «Начать диагностику», затем воспроизведите проблему.
          <div className="mt-3">
            <Button size="sm" onClick={() => go("overview")}>
              <Play size={13} /> Выбрать приложение
            </Button>
          </div>
        </Empty>
      ) : (
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
          <Card
            title={
              <span className="flex items-center gap-2">
                <ProcessIcon path={selected.meta.target.path} size={16} />
                {selected.meta.title}
                {recording ? <Badge tone="bad">● запись</Badge> : <Badge tone={selected.meta.status === "completed" ? "ok" : "warn"}>{selected.meta.status === "completed" ? "завершена" : "прервана"}</Badge>}
              </span>
            }
            actions={
              recording && (
                <Button variant="danger" size="sm" onClick={() => void stop()} disabled={stopping}>
                  <Square size={12} /> {stopping ? "Остановка…" : "Остановить запись"}
                </Button>
              )
            }
          >
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
              <Stat label="Длительность" value={duration((selected.meta.endedAt ?? (recording ? now : selected.meta.startedAt)) - selected.meta.startedAt)} hint={`с ${dateTime(selected.meta.startedAt)}`} />
              <Stat label="Адресов" value={live?.counts.remoteAddresses ?? selected.counts.remoteAddresses} />
              <Stat label="Endpoints" value={live?.counts.endpoints ?? selected.counts.endpoints} hint={`TCP ${live?.counts.tcpEndpoints ?? selected.counts.tcpEndpoints} · UDP ${live?.counts.udpEndpoints ?? selected.counts.udpEndpoints}`} />
              <Stat label="Активно сейчас" value={recording ? (live?.counts.presentEndpoints ?? "…") : "—"} />
              <Stat label="Процессов" value={live?.counts.processes ?? selected.counts.processes} hint={recording && live ? `живых ${live.trackedAlive}` : undefined} />
              <Stat
                label="Снимков"
                value={live?.snapshotsOk ?? selected.meta.coverage.snapshotsOk}
                hint={`ошибок ${live?.snapshotsFailed ?? selected.meta.coverage.snapshotsFailed}${live ? ` · ${live.lastSnapshotMs.toFixed(0)} мс/снимок` : ""}`}
                tone={(live?.snapshotsFailed ?? selected.meta.coverage.snapshotsFailed) > 0 ? "warn" : undefined}
              />
              <Stat label="Интервал" value={`${selected.meta.settings.pollIntervalMs} мс`} hint={`макс. разрыв ${selected.meta.coverage.maxGapMs} мс`} />
            </div>
            {(live?.lastError || selected.meta.coverage.lastError) && (
              <div className="mt-3">
                <Notice tone="bad">Последняя ошибка источника: {live?.lastError ?? selected.meta.coverage.lastError}</Notice>
              </div>
            )}
            {recording && live && live.processes.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-1.5">
                {live.processes.map((p) => (
                  <Badge key={`${p.info.identity.pid}:${p.firstSeen}`} tone={p.exitedAt ? "muted" : "info"} title={p.info.path ?? undefined}>
                    {p.info.name} · {p.info.identity.pid}
                    {p.reason === "child" ? " · дочерний" : p.reason === "sameImage" ? " · тот же файл" : ""}
                    {p.exitedAt ? ` · завершён ${time(p.exitedAt)}` : ""}
                  </Badge>
                ))}
              </div>
            )}
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <div>
                <div className="mb-1.5 text-2xs uppercase tracking-wide text-faint">Маркер времени</div>
                <div className="flex gap-2">
                  <Input value={marker} onChange={(e) => setMarker(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void addMarker()} placeholder="Например: «звук пропал»" className="flex-1" />
                  <Button onClick={() => void addMarker()}>
                    <Bookmark size={13} /> Отметить
                  </Button>
                </div>
                <p className="mt-1 text-2xs text-muted">Поставьте маркер в момент, когда проблема проявилась: он появится в хронологии.</p>
              </div>
              <div>
                <div className="mb-1.5 text-2xs uppercase tracking-wide text-faint">Заметка к сессии</div>
                <textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  onBlur={() => selectedId && note !== selected.meta.note && void api.setNote(selectedId, note).then(refreshSessions).catch(setError)}
                  rows={2}
                  placeholder="Что вы делали, что ожидали, что произошло"
                  className="w-full resize-y rounded-md border border-line-strong bg-bg px-2.5 py-1.5 text-[13px] text-fg placeholder:text-faint focus:border-accent/60 focus:outline-none"
                />
              </div>
            </div>
          </Card>

          <ProbePanel sessionId={selected.meta.id} />
          <FindingsPanel sessionId={selected.meta.id} />
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------

function ProbePanel({ sessionId }: { sessionId: string }) {
  const { setError, recordingId } = useApp();
  const [kind, setKind] = useState<ProbeRequest["kind"]>("tcp");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("443");
  const [v4, setV4] = useState(true);
  const [v6, setV6] = useState(true);
  const [timeout, setTimeoutMs] = useState("3000");
  const [payload, setPayload] = useState<PayloadSpec["type"]>("stun");
  const [payloadText, setPayloadText] = useState("");
  const [running, setRunning] = useState(false);
  const [probes, setProbes] = useState<ProbeRecord[]>([]);
  const [groups, setGroups] = useState<AddressGroup[]>([]);

  const load = useCallback(async () => {
    try {
      const [p, g] = await Promise.all([api.probes(sessionId), api.groups(sessionId)]);
      setProbes(p);
      setGroups(g.filter((x) => x.remoteAddr && x.scope === "global"));
    } catch (e) {
      setError(e);
    }
  }, [sessionId, setError]);
  usePolling(load, sessionId === recordingId, 5000, [sessionId]);

  async function run() {
    setRunning(true);
    try {
      const pl: PayloadSpec | null =
        kind !== "udp" ? null : payload === "text" ? { type: "text", value: payloadText } : payload === "dnsQuery" ? { type: "dnsQuery", value: payloadText || "example.com" } : payload === "stun" ? { type: "stun" } : { type: "empty" };
      await api.runProbe({ kind, target, port: kind === "dns" ? null : Number(port), ipv4: v4, ipv6: v6, timeoutMs: Number(timeout), payload: pl, sessionId });
      await load();
    } catch (e) {
      setError(e);
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card title={<span className="flex items-center gap-2"><FlaskConical size={14} className="text-accent" /> Контрольные проверки</span>}>
      <Notice>
        Проверки выполняет сам Network Intelligence по вашему действию и только к указанной цели. Успешная проверка не означает, что анализируемое приложение тоже
        смогло подключиться, и наоборот.
      </Notice>
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <Segmented value={kind} onChange={setKind} options={[{ value: "dns", label: "DNS" }, { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }]} />
        <div className="flex flex-col">
          <label className="mb-1 text-2xs text-faint">Цель (имя или один IP)</label>
          <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="discord.com или 162.159.130.234" className="w-64 font-mono" list="observed-ips" />
          <datalist id="observed-ips">
            {groups.map((g) => (
              <option key={g.remoteAddr!} value={g.remoteAddr!}>
                порты {g.ports.join(", ")}
              </option>
            ))}
          </datalist>
        </div>
        {kind !== "dns" && (
          <div className="flex flex-col">
            <label className="mb-1 text-2xs text-faint">Порт</label>
            <Input value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, "").slice(0, 5))} className="w-20 font-mono" />
          </div>
        )}
        <div className="flex flex-col">
          <label className="mb-1 text-2xs text-faint">Тайм-аут</label>
          <Select value={timeout} onChange={setTimeoutMs}>
            {["1000", "3000", "5000", "10000"].map((t) => (
              <option key={t} value={t}>
                {Number(t) / 1000} с
              </option>
            ))}
          </Select>
        </div>
        {kind === "udp" && (
          <div className="flex flex-col">
            <label className="mb-1 text-2xs text-faint">Запрос</label>
            <Select value={payload} onChange={(v) => setPayload(v as PayloadSpec["type"])}>
              <option value="stun">STUN Binding (голос/WebRTC)</option>
              <option value="dnsQuery">DNS-запрос (порт 53)</option>
              <option value="text">Свой текст</option>
              <option value="empty">Пустая датаграмма</option>
            </Select>
          </div>
        )}
        {kind === "udp" && (payload === "text" || payload === "dnsQuery") && (
          <Input value={payloadText} onChange={(e) => setPayloadText(e.target.value)} placeholder={payload === "dnsQuery" ? "имя для запроса" : "текст ≤ 512 байт"} className="w-44" />
        )}
        <div className="flex items-center gap-3 pb-1">
          <Toggle checked={v4} onChange={setV4} label="IPv4" />
          <Toggle checked={v6} onChange={setV6} label="IPv6" />
        </div>
        <Button variant="primary" onClick={() => void run()} disabled={running || !target.trim()}>
          {running ? "Выполняется…" : "Проверить"}
        </Button>
      </div>
      <div className="mt-4 space-y-2">
        {probes.length === 0 && <div className="text-xs text-faint">Проверок в этой сессии ещё не было.</div>}
        {probes.map((p) => (
          <ProbeView key={p.id} p={p} />
        ))}
      </div>
    </Card>
  );
}

function outcomeTone(o: string): "ok" | "warn" | "bad" | "muted" {
  if (o === "connected" || o === "reply" || o === "resolved") return "ok";
  if (o === "timedOut" || o === "noReply") return "warn";
  if (o === "refused" || o === "unreachable" || o === "portUnreachable" || o === "failed") return "bad";
  return "muted";
}

const outcomeLabel: Record<string, string> = {
  connected: "соединение установлено",
  refused: "отказ (RST)",
  timedOut: "нет ответа (тайм-аут)",
  unreachable: "недоступен",
  failed: "ошибка",
  reply: "ответ получен",
  noReply: "ответа нет",
  portUnreachable: "порт закрыт (ICMP)",
  resolved: "разрешено",
};

function ProbeView({ p }: { p: ProbeRecord }) {
  const r = p.report;
  const dns = r.kind === "dns" ? r : r.dns;
  return (
    <div className="rounded-md border border-line bg-bg px-3 py-2 text-xs">
      <div className="flex items-center gap-2">
        <Badge tone="accent">{r.kind.toUpperCase()}</Badge>
        <span className="font-mono">{r.kind === "dns" ? r.name : r.target}</span>
        <SourceBadge source="active_probe" />
        <span className="ml-auto text-faint">
          {time(p.startedAt)} · {duration(p.finishedAt - p.startedAt)}
        </span>
      </div>
      {dns && (
        <div className="mt-1.5 text-muted">
          DNS (системный резолвер, {dns.elapsedMs.toFixed(0)} мс):{" "}
          {dns.outcome.outcome === "resolved" ? (
            <span className="font-mono text-fg">
              {[...dns.outcome.ipv4, ...dns.outcome.ipv6].join(", ") || "пустой ответ"}
            </span>
          ) : dns.outcome.outcome === "failed" ? (
            <span className="text-bad">{dns.outcome.error.message}</span>
          ) : (
            <span className="text-warn">нет ответа за {dns.outcome.timeoutMs} мс</span>
          )}
        </div>
      )}
      {r.kind !== "dns" && (
        <div className="mt-1.5 space-y-1">
          {r.attempts.length === 0 && <div className="text-faint">Нет адресов для проверки (DNS не дал адресов выбранных семейств).</div>}
          {r.attempts.map((a, i) => {
            const o = a.outcome;
            const err = "error" in o ? (o.error.name ?? o.error.message) : null;
            return (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <span className="w-56 truncate font-mono">{sock(a.addr, a.port)}</span>
                <Badge tone={outcomeTone(o.outcome)}>{outcomeLabel[o.outcome] ?? o.outcome}</Badge>
                {"elapsedMs" in o && <span className="font-mono text-muted">{o.elapsedMs.toFixed(1)} мс</span>}
                {"timeoutMs" in o && <span className="font-mono text-muted">{o.timeoutMs} мс</span>}
                {"bytes" in o && <span className="text-muted">{o.bytes} байт</span>}
                {err && <span className="font-mono text-faint">{err}</span>}
                {o.outcome === "noReply" && <span className="text-faint">— само по себе не означает блокировку</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

const sevTone: Record<Severity, "info" | "muted" | "warn" | "bad"> = { info: "muted", notice: "info", warning: "warn", problem: "bad" };

function FindingsPanel({ sessionId }: { sessionId: string }) {
  const { setError } = useApp();
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [showRules, setShowRules] = useState(false);

  useEffect(() => {
    setFindings(null);
    api.findings(sessionId).then((f) => setFindings(f.length ? f : null)).catch(setError);
    api.ruleCatalog().then(setRules).catch(setError);
  }, [sessionId, setError]);

  async function analyze() {
    setBusy(true);
    try {
      setFindings(await api.analyze(sessionId));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const planned = useMemo(() => rules.filter((r) => r.status === "planned"), [rules]);

  return (
    <Card
      title={<span className="flex items-center gap-2"><Stethoscope size={14} className="text-accent" /> Выводы</span>}
      actions={
        <>
          <Button size="sm" variant="ghost" onClick={() => setShowRules((v) => !v)}>
            Правила ({rules.length})
          </Button>
          <Button size="sm" onClick={() => void analyze()} disabled={busy}>
            {busy ? "Анализ…" : findings ? "Проанализировать заново" : "Проанализировать"}
          </Button>
        </>
      }
    >
      <p className="text-xs text-muted">
        Выводы разделяют наблюдения (с их достоверностью) и гипотезы о причинах (с уверенностью). Ни тайм-аут, ни RST, ни отсутствие UDP-ответа не считаются
        доказательством DPI-блокировки.
      </p>
      {showRules && (
        <div className="mt-3 grid gap-1 text-xs md:grid-cols-2">
          {rules.map((r) => (
            <div key={r.id} className="flex items-center gap-2">
              <Badge tone={r.status === "implemented" ? "ok" : "muted"}>{r.status === "implemented" ? "работает" : "запланировано"}</Badge>
              <span className={cx(r.status === "planned" && "text-faint")}>{r.title}</span>
              <span className="ml-auto font-mono text-2xs text-faint">{r.requires.join(", ")}</span>
            </div>
          ))}
        </div>
      )}
      {findings && (
        <div className="mt-3 space-y-2">
          {findings.map((f) => (
            <FindingView key={f.id} f={f} />
          ))}
        </div>
      )}
      {!findings && <div className="mt-3 text-xs text-faint">Анализ ещё не выполнялся для этой сессии.</div>}
      {planned.length > 0 && (
        <div className="mt-3 text-2xs text-faint">
          Не реализовано (нужны источники ETW/WFP или TLS-проверки): {planned.map((r) => r.title.toLowerCase()).join("; ")}.
        </div>
      )}
    </Card>
  );
}

function FindingView({ f }: { f: Finding }) {
  const [open, setOpen] = useState(f.severity === "warning" || f.severity === "problem");
  return (
    <div className="rounded-md border border-line bg-bg">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-2 px-3 py-2 text-left">
        <Badge tone={sevTone[f.severity]}>{severityLabel[f.severity]}</Badge>
        <span className="text-[13px]">{f.title}</span>
        <span className="ml-auto">
          <ConfidenceBadge c={f.confidence} label="уверенность в причине" />
        </span>
      </button>
      {open && (
        <div className="selectable space-y-2.5 border-t border-line px-3 py-2.5 text-xs">
          <Section title="Наблюдения">
            {f.observations.map((o, i) => (
              <li key={i} className="flex items-start gap-2">
                <SourceBadge source={o.source} />
                <span className="flex-1">{o.text}</span>
                <ConfidenceBadge c={o.confidence} label="достоверность" />
              </li>
            ))}
          </Section>
          {f.hypotheses.length > 0 && (
            <Section title="Возможные причины (гипотезы)">
              {f.hypotheses.map((h, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="flex-1">{h.text}</span>
                  <ConfidenceBadge c={h.confidence} />
                </li>
              ))}
            </Section>
          )}
          {f.alternativeExplanations.length > 0 && <Section title="Альтернативные объяснения">{f.alternativeExplanations.map((t, i) => <li key={i}>{t}</li>)}</Section>}
          {f.limitations.length > 0 && <Section title="Ограничения">{f.limitations.map((t, i) => <li key={i} className="text-muted">{t}</li>)}</Section>}
          {f.suggestedChecks.length > 0 && <Section title="Что проверить">{f.suggestedChecks.map((t, i) => <li key={i}>{t}</li>)}</Section>}
          {f.evidence.length > 0 && (
            <div className="font-mono text-2xs text-faint">
              доказательства: {f.evidence.map((e) => (e.type === "endpoint" ? `endpoint #${e.endpointId}` : e.type === "probe" ? `проверка ${e.probeId.slice(0, 8)}` : `${e.kind}@${e.ts}`)).join(", ")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-2xs uppercase tracking-wide text-faint">{title}</div>
      <ul className="space-y-1 pl-0.5">{children}</ul>
    </div>
  );
}
