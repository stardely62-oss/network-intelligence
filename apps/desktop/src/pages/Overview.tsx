import { Play, RefreshCw, Search } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { ProcessIcon } from "../components/ProcessIcon";
import { Badge, Button, Card, CopyButton, Empty, Input, Notice, Segmented, Select, Toggle, cx } from "../components/ui";
import { VirtualTable, type Column } from "../components/VirtualTable";
import { api } from "../lib/api";
import { useApp, usePolling } from "../lib/app";
import { dateTime, matchesQuery } from "../lib/format";
import type { ProcessList, ProcessRow, SessionSettings } from "../lib/types";

/** All processes of one executable, so multi-process apps show as one row. */
interface AppGroup {
  key: string;
  name: string;
  path: string | null;
  procs: ProcessRow[];
  root: ProcessRow;
  tcp: number;
  est: number;
  syn: number;
  listen: number;
  udp: number;
  denied: boolean;
}

function groupApps(list: ProcessRow[]): AppGroup[] {
  const m = new Map<string, ProcessRow[]>();
  for (const p of list) {
    const k = (p.path ?? p.name).toLowerCase();
    const arr = m.get(k);
    if (arr) arr.push(p);
    else m.set(k, [p]);
  }
  return [...m.entries()].map(([key, procs]) => {
    const pids = new Set(procs.map((p) => p.pid));
    // Root: a process whose parent is not part of the group; oldest first.
    const roots = procs.filter((p) => p.parentPid == null || !pids.has(p.parentPid));
    const root = [...(roots.length ? roots : procs)].sort((a, b) => (a.createdAt ?? 0) - (b.createdAt ?? 0))[0];
    const sum = (f: (p: ProcessRow) => number) => procs.reduce((s, p) => s + f(p), 0);
    return {
      key,
      name: root.name,
      path: root.path,
      procs,
      root,
      tcp: sum((p) => p.tcp),
      est: sum((p) => p.tcpEstablished),
      syn: sum((p) => p.tcpSynSent),
      listen: sum((p) => p.tcpListen),
      udp: sum((p) => p.udp),
      denied: procs.every((p) => p.access !== "full"),
    };
  });
}

function accessBadge(a: ProcessRow["access"]) {
  if (a === "full") return <Badge tone="ok">доступен</Badge>;
  if (a === "system") return <Badge>системный</Badge>;
  return (
    <Badge tone="warn" title="Процесс не удалось открыть без прав администратора: путь и время создания недоступны, идентичность — только по PID">
      ограничено правами
    </Badge>
  );
}

export function Overview() {
  const { settings, recordingId, setRecordingId, select, refreshSessions, go, setError, info } = useApp();
  const [data, setData] = useState<ProcessList | null>(null);
  const [q, setQ] = useState("");
  const [onlyNet, setOnlyNet] = useState(true);
  const [mode, setMode] = useState<"apps" | "procs">("apps");
  const [auto, setAuto] = useState(true);
  const [sel, setSel] = useState<string | null>(null);
  const [opts, setOpts] = useState<SessionSettings | null>(null);
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.listProcesses());
    } catch (e) {
      setError(e);
    }
  }, [setError]);
  usePolling(load, auto, 3000, []);

  const groups = useMemo(() => groupApps(data?.processes ?? []), [data]);
  const shownGroups = useMemo(
    () => groups.filter((g) => (!onlyNet || g.tcp + g.udp > 0) && matchesQuery([g.name, g.path, ...g.procs.map((p) => p.pid)], q)),
    [groups, onlyNet, q],
  );
  const shownProcs = useMemo(
    () => (data?.processes ?? []).filter((p) => (!onlyNet || p.tcp + p.udp > 0) && matchesQuery([p.name, p.path, p.pid], q)),
    [data, onlyNet, q],
  );

  const selGroup = mode === "apps" ? groups.find((g) => g.key === sel) : undefined;
  const selProc = mode === "procs" ? data?.processes.find((p) => `${p.pid}:${p.createdKey}` === sel) : selGroup?.root;
  const effOpts = opts ?? settings?.session ?? null;

  async function start() {
    if (!selProc || !effOpts) return;
    setStarting(true);
    try {
      const m = await api.startSession(selProc.pid, selProc.createdKey, effOpts);
      setRecordingId(m.id);
      select(m.id);
      await refreshSessions();
      go("diagnostics");
    } catch (e) {
      setError(e);
    } finally {
      setStarting(false);
    }
  }

  const netCols = {
    tcp: (r: { tcp: number; est: number; syn: number; listen: number }) => (
      <span className="font-mono">
        {r.tcp}
        {r.tcp > 0 && (
          <span className="text-faint">
            {" "}
            · <span className="text-ok">{r.est}</span>
            {r.syn > 0 && <span className="text-warn"> · {r.syn} syn</span>}
            {r.listen > 0 && <span> · {r.listen} L</span>}
          </span>
        )}
      </span>
    ),
  };

  const appColumns: Column<AppGroup>[] = [
    {
      key: "name",
      header: "Приложение",
      width: "minmax(220px,1.3fr)",
      sort: (a, b) => a.name.localeCompare(b.name),
      cell: (g) => (
        <span className="flex items-center gap-2">
          <ProcessIcon path={g.path} denied={g.denied} />
          <span className="truncate">{g.name}</span>
          {g.procs.length > 1 && <Badge>×{g.procs.length}</Badge>}
        </span>
      ),
    },
    { key: "pid", header: "PID", width: "80px", sort: (a, b) => a.root.pid - b.root.pid, cell: (g) => <span className="font-mono text-muted">{g.root.pid}</span> },
    {
      key: "tcp",
      header: "TCP · уст.",
      width: "150px",
      title: "Всего TCP endpoints · из них ESTABLISHED · SYN_SENT · LISTEN",
      sort: (a, b) => a.tcp - b.tcp,
      cell: (g) => netCols.tcp(g),
    },
    { key: "udp", header: "UDP", width: "64px", title: "Локальные UDP-привязки (без удалённого адреса)", sort: (a, b) => a.udp - b.udp, cell: (g) => <span className="font-mono">{g.udp}</span> },
    { key: "acc", header: "Доступ", width: "150px", cell: (g) => accessBadge(g.root.access) },
    { key: "path", header: "Путь", width: "minmax(200px,2fr)", cell: (g) => <span className="text-muted">{g.path ?? "—"}</span> },
  ];

  const procColumns: Column<ProcessRow>[] = [
    {
      key: "name",
      header: "Процесс",
      width: "minmax(200px,1.2fr)",
      sort: (a, b) => a.name.localeCompare(b.name),
      cell: (p) => (
        <span className="flex items-center gap-2">
          <ProcessIcon path={p.path} denied={p.access !== "full"} />
          <span className="truncate">{p.name}</span>
        </span>
      ),
    },
    { key: "pid", header: "PID", width: "80px", sort: (a, b) => a.pid - b.pid, cell: (p) => <span className="font-mono text-muted">{p.pid}</span> },
    { key: "ppid", header: "Родитель", width: "80px", cell: (p) => <span className="font-mono text-faint">{p.parentPid ?? "—"}</span> },
    {
      key: "tcp",
      header: "TCP · уст.",
      width: "150px",
      sort: (a, b) => a.tcp - b.tcp,
      cell: (p) => netCols.tcp({ tcp: p.tcp, est: p.tcpEstablished, syn: p.tcpSynSent, listen: p.tcpListen }),
    },
    { key: "udp", header: "UDP", width: "64px", sort: (a, b) => a.udp - b.udp, cell: (p) => <span className="font-mono">{p.udp}</span> },
    { key: "acc", header: "Доступ", width: "150px", cell: (p) => accessBadge(p.access) },
    { key: "path", header: "Путь", width: "minmax(200px,2fr)", cell: (p) => <span className="text-muted">{p.path ?? "—"}</span> },
  ];

  const errors = [data?.processError, data?.tcpError, data?.udpError].filter(Boolean);

  return (
    <>
      <PageHeader
        title="Обзор"
        subtitle="Выберите приложение и начните диагностическую сессию. Списки обновляются снимками каждые 3 с."
        actions={
          <div className="flex items-center gap-2">
            <Toggle checked={auto} onChange={setAuto} label="Автообновление" />
            <Button size="sm" variant="ghost" onClick={() => void load()} title="Обновить сейчас">
              <RefreshCw size={14} />
            </Button>
          </div>
        }
      />
      {info && !info.collectorAvailable && (
        <div className="px-5 pt-3">
          <Notice tone="bad">Сбор данных на этой платформе недоступен: Network Intelligence работает только в Windows.</Notice>
        </div>
      )}
      {errors.length > 0 && (
        <div className="px-5 pt-3">
          <Notice tone="bad">Источник данных вернул ошибку: {errors.join("; ")}</Notice>
        </div>
      )}
      <div className="flex min-h-0 flex-1 gap-4 p-5">
        <Card className="flex min-h-0 min-w-0 flex-1 flex-col" pad={false}>
          <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
            <div className="relative">
              <Search size={14} className="pointer-events-none absolute left-2.5 top-2 text-faint" />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Имя, путь или PID" className="w-64 pl-8" />
            </div>
            <Segmented
              value={mode}
              onChange={(v) => {
                setMode(v);
                setSel(null);
              }}
              options={[
                { value: "apps", label: "Приложения" },
                { value: "procs", label: "Процессы" },
              ]}
            />
            <Toggle checked={onlyNet} onChange={setOnlyNet} label="Только с сетевой активностью" />
            <span className="ml-auto text-2xs text-faint">
              {mode === "apps" ? `${shownGroups.length} из ${groups.length}` : `${shownProcs.length} из ${data?.processes.length ?? 0}`}
            </span>
          </div>
          {mode === "apps" ? (
            <VirtualTable
              rows={shownGroups}
              columns={appColumns}
              rowKey={(g) => g.key}
              selectedKey={sel}
              onRowClick={(g) => setSel(g.key)}
              defaultSort={{ key: "tcp", dir: -1 }}
              empty={<Empty title={data ? "Нет подходящих приложений" : "Загрузка списка процессов…"} />}
            />
          ) : (
            <VirtualTable
              rows={shownProcs}
              columns={procColumns}
              rowKey={(p) => `${p.pid}:${p.createdKey}`}
              selectedKey={sel}
              onRowClick={(p) => setSel(`${p.pid}:${p.createdKey}`)}
              defaultSort={{ key: "tcp", dir: -1 }}
              empty={<Empty title={data ? "Нет подходящих процессов" : "Загрузка списка процессов…"} />}
            />
          )}
        </Card>

        <div className="flex w-[340px] shrink-0 flex-col gap-4 overflow-y-auto">
          {!selProc ? (
            <Card>
              <Empty title="Приложение не выбрано">Выберите строку в таблице, чтобы увидеть сведения и начать запись.</Empty>
            </Card>
          ) : (
            <>
              <Card title="Выбрано">
                <div className="flex items-center gap-3">
                  <ProcessIcon path={selProc.path} denied={selProc.access !== "full"} size={32} />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">{selProc.name}</div>
                    <div className="text-xs text-muted">
                      PID <span className="font-mono">{selProc.pid}</span>
                      {selGroup && selGroup.procs.length > 1 && ` · ещё ${selGroup.procs.length - 1} процесс(ов) с тем же файлом`}
                    </div>
                  </div>
                </div>
                <dl className="selectable mt-3 grid grid-cols-[96px_1fr] gap-x-3 gap-y-1.5 text-xs">
                  <dt className="text-faint">Путь</dt>
                  <dd className="group flex min-w-0 items-start gap-1 break-all text-muted">
                    {selProc.path ?? "недоступен"} {selProc.path && <CopyButton text={selProc.path} />}
                  </dd>
                  <dt className="text-faint">Запущен</dt>
                  <dd>{dateTime(selProc.createdAt)}</dd>
                  <dt className="text-faint">Родитель</dt>
                  <dd className="font-mono">{selProc.parentPid ?? "—"}</dd>
                  <dt className="text-faint">Доступ</dt>
                  <dd>{accessBadge(selProc.access)}</dd>
                  <dt className="text-faint">Сейчас</dt>
                  <dd>
                    TCP {selGroup ? selGroup.tcp : selProc.tcp}, UDP {selGroup ? selGroup.udp : selProc.udp}
                  </dd>
                </dl>
                {selProc.access !== "full" && (
                  <div className="mt-3">
                    <Notice tone="warn">
                      Время создания процесса недоступно без прав администратора. Сессия будет идентифицировать процесс только по PID, повторное использование PID
                      нельзя будет исключить.
                    </Notice>
                  </div>
                )}
              </Card>
              {effOpts && (
                <Card title="Параметры записи">
                  <Toggle checked={effOpts.includeChildren} onChange={(v) => setOpts({ ...effOpts, includeChildren: v })} label="Дочерние процессы" hint="Процессы, запущенные выбранным (проверяется время создания)" />
                  <Toggle
                    checked={effOpts.includeSameImage}
                    onChange={(v) => setOpts({ ...effOpts, includeSameImage: v })}
                    label="Все процессы этого файла"
                    hint="Для многопроцессных приложений и перезапусков"
                  />
                  <Toggle checked={effOpts.includeListeners} onChange={(v) => setOpts({ ...effOpts, includeListeners: v })} label="Слушающие сокеты (LISTEN)" />
                  <div className="mt-2 flex items-center justify-between gap-2 text-[13px]">
                    <span>Интервал снимков</span>
                    <Select value={String(effOpts.pollIntervalMs)} onChange={(v) => setOpts({ ...effOpts, pollIntervalMs: Number(v) })}>
                      {[250, 500, 1000, 2000, 5000].map((v) => (
                        <option key={v} value={v}>
                          {v} мс
                        </option>
                      ))}
                    </Select>
                  </div>
                  <p className="mt-2 text-2xs leading-4 text-muted">
                    Соединения, которые открываются и закрываются быстрее интервала, могут не попасть ни в один снимок.
                  </p>
                  <Button variant="primary" className={cx("mt-3 w-full")} disabled={!!recordingId || starting || info?.collectorAvailable === false} onClick={() => void start()}>
                    <Play size={14} /> {recordingId ? "Уже идёт запись" : starting ? "Запуск…" : "Начать диагностику"}
                  </Button>
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
