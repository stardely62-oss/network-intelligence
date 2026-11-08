import { Cable, Search, X } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { Badge, Button, Card, CopyButton, Empty, Input, Segmented, SourceBadge, Toggle } from "../components/ui";
import { VirtualTable, type Column } from "../components/VirtualTable";
import { api } from "../lib/api";
import { useApp, usePolling } from "../lib/app";
import { compareIp, dateTime, duration, matchesQuery, scopeLabel, sock, stateTone, time } from "../lib/format";
import type { AddressGroup, EndpointRecord, TcpState } from "../lib/types";

type Proto = "all" | "tcp" | "udp";
type Fam = "all" | "ipv4" | "ipv6";
type Where = "all" | "internet" | "local";

function StateBadge({ s }: { s: TcpState | null }) {
  if (!s) return <span className="text-faint">—</span>;
  return (
    <Badge tone={stateTone(s)} mono>
      {s}
    </Badge>
  );
}

/** Fields defined in the model but not collected by 0.1 sources. */
const NOT_COLLECTED = ["DNS-имя", "ASN / владелец сети", "Отправлено / получено байт", "Пакеты", "RTT", "Повторные передачи", "Признаки DPI"];

export function Connections() {
  const { selectedId, selected, recordingId, setError, go } = useApp();
  const [view, setView] = useState<"groups" | "endpoints">("groups");
  const [groups, setGroups] = useState<AddressGroup[]>([]);
  const [eps, setEps] = useState<EndpointRecord[]>([]);
  const [q, setQ] = useState("");
  const [proto, setProto] = useState<Proto>("all");
  const [fam, setFam] = useState<Fam>("all");
  const [where, setWhere] = useState<Where>("all");
  const [onlyPresent, setOnlyPresent] = useState(false);
  const [detail, setDetail] = useState<string | null | undefined>(undefined); // remote addr; null = "no remote"

  const live = !!selectedId && selectedId === recordingId;
  const load = useCallback(async () => {
    if (!selectedId) return;
    try {
      const [g, e] = await Promise.all([api.groups(selectedId), api.endpoints(selectedId)]);
      setGroups(g);
      setEps(e);
    } catch (err) {
      setError(err);
    }
  }, [selectedId, setError]);
  usePolling(load, live, 2000, [selectedId]);

  const scopeOk = useCallback(
    (scope: string | null) => where === "all" || (where === "internet" ? scope === "global" : scope !== "global"),
    [where],
  );

  const shownGroups = useMemo(
    () =>
      groups.filter(
        (g) =>
          (proto === "all" || (proto === "tcp" ? g.tcp > 0 : g.udp > 0)) &&
          (fam === "all" || g.family === fam || (g.family == null && fam === "ipv4")) &&
          scopeOk(g.scope) &&
          (!onlyPresent || g.present > 0) &&
          matchesQuery([g.remoteAddr ?? "без удалённого адреса", ...g.ports, ...g.pids, ...g.states], q),
      ),
    [groups, proto, fam, onlyPresent, q, scopeOk],
  );

  const shownEps = useMemo(
    () =>
      eps.filter(
        (e) =>
          (proto === "all" || e.key.protocol === proto) &&
          (fam === "all" || (e.remoteFamily ?? e.socketFamily) === fam) &&
          scopeOk(e.remoteScope) &&
          (!onlyPresent || e.present) &&
          (detail === undefined || e.key.remoteAddr === detail) &&
          matchesQuery([e.key.remoteAddr, e.key.remotePort, e.key.localAddr, e.key.localPort, e.key.process.pid, e.state, e.key.protocol], q),
      ),
    [eps, proto, fam, onlyPresent, q, scopeOk, detail],
  );

  const groupCols: Column<AddressGroup>[] = [
    {
      key: "addr",
      header: "Удалённый адрес",
      width: "minmax(200px,1.4fr)",
      sort: (a, b) => compareIp(a.remoteAddr, b.remoteAddr),
      cell: (g) =>
        g.remoteAddr ? (
          <span className="flex items-center gap-1 font-mono">
            <span className="truncate">{g.remoteAddr}</span>
            <CopyButton text={g.remoteAddr} title="Копировать IP" />
          </span>
        ) : (
          <span className="text-muted" title="UDP-привязки и TCP-слушатели не имеют удалённого адреса">
            без удалённого адреса
          </span>
        ),
    },
    {
      key: "fam",
      header: "Тип",
      width: "150px",
      cell: (g) => (g.family ? <span className="text-muted">{g.family === "ipv4" ? "IPv4" : "IPv6"} · {g.scope ? scopeLabel[g.scope] : ""}</span> : <span className="text-faint">—</span>),
    },
    {
      key: "proto",
      header: "Протокол",
      width: "100px",
      cell: (g) => (
        <span className="flex gap-1">
          {g.tcp > 0 && <Badge tone="info">TCP {g.tcp}</Badge>}
          {g.udp > 0 && <Badge>UDP {g.udp}</Badge>}
        </span>
      ),
    },
    { key: "ports", header: "Порты", width: "120px", title: "Удалённые порты (для записей без удалённого адреса — локальные)", cell: (g) => <span className="font-mono text-muted">{g.ports.join(", ")}</span> },
    { key: "states", header: "Состояния TCP", width: "minmax(140px,1fr)", cell: (g) => <span className="flex gap-1">{g.states.map((s) => <StateBadge key={s} s={s} />)}</span> },
    { key: "pid", header: "PID", width: "90px", cell: (g) => <span className="font-mono text-muted">{g.pids.join(", ")}</span> },
    { key: "first", header: "Первое", width: "84px", sort: (a, b) => a.firstSeen - b.firstSeen, cell: (g) => <span className="font-mono text-muted">{time(g.firstSeen)}</span> },
    { key: "last", header: "Последнее", width: "84px", sort: (a, b) => a.lastSeen - b.lastSeen, cell: (g) => <span className="font-mono text-muted">{time(g.lastSeen)}</span> },
    { key: "obs", header: "Набл.", width: "64px", align: "right", title: "Сумма наблюдений во всех снимках", sort: (a, b) => a.observations - b.observations, cell: (g) => <span className="font-mono">{g.observations}</span> },
    { key: "eps", header: "Endp.", width: "60px", align: "right", sort: (a, b) => a.endpoints - b.endpoints, cell: (g) => <span className="font-mono">{g.endpoints}</span> },
    {
      key: "now",
      header: "Сейчас",
      width: "80px",
      sort: (a, b) => a.present - b.present,
      cell: (g) => (g.present > 0 ? <Badge tone="ok">{g.present} акт.</Badge> : <span className="text-faint">нет</span>),
    },
  ];

  const epCols: Column<EndpointRecord>[] = [
    { key: "proto", header: "Прот.", width: "56px", cell: (e) => <Badge tone={e.key.protocol === "tcp" ? "info" : "muted"}>{e.key.protocol.toUpperCase()}</Badge> },
    {
      key: "remote",
      header: "Удалённый",
      width: "minmax(200px,1.3fr)",
      sort: (a, b) => compareIp(a.key.remoteAddr, b.key.remoteAddr),
      cell: (e) =>
        e.key.remoteAddr ? (
          <span className="flex items-center gap-1 font-mono">
            <span className="truncate">{sock(e.key.remoteAddr, e.key.remotePort)}</span>
            <CopyButton text={e.key.remoteAddr} title="Копировать IP" />
          </span>
        ) : (
          <span className="text-faint">{e.key.protocol === "udp" ? "нет (UDP-привязка)" : "нет (LISTEN)"}</span>
        ),
    },
    { key: "local", header: "Локальный", width: "minmax(160px,1fr)", cell: (e) => <span className="font-mono text-muted">{sock(e.key.localAddr, e.key.localPort)}</span> },
    { key: "fam", header: "Сокет", width: "60px", title: "Семейство сокета (IPv4-mapped адреса показываются как IPv4)", cell: (e) => <span className="text-muted">{e.socketFamily === "ipv4" ? "v4" : "v6"}</span> },
    { key: "state", header: "Состояние", width: "120px", cell: (e) => <StateBadge s={e.state} /> },
    { key: "pid", header: "PID", width: "70px", sort: (a, b) => a.key.process.pid - b.key.process.pid, cell: (e) => <span className="font-mono text-muted">{e.key.process.pid}</span> },
    { key: "first", header: "Первое", width: "84px", sort: (a, b) => a.firstSeen - b.firstSeen, cell: (e) => <span className="font-mono text-muted">{time(e.firstSeen)}</span> },
    { key: "last", header: "Последнее", width: "84px", sort: (a, b) => a.lastSeen - b.lastSeen, cell: (e) => <span className="font-mono text-muted">{time(e.lastSeen)}</span> },
    { key: "obs", header: "Набл.", width: "58px", align: "right", sort: (a, b) => a.observations - b.observations, cell: (e) => <span className="font-mono">{e.observations}</span> },
    { key: "ep", header: "Эпиз.", width: "54px", align: "right", title: "Сколько раз endpoint появлялся заново", cell: (e) => <span className="font-mono">{e.episodes}</span> },
    { key: "now", header: "Сейчас", width: "84px", cell: (e) => (e.present ? <Badge tone="ok">активен</Badge> : <span className="text-faint" title={`Отсутствовал в снимке ${time(e.goneAt)}`}>исчез</span>) },
    { key: "src", header: "Источник", width: "90px", cell: (e) => <SourceBadge source={e.source} /> },
    {
      key: "conf",
      header: "Достов.",
      width: "84px",
      title: "Достоверность наблюдения: высокая — идентичность процесса по PID и времени создания; средняя — только по PID",
      cell: (e) => <Badge tone={e.confidence === "high" ? "ok" : "warn"}>{e.confidence === "high" ? "высокая" : "средняя"}</Badge>,
    },
  ];

  const detailEps = detail === undefined ? [] : eps.filter((e) => e.key.remoteAddr === detail);
  const detailGroup = detail === undefined ? undefined : groups.find((g) => g.remoteAddr === detail);

  return (
    <>
      <PageHeader title="Соединения" subtitle={selected ? `Все наблюдавшиеся адреса и endpoints · ${selected.meta.title}` : "Выберите сессию"} sessionPicker />
      {!selectedId ? (
        <Empty icon={<Cable size={28} />} title="Сессия не выбрана">
          Начните запись на странице «Обзор» или выберите сохранённую сессию сверху.
          <div className="mt-3">
            <Button size="sm" onClick={() => go("overview")}>
              Перейти к выбору приложения
            </Button>
          </div>
        </Empty>
      ) : (
        <div className="flex min-h-0 flex-1 gap-4 p-5">
          <Card className="flex min-h-0 min-w-0 flex-1 flex-col" pad={false}>
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
              <Segmented
                value={view}
                onChange={(v) => {
                  setView(v);
                  if (v === "groups") setDetail(undefined);
                }}
                options={[
                  { value: "groups", label: "По адресам" },
                  { value: "endpoints", label: "Endpoints" },
                ]}
              />
              <div className="relative">
                <Search size={14} className="pointer-events-none absolute left-2.5 top-2 text-faint" />
                <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, порт, PID, состояние" className="w-56 pl-8" />
              </div>
              <Segmented value={proto} onChange={setProto} options={[{ value: "all", label: "Все" }, { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }]} />
              <Segmented value={fam} onChange={setFam} options={[{ value: "all", label: "v4+v6" }, { value: "ipv4", label: "IPv4" }, { value: "ipv6", label: "IPv6" }]} />
              <Segmented value={where} onChange={setWhere} options={[{ value: "all", label: "Любые" }, { value: "internet", label: "Интернет" }, { value: "local", label: "Локальные" }]} />
              <Toggle checked={onlyPresent} onChange={setOnlyPresent} label="Только активные" />
              {detail !== undefined && view === "endpoints" && (
                <Badge tone="accent">
                  {detail ?? "без удалённого адреса"}
                  <button onClick={() => setDetail(undefined)} className="ml-1">
                    <X size={11} />
                  </button>
                </Badge>
              )}
              <span className="ml-auto text-2xs text-faint">
                {view === "groups" ? `${shownGroups.length} из ${groups.length} адресов` : `${shownEps.length} из ${eps.length} endpoints`}
                {live && " · обновление каждые 2 с"}
              </span>
            </div>
            {view === "groups" ? (
              <VirtualTable
                rows={shownGroups}
                columns={groupCols}
                rowKey={(g) => g.remoteAddr ?? "∅"}
                selectedKey={detail === undefined ? null : (detail ?? "∅")}
                onRowClick={(g) => setDetail(g.remoteAddr)}
                defaultSort={{ key: "last", dir: -1 }}
                empty={<Empty title={groups.length ? "Нет адресов под фильтр" : "Пока ничего не наблюдалось"}>Показываются все адреса процесса, включая успешные соединения.</Empty>}
              />
            ) : (
              <VirtualTable
                rows={shownEps}
                columns={epCols}
                rowKey={(e) => String(e.id)}
                defaultSort={{ key: "last", dir: -1 }}
                empty={<Empty title={eps.length ? "Нет endpoints под фильтр" : "Пока ничего не наблюдалось"} />}
              />
            )}
          </Card>

          {view === "groups" && detail !== undefined && (
            <Card
              className="flex w-[360px] shrink-0 flex-col overflow-y-auto"
              title={<span className="font-mono">{detail ?? "без удалённого адреса"}</span>}
              actions={
                <Button size="sm" variant="ghost" onClick={() => setDetail(undefined)}>
                  <X size={14} />
                </Button>
              }
            >
              {detailGroup && (
                <dl className="selectable grid grid-cols-[120px_1fr] gap-x-3 gap-y-1.5 text-xs">
                  <dt className="text-faint">Семейство</dt>
                  <dd>{detailGroup.family ? detailGroup.family.toUpperCase() : "—"}</dd>
                  <dt className="text-faint">Область</dt>
                  <dd>{detailGroup.scope ? scopeLabel[detailGroup.scope] : "—"}</dd>
                  <dt className="text-faint">Наблюдался</dt>
                  <dd>
                    {dateTime(detailGroup.firstSeen)} — {time(detailGroup.lastSeen)} ({duration(detailGroup.lastSeen - detailGroup.firstSeen)})
                  </dd>
                  <dt className="text-faint">Попыток/эпизодов</dt>
                  <dd>
                    {detailGroup.endpoints} endpoints, {detailGroup.episodes} эпизодов
                  </dd>
                </dl>
              )}
              <h4 className="mb-1.5 mt-4 text-2xs uppercase tracking-wide text-faint">Endpoints и попытки</h4>
              <div className="space-y-1.5">
                {detailEps
                  .sort((a, b) => a.firstSeen - b.firstSeen)
                  .map((e) => (
                    <div key={e.id} className="rounded-md border border-line bg-bg px-2.5 py-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Badge tone={e.key.protocol === "tcp" ? "info" : "muted"}>{e.key.protocol.toUpperCase()}</Badge>
                        <span className="font-mono">{e.key.remoteAddr ? sock(e.key.remoteAddr, e.key.remotePort) : sock(e.key.localAddr, e.key.localPort)}</span>
                        <span className="ml-auto">{e.present ? <Badge tone="ok">активен</Badge> : <Badge>исчез</Badge>}</span>
                      </div>
                      <div className="mt-1 font-mono text-2xs text-muted">
                        локальный {sock(e.key.localAddr, e.key.localPort)} · PID {e.key.process.pid}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">{e.statesSeen.map((s) => <StateBadge key={s} s={s} />)}</div>
                      <div className="mt-1 text-2xs text-muted">
                        {time(e.firstSeen, true)} → {time(e.lastSeen, true)} · {e.observations} набл. · {e.episodes} эпиз.
                        {e.goneAt && ` · нет в снимке ${time(e.goneAt, true)}`}
                        {e.socketCreatedAt && ` · сокет создан ${time(e.socketCreatedAt, true)}`}
                      </div>
                    </div>
                  ))}
              </div>
              <h4 className="mb-1.5 mt-4 text-2xs uppercase tracking-wide text-faint">Не собирается в версии 0.1</h4>
              <ul className="space-y-0.5 text-xs text-faint">
                {NOT_COLLECTED.map((f) => (
                  <li key={f}>{f} — нет источника</li>
                ))}
              </ul>
              <Button size="sm" className="mt-4" onClick={() => setView("endpoints")}>
                Показать в таблице endpoints
              </Button>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
