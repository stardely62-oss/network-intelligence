import { ListTree, Search } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { Badge, Button, Card, Empty, Input, Segmented, Select, SourceBadge, cx } from "../components/ui";
import { VirtualTable, type Column } from "../components/VirtualTable";
import { api } from "../lib/api";
import { useApp, usePolling } from "../lib/app";
import { describeEvent, eventKindFilterName, eventKindLabel, offset, time } from "../lib/format";
import type { EventKind, SnapshotRow, StoredEvent } from "../lib/types";

type Group = "network" | "process" | "probe" | "user" | "errors";

const GROUPS: Record<Group, { label: string; kinds: EventKind["type"][] }> = {
  network: { label: "Сеть", kinds: ["endpointAppeared", "endpointStateChanged", "endpointDisappeared"] },
  process: { label: "Процессы", kinds: ["processTracked", "processExited", "pidReused"] },
  probe: { label: "Проверки", kinds: ["probeStarted", "probeFinished"] },
  user: { label: "Маркеры и сессия", kinds: ["userMarker", "sessionStarted", "sessionStopped"] },
  errors: { label: "Ошибки источника", kinds: ["sourceError"] },
};

const PAGE = 5000;

function kindTone(k: EventKind): "ok" | "warn" | "bad" | "info" | "muted" | "accent" {
  switch (k.type) {
    case "endpointAppeared":
      return "info";
    case "endpointStateChanged":
      return k.to === "ESTABLISHED" ? "ok" : "warn";
    case "endpointDisappeared":
      return "muted";
    case "processExited":
    case "pidReused":
      return "warn";
    case "sourceError":
      return "bad";
    case "userMarker":
      return "accent";
    case "probeFinished":
      return k.ok ? "ok" : "warn";
    default:
      return "muted";
  }
}

export function Timeline() {
  const { selectedId, selected, recordingId, setError } = useApp();
  const [groups, setGroups] = useState<Set<Group>>(new Set(["network", "process", "probe", "user", "errors"]));
  const [proto, setProto] = useState<"all" | "tcp" | "udp">("all");
  const [addr, setAddr] = useState("");
  const [pid, setPid] = useState("");
  const [range, setRange] = useState<[number, number] | null>(null);
  const [page, setPage] = useState(0);
  const [events, setEvents] = useState<StoredEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [snaps, setSnaps] = useState<SnapshotRow[]>([]);
  const [hist, setHist] = useState<StoredEvent[]>([]);

  const kinds = useMemo(() => [...groups].flatMap((g) => GROUPS[g].kinds.map((k) => eventKindFilterName[k])), [groups]);
  const live = !!selectedId && selectedId === recordingId;

  const load = useCallback(async () => {
    if (!selectedId) return;
    try {
      const filter = {
        kinds: kinds.length ? kinds : ["none"],
        protocol: proto === "all" ? null : proto,
        addr: addr.trim() || null,
        pid: pid ? Number(pid) : null,
        from: range?.[0] ?? null,
        to: range?.[1] ?? null,
        limit: PAGE,
        offset: page * PAGE,
      };
      const [p, s, h] = await Promise.all([
        api.events(selectedId, filter),
        api.snapshots(selectedId),
        // Unfiltered timestamps for the activity strip (network + markers).
        api.events(selectedId, { kinds: ["endpoint_appeared", "endpoint_disappeared", "endpoint_state_changed", "user_marker", "source_error"], limit: 5000 }),
      ]);
      setEvents(p.events);
      setTotal(p.total);
      setSnaps(s);
      setHist(h.events);
    } catch (e) {
      setError(e);
    }
  }, [selectedId, kinds, proto, addr, pid, range, page, setError]);
  usePolling(load, live, 2000, [load]);

  const start = selected?.meta.startedAt ?? 0;
  const end = Math.max(selected?.meta.endedAt ?? 0, snaps.at(-1)?.ts ?? 0, start + 1000);

  const cols: Column<StoredEvent>[] = [
    {
      key: "ts",
      header: "Время",
      width: "150px",
      cell: (e) => (
        <span className="font-mono text-muted">
          {time(e.ts, true)} <span className="text-faint">{offset(e.ts, start)}</span>
        </span>
      ),
    },
    { key: "kind", header: "Событие", width: "170px", cell: (e) => <Badge tone={kindTone(e.kind)}>{eventKindLabel[e.kind.type]}</Badge> },
    { key: "desc", header: "Описание", width: "minmax(320px,1fr)", cell: (e) => <span className="font-mono text-[12px]" title={describeEvent(e.kind)}>{describeEvent(e.kind)}</span> },
    { key: "src", header: "Источник", width: "120px", cell: (e) => <SourceBadge source={e.source} /> },
  ];

  return (
    <>
      <PageHeader title="Хронология" subtitle="Только реальные наблюдения: время события — время снимка, в котором изменение было замечено" sessionPicker />
      {!selected ? (
        <Empty icon={<ListTree size={28} />} title="Сессия не выбрана" />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-4 p-5">
          <Card pad={false}>
            <ActivityStrip start={start} end={end} snaps={snaps} events={hist} range={range} onRange={(r) => (setRange(r), setPage(0))} />
          </Card>
          <Card className="flex min-h-0 flex-1 flex-col" pad={false}>
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
              {(Object.keys(GROUPS) as Group[]).map((g) => (
                <button
                  key={g}
                  onClick={() => {
                    const n = new Set(groups);
                    if (n.has(g)) n.delete(g);
                    else n.add(g);
                    setGroups(n);
                    setPage(0);
                  }}
                  className={cx("rounded border px-2 py-0.5 text-xs", groups.has(g) ? "border-accent/40 bg-accent/10 text-fg" : "border-line text-faint hover:text-muted")}
                >
                  {GROUPS[g].label}
                </button>
              ))}
              <Segmented value={proto} onChange={(v) => (setProto(v), setPage(0))} options={[{ value: "all", label: "Все" }, { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }]} />
              <div className="relative">
                <Search size={14} className="pointer-events-none absolute left-2.5 top-2 text-faint" />
                <Input value={addr} onChange={(e) => (setAddr(e.target.value), setPage(0))} placeholder="Удалённый адрес" className="w-48 pl-8 font-mono" />
              </div>
              <Input value={pid} onChange={(e) => (setPid(e.target.value.replace(/\D/g, "")), setPage(0))} placeholder="PID" className="w-20 font-mono" />
              {range && (
                <Badge tone="accent">
                  {offset(range[0], start)} … {offset(range[1], start)}
                  <button className="ml-1" onClick={() => setRange(null)}>
                    ✕
                  </button>
                </Badge>
              )}
              <span className="ml-auto text-2xs text-faint">
                {total} событий{total > PAGE && ` · страница ${page + 1} из ${Math.ceil(total / PAGE)}`}
              </span>
              {total > PAGE && (
                <Select value={String(page)} onChange={(v) => setPage(Number(v))}>
                  {Array.from({ length: Math.ceil(total / PAGE) }, (_, i) => (
                    <option key={i} value={i}>
                      {i * PAGE + 1}–{Math.min(total, (i + 1) * PAGE)}
                    </option>
                  ))}
                </Select>
              )}
            </div>
            <VirtualTable rows={events} columns={cols} rowKey={(e) => String(e.id)} rowHeight={28} empty={<Empty title="Нет событий под фильтр" />} />
          </Card>
        </div>
      )}
    </>
  );
}

/** Event density per time bucket, snapshot failures and user markers.
 *  Drag to select a time range. */
function ActivityStrip({
  start,
  end,
  snaps,
  events,
  range,
  onRange,
}: {
  start: number;
  end: number;
  snaps: SnapshotRow[];
  events: StoredEvent[];
  range: [number, number] | null;
  onRange: (r: [number, number] | null) => void;
}) {
  const W = 1000;
  const H = 56;
  const N = 120;
  const span = Math.max(1, end - start);
  const x = (t: number) => ((t - start) / span) * W;
  const buckets = useMemo(() => {
    const b = new Array(N).fill(0);
    for (const e of events) {
      if (e.kind.type === "userMarker" || e.kind.type === "sourceError") continue;
      const i = Math.min(N - 1, Math.max(0, Math.floor(((e.ts - start) / span) * N)));
      b[i]++;
    }
    return b;
  }, [events, start, span]);
  const max = Math.max(1, ...buckets);
  const [drag, setDrag] = useState<number | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const toTs = (el: SVGSVGElement, clientX: number) => {
    const r = el.getBoundingClientRect();
    return start + ((clientX - r.left) / r.width) * span;
  };

  return (
    <div className="px-3 pb-2 pt-2.5">
      <div className="mb-1 flex items-center justify-between text-2xs text-faint">
        <span>Активность (изменения endpoints) · ▲ маркеры · ▮ неудачные снимки — выделите участок мышью</span>
        <span className="font-mono">{snaps.length} снимков</span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        className="h-14 w-full cursor-crosshair"
        onMouseDown={(e) => setDrag(toTs(e.currentTarget, e.clientX))}
        onMouseMove={(e) => setHover(toTs(e.currentTarget, e.clientX))}
        onMouseLeave={() => setHover(null)}
        onMouseUp={(e) => {
          if (drag == null) return;
          const t = toTs(e.currentTarget, e.clientX);
          if (Math.abs(x(t) - x(drag)) > 4) onRange([Math.min(t, drag), Math.max(t, drag)]);
          else onRange(null);
          setDrag(null);
        }}
      >
        <rect x={0} y={0} width={W} height={H} fill="#0d0f12" />
        {buckets.map((c, i) => {
          const h = c ? Math.max(2, (c / max) * (H - 14)) : 0;
          return <rect key={i} x={(i / N) * W + 0.5} y={H - 4 - h} width={W / N - 1} height={h} fill="#3c7f79" />;
        })}
        {snaps
          .filter((s) => !s.ok)
          .map((s, i) => (
            <rect key={`f${i}`} x={x(s.ts)} y={H - 4} width={2} height={4} fill="#e0645c" />
          ))}
        {events
          .filter((e) => e.kind.type === "userMarker")
          .map((e) => (
            <g key={e.id}>
              <line x1={x(e.ts)} x2={x(e.ts)} y1={8} y2={H - 4} stroke="#d9a54a" strokeWidth={1} vectorEffect="non-scaling-stroke" />
              <path d={`M ${x(e.ts) - 4} 0 L ${x(e.ts) + 4} 0 L ${x(e.ts)} 7 Z`} fill="#d9a54a" />
            </g>
          ))}
        {range && <rect x={x(range[0])} y={0} width={Math.max(1, x(range[1]) - x(range[0]))} height={H} fill="#4fb3a9" fillOpacity={0.12} stroke="#4fb3a9" strokeOpacity={0.5} vectorEffect="non-scaling-stroke" />}
        {hover != null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={H} stroke="#8b95a1" strokeOpacity={0.4} vectorEffect="non-scaling-stroke" />}
      </svg>
      <div className="mt-0.5 flex justify-between font-mono text-2xs text-faint">
        <span>{time(start)}</span>
        {hover != null && <span className="text-muted">{time(hover, true)} ({offset(hover, start)})</span>}
        <span>{time(end)}</span>
      </div>
      {range && (
        <Button size="sm" variant="ghost" className="mt-1" onClick={() => onRange(null)}>
          Сбросить интервал
        </Button>
      )}
    </div>
  );
}
