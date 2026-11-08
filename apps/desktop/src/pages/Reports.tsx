import { save } from "@tauri-apps/plugin-dialog";
import { Download, FileText, Pencil, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { ProcessIcon } from "../components/ProcessIcon";
import { Badge, Button, Card, Empty, Input, Notice, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { useApp } from "../lib/app";
import { bytes, dateTime, duration } from "../lib/format";
import type { ExportOptions, SessionSummary } from "../lib/types";

export function Reports() {
  const { sessions, refreshSessions, select, go, recordingId, settings, setError } = useApp();
  const [exporting, setExporting] = useState<SessionSummary | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [title, setTitle] = useState("");

  useEffect(() => void refreshSessions(), [refreshSessions]);

  async function remove(s: SessionSummary) {
    if (!confirm(`Удалить сессию «${s.meta.title}» и все её данные?`)) return;
    try {
      await api.deleteSession(s.meta.id);
      await refreshSessions();
    } catch (e) {
      setError(e);
    }
  }

  async function rename(id: string) {
    try {
      await api.renameSession(id, title);
      setRenaming(null);
      await refreshSessions();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <PageHeader title="Отчёты" subtitle="Сохранённые диагностические сессии и экспорт в JSON" />
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-5">
        {sessions.length === 0 && (
          <Card>
            <Empty icon={<FileText size={28} />} title="Сессий пока нет">
              Записанные сессии хранятся локально в SQLite и никуда не отправляются.
            </Empty>
          </Card>
        )}
        {sessions.map((s) => (
          <Card key={s.meta.id} pad={false}>
            <div className="flex flex-wrap items-center gap-3 px-4 py-3">
              <ProcessIcon path={s.meta.target.path} size={22} />
              <div className="min-w-0 flex-1">
                {renaming === s.meta.id ? (
                  <div className="flex gap-2">
                    <Input autoFocus value={title} onChange={(e) => setTitle(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void rename(s.meta.id)} className="w-80" />
                    <Button size="sm" onClick={() => void rename(s.meta.id)}>
                      Сохранить
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setRenaming(null)}>
                      Отмена
                    </Button>
                  </div>
                ) : (
                  <button
                    className="text-left text-[13px] font-semibold hover:text-accent"
                    onClick={() => {
                      select(s.meta.id);
                      go("connections");
                    }}
                  >
                    {s.meta.title}
                  </button>
                )}
                <div className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-muted">
                  <span>{dateTime(s.meta.startedAt)}</span>
                  <span>{s.meta.endedAt ? duration(s.meta.endedAt - s.meta.startedAt) : "идёт"}</span>
                  <span>{s.counts.remoteAddresses} адресов</span>
                  <span>
                    {s.counts.endpoints} endpoints (TCP {s.counts.tcpEndpoints}, UDP {s.counts.udpEndpoints})
                  </span>
                  <span>{s.counts.events} событий</span>
                  <span>{s.counts.probes} проверок</span>
                </div>
                {s.meta.note && <div className="mt-1 line-clamp-2 text-xs text-faint">{s.meta.note}</div>}
              </div>
              {s.meta.id === recordingId ? (
                <Badge tone="bad">● запись</Badge>
              ) : s.meta.status === "interrupted" ? (
                <Badge tone="warn" title="Приложение было закрыто во время записи; данные сохранены до последнего снимка">
                  прервана
                </Badge>
              ) : (
                <Badge tone="ok">завершена</Badge>
              )}
              <div className="flex gap-1">
                <Button size="sm" variant="ghost" title="Переименовать" onClick={() => (setRenaming(s.meta.id), setTitle(s.meta.title))}>
                  <Pencil size={13} />
                </Button>
                <Button size="sm" onClick={() => setExporting(s)}>
                  <Download size={13} /> JSON
                </Button>
                <Button size="sm" variant="ghost" title="Удалить" disabled={s.meta.id === recordingId} onClick={() => void remove(s)}>
                  <Trash2 size={13} />
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>
      {exporting && settings && <ExportDialog s={exporting} defaults={settings.export} onClose={() => setExporting(null)} />}
    </>
  );
}

function ExportDialog({ s, defaults, onClose }: { s: SessionSummary; defaults: ExportOptions; onClose: () => void }) {
  const { setError } = useApp();
  const [o, setO] = useState<ExportOptions>(defaults);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    const date = new Date(s.meta.startedAt).toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const name = `ni-${s.meta.target.name.replace(/[^\w.-]+/g, "_")}-${date}.json`;
    const path = await save({ defaultPath: name, filters: [{ name: "JSON", extensions: ["json"] }] });
    if (!path) return;
    setBusy(true);
    try {
      const r = await api.exportSession(s.meta.id, o, path);
      setDone(`Сохранено: ${r.path} (${bytes(r.bytes)})`);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="w-[460px] animate-fade-in rounded-lg border border-line-strong bg-panel p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-sm font-semibold">Экспорт отчёта JSON</h2>
        <p className="mt-1 text-xs text-muted">{s.meta.title}</p>
        <div className="mt-4 space-y-1">
          <Toggle checked={o.redactPrivateIps} onChange={(v) => setO({ ...o, redactPrivateIps: v })} label="Скрыть частные и локальные IP" hint="192.168.x.x, 10.x.x.x, fe80::, 100.64/10 и т. п. заменяются псевдонимами" />
          <Toggle checked={o.redactLocalAddresses} onChange={(v) => setO({ ...o, redactLocalAddresses: v })} label="Скрыть все локальные адреса компьютера" hint="Включая публичный IP, если он назначен этому компьютеру" />
          <Toggle checked={o.redactPaths} onChange={(v) => setO({ ...o, redactPaths: v })} label="Скрыть пути к файлам" hint="Остаётся только имя файла (без имени пользователя и папок)" />
          <Toggle checked={o.includeNotes} onChange={(v) => setO({ ...o, includeNotes: v })} label="Включить заметки и подписи маркеров" />
          <Toggle checked={o.includeEvents} onChange={(v) => setO({ ...o, includeEvents: v })} label="Включить полный список событий" />
        </div>
        <div className="mt-3">
          <Notice>
            Публичные адреса серверов остаются в отчёте — без них он бесполезен для диагностики. Отчёт сохраняется только в выбранный файл и никуда не отправляется.
          </Notice>
        </div>
        {done && <div className="mt-3 break-all text-xs text-ok">{done}</div>}
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Закрыть
          </Button>
          <Button variant="primary" onClick={() => void run()} disabled={busy}>
            <Download size={13} /> {busy ? "Сохранение…" : "Сохранить как…"}
          </Button>
        </div>
      </div>
    </div>
  );
}
