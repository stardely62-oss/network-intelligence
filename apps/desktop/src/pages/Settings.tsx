import { Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { Badge, Button, Card, Notice, Select, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { useApp } from "../lib/app";
import { bytes } from "../lib/format";
import type { AppInfo, AppSettings, RuleInfo } from "../lib/types";

const LIMITS = [
  "Источник 0.1 — периодические снимки системных таблиц TCP/UDP (IP Helper API). Это инвентаризация, а не захват пакетов.",
  "Соединения, которые открылись и закрылись между двумя снимками, не видны.",
  "Время исчезновения endpoint — время снимка, в котором его уже не было; точный момент закрытия неизвестен.",
  "UDP-таблица содержит только локальные привязки: удалённые адреса, пакеты и ответы UDP не видны.",
  "TCP-сокеты в TIME_WAIT обычно принадлежат PID 0 и не относятся к приложению.",
  "DNS-имена, байты, пакеты, RTT, повторные передачи, TLS/SNI и признаки DPI не собираются (нужны ETW/WFP — план 0.2).",
  "Без прав администратора время создания некоторых процессов недоступно; их идентичность — только по PID.",
];

export function Settings() {
  const { settings, saveSettings, setError, refreshSessions, select, setRecordingId } = useApp();
  const [s, setS] = useState<AppSettings | null>(settings);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [rules, setRules] = useState<RuleInfo[]>([]);
  useEffect(() => setS(settings), [settings]);
  useEffect(() => {
    api.appInfo().then(setInfo).catch(setError);
    api.ruleCatalog().then(setRules).catch(setError);
  }, [setError]);

  if (!s) return <PageHeader title="Настройки" />;
  const dirty = JSON.stringify(s) !== JSON.stringify(settings);

  async function wipe() {
    if (!confirm("Удалить всю историю: все сессии, события, проверки и выводы? Это действие необратимо. Идущая запись будет остановлена.")) return;
    try {
      await api.deleteAllHistory();
      setRecordingId(null);
      select(null);
      await refreshSessions();
      setInfo(await api.appInfo());
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <PageHeader
        title="Настройки"
        subtitle="Сбор, хранение и приватность"
        actions={
          <Button variant="primary" disabled={!dirty} onClick={() => void saveSettings(s)}>
            Сохранить
          </Button>
        }
      />
      <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto p-5 xl:grid-cols-2">
        <Card title="Сбор данных (значения по умолчанию для новых сессий)">
          <div className="flex items-center justify-between py-1 text-[13px]">
            <span>Интервал снимков</span>
            <Select value={String(s.session.pollIntervalMs)} onChange={(v) => setS({ ...s, session: { ...s.session, pollIntervalMs: Number(v) } })}>
              {[250, 500, 1000, 2000, 5000].map((v) => (
                <option key={v} value={v}>
                  {v} мс
                </option>
              ))}
            </Select>
          </div>
          <Toggle checked={s.session.includeChildren} onChange={(v) => setS({ ...s, session: { ...s.session, includeChildren: v } })} label="Отслеживать дочерние процессы" />
          <Toggle checked={s.session.includeSameImage} onChange={(v) => setS({ ...s, session: { ...s.session, includeSameImage: v } })} label="Отслеживать все процессы того же файла" />
          <Toggle checked={s.session.includeListeners} onChange={(v) => setS({ ...s, session: { ...s.session, includeListeners: v } })} label="Записывать слушающие сокеты (LISTEN)" />
        </Card>

        <Card title="Хранение">
          <div className="flex items-center justify-between py-1 text-[13px]">
            <span>Автоудаление завершённых сессий</span>
            <Select value={String(s.retentionDays)} onChange={(v) => setS({ ...s, retentionDays: Number(v) })}>
              <option value="7">через 7 дней</option>
              <option value="30">через 30 дней</option>
              <option value="90">через 90 дней</option>
              <option value="0">не удалять</option>
            </Select>
          </div>
          {info && (
            <dl className="selectable mt-2 grid grid-cols-[110px_1fr] gap-y-1 text-xs">
              <dt className="text-faint">База данных</dt>
              <dd className="break-all text-muted">{info.dataDir}\ni.sqlite3</dd>
              <dt className="text-faint">Размер</dt>
              <dd>{bytes(info.dbSize)}</dd>
            </dl>
          )}
          <p className="mt-2 text-xs text-muted">Файл находится в профиле пользователя (%LOCALAPPDATA%), доступ к нему имеют только вы, SYSTEM и администраторы.</p>
          <Button variant="danger" className="mt-3" onClick={() => void wipe()}>
            <Trash2 size={13} /> Удалить всю историю
          </Button>
        </Card>

        <Card title="Приватность экспорта (по умолчанию)">
          <Toggle checked={s.export.redactPrivateIps} onChange={(v) => setS({ ...s, export: { ...s.export, redactPrivateIps: v } })} label="Скрывать частные и локальные IP" />
          <Toggle checked={s.export.redactLocalAddresses} onChange={(v) => setS({ ...s, export: { ...s.export, redactLocalAddresses: v } })} label="Скрывать все локальные адреса компьютера" />
          <Toggle checked={s.export.redactPaths} onChange={(v) => setS({ ...s, export: { ...s.export, redactPaths: v } })} label="Скрывать пути к файлам" />
          <Toggle checked={s.export.includeNotes} onChange={(v) => setS({ ...s, export: { ...s.export, includeNotes: v } })} label="Включать заметки и маркеры" />
          <Toggle checked={s.export.includeEvents} onChange={(v) => setS({ ...s, export: { ...s.export, includeEvents: v } })} label="Включать список событий" />
          <div className="mt-3">
            <Notice>
              Network Intelligence не отправляет данные в сеть: нет телеметрии, аккаунтов и облака. Содержимое пакетов, пароли, токены и cookie не собираются — источник
              0.1 их не видит вообще.
            </Notice>
          </div>
        </Card>

        <Card title="Границы наблюдаемости">
          <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
            {LIMITS.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
          <div className="mt-3 text-2xs uppercase tracking-wide text-faint">Правила диагностики</div>
          <div className="mt-1 space-y-1">
            {rules.map((r) => (
              <div key={r.id} className="flex items-center gap-2 text-xs">
                <Badge tone={r.status === "implemented" ? "ok" : "muted"}>{r.status === "implemented" ? "работает" : "запланировано"}</Badge>
                <span>{r.title}</span>
              </div>
            ))}
          </div>
          {info && (
            <div className="mt-3 text-2xs text-faint">
              Источник: {info.provider} · права: {info.elevated == null ? "неизвестно" : info.elevated ? "администратор" : "обычный пользователь"} · версия {info.version}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
