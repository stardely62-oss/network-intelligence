import type { ReactNode } from "react";
import { useApp } from "../lib/app";
import { dateTime } from "../lib/format";
import { Badge, Select } from "./ui";

export function PageHeader({ title, subtitle, actions, sessionPicker }: { title: string; subtitle?: ReactNode; actions?: ReactNode; sessionPicker?: boolean }) {
  const { sessions, selectedId, select, recordingId } = useApp();
  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
      <div className="mr-auto min-w-0">
        <h1 className="text-[15px] font-semibold">{title}</h1>
        {subtitle && <div className="truncate text-xs text-muted">{subtitle}</div>}
      </div>
      {sessionPicker && (
        <div className="flex items-center gap-2">
          {selectedId && selectedId === recordingId && <Badge tone="bad">● запись</Badge>}
          <Select value={selectedId ?? ""} onChange={(v) => select(v || null)} className="max-w-[340px]">
            <option value="">— выберите сессию —</option>
            {sessions.map((s) => (
              <option key={s.meta.id} value={s.meta.id}>
                {s.meta.title} · {dateTime(s.meta.startedAt)}
              </option>
            ))}
          </Select>
        </div>
      )}
      {actions}
    </header>
  );
}
