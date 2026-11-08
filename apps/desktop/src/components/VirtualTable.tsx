import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp } from "lucide-react";
import { useMemo, useRef, useState, type ReactNode } from "react";
import { cx } from "./ui";

export interface Column<T> {
  key: string;
  header: ReactNode;
  width: string; // CSS grid track, e.g. "120px" or "minmax(160px,1fr)"
  cell: (row: T) => ReactNode;
  sort?: (a: T, b: T) => number;
  align?: "right";
  title?: string;
}

/**
 * Virtualised table: only visible rows are rendered, so sessions with tens
 * of thousands of endpoints or events stay responsive.
 */
export function VirtualTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  selectedKey,
  rowHeight = 30,
  defaultSort,
  empty,
  className,
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (r: T) => string;
  onRowClick?: (r: T) => void;
  selectedKey?: string | null;
  rowHeight?: number;
  defaultSort?: { key: string; dir: 1 | -1 };
  empty?: ReactNode;
  className?: string;
}) {
  const parent = useRef<HTMLDivElement>(null);
  const [sort, setSort] = useState(defaultSort ?? null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sort) return rows;
    const s = col.sort;
    return [...rows].sort((a, b) => s(a, b) * sort.dir);
  }, [rows, sort, columns]);
  const v = useVirtualizer({ count: sorted.length, getScrollElement: () => parent.current, estimateSize: () => rowHeight, overscan: 12 });
  const template = columns.map((c) => c.width).join(" ");

  return (
    <div ref={parent} className={cx("relative min-h-0 flex-1 overflow-auto", className)}>
      <div className="sticky top-0 z-10 grid border-b border-line bg-panel/95 text-2xs uppercase tracking-wide text-faint backdrop-blur" style={{ gridTemplateColumns: template, minWidth: "fit-content" }}>
        {columns.map((c) => (
          <button
            key={c.key}
            title={c.title}
            disabled={!c.sort}
            onClick={() => setSort((s) => (s?.key === c.key ? { key: c.key, dir: s.dir === 1 ? -1 : 1 } : { key: c.key, dir: 1 }))}
            className={cx("flex items-center gap-1 px-2.5 py-2 text-left", c.sort && "hover:text-fg", c.align === "right" && "justify-end")}
          >
            {c.header}
            {sort?.key === c.key && (sort.dir === 1 ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
          </button>
        ))}
      </div>
      {sorted.length === 0 ? (
        empty
      ) : (
        <div style={{ height: v.getTotalSize(), position: "relative", minWidth: "fit-content" }}>
          {v.getVirtualItems().map((vi) => {
            const r = sorted[vi.index];
            const k = rowKey(r);
            return (
              <div
                key={k}
                onClick={() => onRowClick?.(r)}
                className={cx(
                  "group absolute left-0 grid w-full items-center border-b border-line/60 text-[13px]",
                  onRowClick && "cursor-pointer",
                  selectedKey === k ? "bg-accent/[0.09]" : "hover:bg-white/[0.025]",
                )}
                style={{ top: vi.start, height: vi.size, gridTemplateColumns: template }}
              >
                {columns.map((c) => (
                  <div key={c.key} className={cx("min-w-0 truncate px-2.5", c.align === "right" && "text-right tabular-nums")}>
                    {c.cell(r)}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
