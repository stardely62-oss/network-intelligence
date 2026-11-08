import { Check, Copy } from "lucide-react";
import { useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { confidenceLabel, sourceLabel } from "../lib/format";
import type { Confidence, DataSource } from "../lib/types";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

type Tone = "ok" | "warn" | "bad" | "info" | "muted" | "accent";

const toneCls: Record<Tone, string> = {
  ok: "text-ok bg-ok/10 border-ok/25",
  warn: "text-warn bg-warn/10 border-warn/25",
  bad: "text-bad bg-bad/10 border-bad/25",
  info: "text-info bg-info/10 border-info/25",
  muted: "text-muted bg-white/[0.03] border-line",
  accent: "text-accent bg-accent/10 border-accent/25",
};

export function Badge({ tone = "muted", children, title, mono }: { tone?: Tone; children: ReactNode; title?: string; mono?: boolean }) {
  return (
    <span
      title={title}
      className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-px text-2xs", mono && "font-mono", toneCls[tone])}
    >
      {children}
    </span>
  );
}

export function SourceBadge({ source }: { source: DataSource }) {
  const tone: Tone = source === "active_probe" ? "accent" : source === "observed_process" ? "info" : source === "user" ? "warn" : "muted";
  return (
    <Badge tone={tone} title={`Источник данных: ${source}`}>
      {sourceLabel[source]}
    </Badge>
  );
}

export function ConfidenceBadge({ c, label = "уверенность" }: { c: Confidence; label?: string }) {
  const tone: Tone = c === "high" ? "ok" : c === "medium" ? "info" : c === "low" ? "warn" : "muted";
  return (
    <Badge tone={tone} title={label}>
      {label}: {confidenceLabel[c]}
    </Badge>
  );
}

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "danger" | "default"; size?: "sm" | "md" };

export function Button({ variant = "default", size = "md", className, ...p }: BtnProps) {
  return (
    <button
      {...p}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-md border font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 disabled:cursor-not-allowed disabled:opacity-45",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-[13px]",
        variant === "primary" && "border-accent/60 bg-accent/90 text-[#08201d] hover:bg-accent",
        variant === "default" && "border-line-strong bg-raised text-fg hover:border-faint hover:bg-[#1f242b]",
        variant === "ghost" && "border-transparent bg-transparent text-muted hover:bg-white/[0.04] hover:text-fg",
        variant === "danger" && "border-bad/40 bg-bad/10 text-bad hover:bg-bad/20",
        className,
      )}
    />
  );
}

export function Card({ title, actions, children, className, pad = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={cx("rounded-lg border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h3 className="text-[13px] font-semibold text-fg">{title}</h3>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={cx(pad && "p-4")}>{children}</div>
    </section>
  );
}

export function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; hint?: ReactNode }) {
  return (
    <label className="flex cursor-pointer items-start gap-2.5 py-1">
      <span
        role="switch"
        aria-checked={checked}
        tabIndex={0}
        onKeyDown={(e) => (e.key === " " || e.key === "Enter") && (e.preventDefault(), onChange(!checked))}
        onClick={(e) => {
          e.preventDefault();
          onChange(!checked);
        }}
        className={cx(
          "relative mt-0.5 inline-flex h-4 w-7 shrink-0 rounded-full border transition-colors",
          checked ? "border-accent/70 bg-accent/70" : "border-line-strong bg-raised",
        )}
      >
        <span className={cx("absolute top-[1px] h-3 w-3 rounded-full bg-fg transition-transform", checked ? "translate-x-[13px]" : "translate-x-[1px]")} />
      </span>
      <span className="text-[13px] leading-5">
        <span className="text-fg">{label}</span>
        {hint && <span className="block text-xs text-muted">{hint}</span>}
      </span>
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-md border border-line bg-bg p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={cx("rounded px-2.5 py-1 text-xs transition-colors", value === o.value ? "bg-raised text-fg shadow-sm" : "text-muted hover:text-fg")}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Input(p: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...p}
      className={cx(
        "h-8 rounded-md border border-line-strong bg-bg px-2.5 text-[13px] text-fg placeholder:text-faint focus:border-accent/60 focus:outline-none",
        p.className,
      )}
    />
  );
}

export function Select({ value, onChange, children, className }: { value: string; onChange: (v: string) => void; children: ReactNode; className?: string }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cx("h-8 rounded-md border border-line-strong bg-bg px-2 text-[13px] text-fg focus:border-accent/60 focus:outline-none", className)}
    >
      {children}
    </select>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {icon && <div className="text-faint">{icon}</div>}
      <div className="text-sm font-medium text-fg">{title}</div>
      {children && <div className="max-w-md text-[13px] text-muted">{children}</div>}
    </div>
  );
}

export function CopyButton({ text, title = "Копировать" }: { text: string; title?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      title={title}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
      className="inline-flex h-5 w-5 items-center justify-center rounded text-faint opacity-0 transition hover:bg-white/5 hover:text-fg group-hover:opacity-100"
    >
      {done ? <Check size={12} className="text-ok" /> : <Copy size={12} />}
    </button>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone }) {
  return (
    <div className="min-w-0">
      <div className="text-2xs uppercase tracking-wide text-faint">{label}</div>
      <div className={cx("mt-0.5 font-mono text-lg tabular-nums", tone === "bad" ? "text-bad" : tone === "warn" ? "text-warn" : "text-fg")}>{value}</div>
      {hint && <div className="text-2xs text-muted">{hint}</div>}
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "bad"; children: ReactNode }) {
  return (
    <div
      className={cx(
        "rounded-md border px-3 py-2 text-xs leading-5",
        tone === "info" && "border-info/25 bg-info/[0.06] text-[#b8cde4]",
        tone === "warn" && "border-warn/25 bg-warn/[0.07] text-[#e8d2a8]",
        tone === "bad" && "border-bad/30 bg-bad/[0.08] text-[#f0bdb8]",
      )}
    >
      {children}
    </div>
  );
}
