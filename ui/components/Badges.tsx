import clsx from "clsx";
import { Severity, CveStatus } from "@/lib/types";

export function SeverityStripe({ severity }: { severity: Severity }) {
  const color =
    severity === "critical" ? "#f85149" :
    severity === "high"     ? "#d29922" :
    severity === "medium"   ? "#4493f8" : "#6e7681";
  return (
    <div
      className="absolute left-0 top-0 bottom-0 w-0.5 rounded-l"
      style={{ background: color }}
    />
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, { bg: string; color: string }> = {
    critical: { bg: "rgba(248,81,73,0.15)",  color: "#f85149" },
    high:     { bg: "rgba(210,153,34,0.15)", color: "#d29922" },
    medium:   { bg: "rgba(68,147,248,0.15)", color: "#4493f8" },
    low:      { bg: "rgba(110,118,129,0.15)",color: "#8b949e" },
  };
  const s = styles[severity];
  return (
    <span
      className="text-[10px] font-extrabold px-2 py-0.5 rounded uppercase tracking-wide"
      style={{ background: s.bg, color: s.color }}
    >
      {severity}
    </span>
  );
}

export function StatusDot({ status }: { status: CveStatus }) {
  const color =
    status === "approved"  ? "#3fb950" :
    status === "pending"   ? "#d29922" :
    status === "submitted" ? "#4493f8" :
    status === "rejected"  ? "#f85149" : "#3d444d";
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ background: color }}
    />
  );
}

export function SevBadge({ label, count, color }: { label: string; count: number; color: string }) {
  if (count === 0) return null;
  return (
    <span
      className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase"
      style={{ background: `${color}18`, color }}
    >
      {count} {label}
    </span>
  );
}

export function StatusChip({ status, approved, total }: { status: string; approved: number; total: number }) {
  const pct = total > 0 ? Math.round((approved / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-1.5 w-16 rounded-full overflow-hidden"
        style={{ background: "var(--border)" }}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: pct === 100 ? "var(--accent-green)" : pct > 60 ? "var(--accent-blue)" : "var(--accent-yellow)",
          }}
        />
      </div>
      <span className="text-[11px]" style={{ color: "var(--subtle)" }}>
        {approved}/{total}
      </span>
    </div>
  );
}

export type ScanStatus =
  | "queued"
  | "scanning"
  | "running"
  | "awaiting_approval"
  | "completed"
  | "error";

export function RunStatusBadge({ status }: { status: ScanStatus }) {
  const styles: Record<ScanStatus, { bg: string; color: string; label: string; pulse?: boolean }> = {
    queued:            { bg: "var(--surface2)",        color: "var(--dim)",           label: "Queued" },
    scanning:          { bg: "var(--accent-blue-bg)",   color: "var(--accent-blue)",   label: "Scanning…", pulse: true },
    running:           { bg: "var(--accent-purple-bg)", color: "var(--accent-purple)", label: "Running" },
    awaiting_approval: { bg: "rgba(210,153,34,0.15)",   color: "var(--accent-yellow)", label: "Awaiting Review" },
    completed:         { bg: "var(--accent-green-bg)",  color: "var(--accent-green)",  label: "Completed" },
    error:             { bg: "var(--accent-red-bg)",    color: "var(--accent-red)",    label: "Error" },
  };
  const s = styles[status];
  return (
    <span
      className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full uppercase tracking-wide inline-flex items-center gap-1 ${s.pulse ? "animate-pulse" : ""}`}
      style={{ background: s.bg, color: s.color }}
    >
      {s.label}
    </span>
  );
}

export function ChipVariant({
  label,
  variant,
}: {
  label: string;
  variant: "rag" | "tool" | "llm" | "done" | "stream";
}) {
  const styles: Record<string, { bg: string; color: string }> = {
    rag:    { bg: "rgba(163,113,247,0.2)", color: "#a371f7" },
    tool:   { bg: "rgba(210,153,34,0.15)", color: "#d29922" },
    llm:    { bg: "rgba(68,147,248,0.2)",  color: "#4493f8" },
    done:   { bg: "rgba(63,185,80,0.15)",  color: "#3fb950" },
    stream: { bg: "rgba(163,113,247,0.15)",color: "#a371f7" },
  };
  const s = styles[variant];
  return (
    <span
      className="text-[10px] font-semibold px-2 py-0.5 rounded-full font-mono"
      style={{ background: s.bg, color: s.color }}
    >
      {label}
    </span>
  );
}
