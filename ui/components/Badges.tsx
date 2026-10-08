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
    status === "approved" ? "#3fb950" :
    status === "pending"  ? "#d29922" :
    status === "rejected" ? "#f85149" : "#3d444d";
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ background: color }}
    />
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
