"use client";

import { CveRecord } from "@/lib/types";

const SEV: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: "var(--accent-red)",    bg: "var(--accent-red-bg)",         label: "C" },
  high:     { color: "var(--accent-orange)", bg: "rgba(240,136,62,0.12)",         label: "H" },
  medium:   { color: "var(--accent-yellow)", bg: "rgba(210,153,34,0.10)",         label: "M" },
  low:      { color: "var(--accent-green)",  bg: "var(--accent-green-bg)",        label: "L" },
};

const STATUS: Record<string, { icon: string; color: string }> = {
  approved: { icon: "✓", color: "var(--accent-green)"  },
  rejected: { icon: "✕", color: "var(--accent-red)"    },
  pending:  { icon: "○", color: "var(--accent-yellow)"  },
  queued:   { icon: "·", color: "var(--dim)"            },
};

interface Props {
  cves: CveRecord[];
  selectedId: string;
  onSelect: (id: string) => void;
}

export default function CveQueue({ cves, selectedId, onSelect }: Props) {
  const approved = cves.filter((c) => c.status === "approved").length;
  const rejected = cves.filter((c) => c.status === "rejected").length;
  const done     = approved + rejected;
  const pct      = cves.length > 0 ? Math.round((done / cves.length) * 100) : 0;

  // Group by severity for the filter chips
  const counts = cves.reduce<Record<string, number>>((acc, c) => {
    acc[c.severity] = (acc[c.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <aside
      className="w-56 flex-shrink-0 flex flex-col overflow-hidden"
      style={{ background: "var(--bg-nav)", borderRight: "1px solid var(--border)" }}
    >
      {/* ── Header ── */}
      <div className="px-4 pt-4 pb-3" style={{ borderBottom: "1px solid var(--border)" }}>
        {/* Title row */}
        <div className="flex items-center justify-between mb-2.5">
          <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
            CVE Queue
          </span>
          <span
            className="text-[11px] font-mono font-bold px-2 py-0.5 rounded-md"
            style={{ background: "var(--surface2)", color: "var(--subtle)", border: "1px solid var(--border)" }}
          >
            {cves.length}
          </span>
        </div>

        {/* Severity chips */}
        <div className="flex items-center gap-1.5 mb-2.5">
          {(["critical","high","medium","low"] as const).map((s) =>
            counts[s] ? (
              <span
                key={s}
                className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                style={{ background: SEV[s].bg, color: SEV[s].color }}
              >
                {SEV[s].label} {counts[s]}
              </span>
            ) : null
          )}
        </div>

        {/* Progress bar */}
        <div className="h-1 rounded-full overflow-hidden mb-1.5" style={{ background: "var(--border)" }}>
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${pct}%`,
              background: pct === 100
                ? "var(--accent-green)"
                : "linear-gradient(90deg, var(--accent-blue), var(--accent-green))",
            }}
          />
        </div>
        <div className="flex justify-between">
          <span className="text-[10px]" style={{ color: "var(--muted)" }}>{done} reviewed</span>
          <span className="text-[10px]" style={{ color: "var(--muted)" }}>{cves.length - done} left</span>
        </div>
      </div>

      {/* ── CVE List ── */}
      <div className="overflow-y-auto flex-1 min-h-0 py-1.5">
        {cves.map((cve) => {
          const isSelected = cve.id === selectedId;
          const sev        = SEV[cve.severity]  ?? SEV.low;
          const sta        = STATUS[cve.status] ?? STATUS.queued;

          return (
            <button
              key={cve.id}
              onClick={() => onSelect(cve.id)}
              className="w-full text-left relative flex items-center gap-0 transition-colors duration-100"
              style={{
                background: isSelected ? "var(--surface2)" : "transparent",
                borderLeft: `3px solid ${isSelected ? sev.color : "transparent"}`,
                paddingTop: "7px",
                paddingBottom: "7px",
                paddingLeft: "12px",
                paddingRight: "10px",
              }}
              onMouseEnter={(e) => {
                if (!isSelected) e.currentTarget.style.background = "var(--surface)";
              }}
              onMouseLeave={(e) => {
                if (!isSelected) e.currentTarget.style.background = "transparent";
              }}
            >
              {/* Severity dot */}
              <span
                className="w-1.5 h-1.5 rounded-full flex-shrink-0 mr-2.5 mt-0.5"
                style={{ background: sev.color }}
              />

              {/* CVE ID + pkg */}
              <div className="flex-1 min-w-0">
                <div
                  className="text-[11.5px] font-semibold font-mono leading-tight"
                  style={{ color: isSelected ? "var(--heading)" : "var(--body)" }}
                >
                  {cve.id}
                </div>
                <div className="text-[10px] mt-0.5 truncate leading-tight" style={{ color: "var(--muted)" }}>
                  {cve.pkg}
                  {cve.cvss > 0 && (
                    <span style={{ color: sev.color }}> · {cve.cvss}</span>
                  )}
                </div>
              </div>

              {/* Status icon */}
              <span
                className="text-[12px] font-bold flex-shrink-0 ml-1.5"
                style={{ color: sta.color }}
              >
                {sta.icon}
              </span>
            </button>
          );
        })}
      </div>

      {/* ── Footer ── */}
      <div
        className="px-4 py-2.5 grid grid-cols-3 gap-1"
        style={{ borderTop: "1px solid var(--border)" }}
      >
        {[
          { label: "Approved",  value: approved,           color: "var(--accent-green)"  },
          { label: "Rejected",  value: rejected,           color: "var(--accent-red)"    },
          { label: "Pending",   value: cves.length - done, color: "var(--accent-yellow)" },
        ].map((s) => (
          <div key={s.label} className="text-center">
            <div className="text-[14px] font-black leading-tight" style={{ color: s.color }}>
              {s.value}
            </div>
            <div className="text-[9px] uppercase tracking-wide" style={{ color: "var(--muted)" }}>
              {s.label}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
