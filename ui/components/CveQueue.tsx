"use client";

import { useState } from "react";
import { CveRecord, cveKey } from "@/lib/types";
import { usePermission } from "@/lib/auth";

const SEV: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: "var(--accent-red)",    bg: "var(--accent-red-bg)",         label: "C" },
  high:     { color: "var(--accent-orange)", bg: "rgba(240,136,62,0.12)",         label: "H" },
  medium:   { color: "var(--accent-yellow)", bg: "rgba(210,153,34,0.10)",         label: "M" },
  low:      { color: "var(--accent-green)",  bg: "var(--accent-green-bg)",        label: "L" },
};

const STATUS: Record<string, { icon: string; color: string }> = {
  approved:          { icon: "✓", color: "var(--accent-green)"  },
  rejected:          { icon: "✕", color: "var(--accent-red)"    },
  submitted:         { icon: "➤", color: "var(--accent-blue)"   },
  changes_requested: { icon: "↺", color: "var(--accent-yellow)" },
  pending:           { icon: "○", color: "var(--accent-yellow)" },
  queued:            { icon: "·", color: "var(--dim)"           },
};

// Findings are segregated by lifecycle so decided items never sit among to-do work.
const GROUPS: { key: string; label: string; statuses: string[]; color: string }[] = [
  { key: "action",    label: "Needs action", statuses: ["pending", "queued"],   color: "var(--accent-yellow)" },
  { key: "changes",   label: "Changes requested", statuses: ["changes_requested"], color: "var(--accent-yellow)" },
  { key: "submitted", label: "Submitted · in review", statuses: ["submitted"],  color: "var(--accent-blue)"   },
  { key: "approved",  label: "Approved",     statuses: ["approved"],            color: "var(--accent-green)"  },
  { key: "rejected",  label: "Rejected",     statuses: ["rejected"],            color: "var(--accent-red)"    },
];

interface Props {
  cves: CveRecord[];
  /** A `cveKey(cve)` composite key, not a bare `cve.id` — see lib/types.ts. */
  selectedId: string;
  onSelect: (key: string) => void;
}

export default function CveQueue({ cves, selectedId, onSelect }: Props) {
  const canApproveSubmitted = usePermission("canApproveSubmitted");
  const canSubmitForApproval = usePermission("canSubmitForApproval");
  // Cyber can narrow to findings awaiting their approval; DevOps to findings
  // sent back to them for revision.
  const [pendingApprovalOnly, setPendingApprovalOnly] = useState(false);
  const [needsActionOnly, setNeedsActionOnly] = useState(false);

  const approved  = cves.filter((c) => c.status === "approved").length;
  const rejected  = cves.filter((c) => c.status === "rejected").length;
  const submitted = cves.filter((c) => c.status === "submitted").length;
  const changesRequested = cves.filter((c) => c.status === "changes_requested").length;
  const pending   = cves.filter((c) => c.status === "pending" || c.status === "queued").length;
  // Findings the agent auto-approved from a published Cyber baseline (learning loop).
  const agentCleared = cves.filter((c) => c.editedByRole === "AGENT" && c.status === "approved").length;
  const done      = approved + rejected;
  const pct       = cves.length > 0 ? Math.round((done / cves.length) * 100) : 0;

  const visibleCves = pendingApprovalOnly
    ? cves.filter((c) => c.status === "submitted")
    : needsActionOnly
    ? cves.filter((c) => c.status === "changes_requested")
    : cves;

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

        {/* Agent pre-cleared chip — the learning loop at a glance */}
        {agentCleared > 0 && (
          <div className="flex items-center gap-1.5 mb-2.5 px-2 py-1 rounded-lg"
            style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}
            title="Auto-approved from published Cyber Manager baselines">
            <span className="text-[11px]" style={{ color: "var(--accent-purple)" }}>⚡</span>
            <span className="text-[10px] font-semibold" style={{ color: "var(--accent-purple)" }}>
              Agent pre-cleared {agentCleared} of {cves.length}
            </span>
          </div>
        )}

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

      {/* ── Cyber: pending-my-approval filter ── */}
      {canApproveSubmitted && submitted > 0 && (
        <button
          onClick={() => setPendingApprovalOnly((v) => !v)}
          className="mx-3 mt-2 flex items-center gap-2 px-3 py-2 rounded-lg text-[11px] font-semibold transition-colors"
          style={{
            background: pendingApprovalOnly ? "var(--accent-blue-bg, rgba(68,147,248,0.12))" : "var(--surface2)",
            color: pendingApprovalOnly ? "var(--accent-blue)" : "var(--muted)",
            border: `1px solid ${pendingApprovalOnly ? "var(--accent-blue-bdr, rgba(68,147,248,0.25))" : "var(--border)"}`,
          }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M22 2 11 13" /><path d="M22 2 15 22 11 13 2 9z" />
          </svg>
          Pending my approval
          <span className="ml-auto font-mono">{submitted}</span>
        </button>
      )}

      {/* ── DevOps: needs-my-action filter (changes requested) ── */}
      {canSubmitForApproval && changesRequested > 0 && (
        <button
          onClick={() => setNeedsActionOnly((v) => !v)}
          className="mx-3 mt-2 flex items-center gap-2 px-3 py-2 rounded-lg text-[11px] font-semibold transition-colors"
          style={{
            background: needsActionOnly ? "rgba(210,153,34,0.12)" : "var(--surface2)",
            color: needsActionOnly ? "var(--accent-yellow)" : "var(--muted)",
            border: `1px solid ${needsActionOnly ? "rgba(210,153,34,0.3)" : "var(--border)"}`,
          }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M3 2v6h6" /><path d="M3 13a9 9 0 1 0 3-7.7L3 8" />
          </svg>
          Needs my action
          <span className="ml-auto font-mono">{changesRequested}</span>
        </button>
      )}

      {/* ── CVE List (grouped by lifecycle) ── */}
      <div className="overflow-y-auto flex-1 min-h-0 py-1.5">
        {GROUPS.map((g) => {
          const items = visibleCves.filter((c) => g.statuses.includes(c.status));
          if (items.length === 0) return null;
          return (
            <div key={g.key} className="mb-1">
              <div className="px-3 pt-2 pb-1 flex items-center gap-2 sticky top-0 z-10" style={{ background: "var(--bg-nav)" }}>
                <span className="text-[9.5px] font-bold uppercase tracking-wider" style={{ color: g.color }}>{g.label}</span>
                <span className="text-[9.5px] font-mono" style={{ color: "var(--dim)" }}>{items.length}</span>
                <div className="flex-1 h-px" style={{ background: "var(--border)" }} />
              </div>
              {items.map((cve) => {
                const key        = cveKey(cve);
                const isSelected = key === selectedId;
                const sev        = SEV[cve.severity]  ?? SEV.low;
                const sta        = STATUS[cve.status] ?? STATUS.queued;
                const fromBaseline = cve.status === "approved" && cve.ragMatch?.project === "Shared Cyber Manager baseline";
                return (
                  <button
                    key={key}
                    onClick={() => onSelect(key)}
                    className="w-full text-left relative flex items-center gap-0 transition-colors duration-100"
                    style={{
                      background: isSelected ? "var(--surface2)" : "transparent",
                      borderLeft: `3px solid ${isSelected ? sev.color : "transparent"}`,
                      paddingTop: "7px", paddingBottom: "7px", paddingLeft: "12px", paddingRight: "10px",
                      opacity: g.key === "approved" || g.key === "rejected" ? 0.75 : 1,
                    }}
                    onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "var(--surface)"; }}
                    onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = "transparent"; }}
                  >
                    <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 mr-2.5 mt-0.5" style={{ background: sev.color }} />
                    <div className="flex-1 min-w-0">
                      <div className="text-[11.5px] font-semibold font-mono leading-tight" style={{ color: isSelected ? "var(--heading)" : "var(--body)" }}>
                        {cve.id}
                      </div>
                      <div className="text-[10px] mt-0.5 truncate leading-tight" style={{ color: "var(--muted)" }}>
                        {cve.pkg}
                        {cve.cvss > 0 && <span style={{ color: sev.color }}> · {cve.cvss}</span>}
                        {fromBaseline && <span style={{ color: "var(--accent-purple)" }} title="Auto-approved from a published baseline"> · ◈ baseline</span>}
                      </div>
                    </div>
                    <span className="text-[12px] font-bold flex-shrink-0 ml-1.5" style={{ color: sta.color }}>{sta.icon}</span>
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>

      {/* ── Footer ── */}
      <div
        className="px-4 py-2.5 grid grid-cols-4 gap-1"
        style={{ borderTop: "1px solid var(--border)" }}
      >
        {[
          { label: "Approved",  value: approved,                     color: "var(--accent-green)"  },
          { label: "Rejected",  value: rejected,                     color: "var(--accent-red)"    },
          { label: "Submitted", value: submitted,                    color: "var(--accent-blue)"   },
          { label: "Open",      value: pending + changesRequested,   color: "var(--accent-yellow)" },
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
