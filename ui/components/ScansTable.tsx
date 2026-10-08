"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import type { Project, ScanSummary } from "@/lib/api";

function SevBadge({ label, count, color }: { label: string; count: number; color: string }) {
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

function StatusChip({ approved, total }: { approved: number; total: number }) {
  const pct = total ? Math.round((approved / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
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

export default function ScansTable({
  scans,
  projects,
  loading,
  error,
  emptyTitle,
  emptyBody,
  emptyActions,
}: {
  scans: ScanSummary[];
  projects: Project[];
  loading: boolean;
  error: string | null;
  emptyTitle: string;
  emptyBody: string;
  emptyActions?: ReactNode;
}) {
  return (
    <div
      className="rounded-2xl overflow-hidden"
      style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}
    >
      {loading && (
        <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--muted)" }}>
          Loading scans…
        </div>
      )}

      {!loading && error && (
        <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--accent-red)" }}>
          {error}
        </div>
      )}

      {!loading && !error && scans.length === 0 && (
        <div className="px-5 py-12 flex flex-col items-center gap-3">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" strokeWidth="1.5" strokeLinecap="round">
            <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <p className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>{emptyTitle}</p>
          <p className="text-[12px] text-center max-w-xs" style={{ color: "var(--muted)" }}>{emptyBody}</p>
          {emptyActions && <div className="mt-1 flex items-center gap-2">{emptyActions}</div>}
        </div>
      )}

      {!loading && !error && scans.length > 0 && (<>
        <div
          className="grid grid-cols-12 px-5 py-3 text-[11px] font-semibold uppercase tracking-wider"
          style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)" }}
        >
          <div className="col-span-1">ID</div>
          <div className="col-span-2">Project</div>
          <div className="col-span-4">Image</div>
          <div className="col-span-2">Findings</div>
          <div className="col-span-2">Approval</div>
          <div className="col-span-1 text-right">Date</div>
        </div>

        {scans.map((scan, i) => (
          <Link
            key={scan.id}
            href={`/review?run=${scan.id}`}
            className="grid grid-cols-12 px-5 py-4 items-center transition-colors"
            style={{ borderBottom: i < scans.length - 1 ? "1px solid var(--border)" : "none" }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <div className="col-span-1 min-w-0 pr-3">
              <span title={scan.id} className="block truncate text-[12px] font-mono font-semibold" style={{ color: "var(--accent-blue)" }}>
                #{scan.seq}
              </span>
            </div>

            <div className="col-span-2 min-w-0 pr-3">
              <span
                title={projects.find(p => p.id === scan.project)?.name ?? scan.project}
                className="block truncate text-[12px] font-semibold px-2 py-1 rounded-md"
                style={{ background: "var(--surface2)", color: "var(--faint)", border: "1px solid var(--border)" }}
              >
                {projects.find(p => p.id === scan.project)?.name ?? scan.project}
              </span>
            </div>

            <div className="col-span-4 min-w-0">
              <p className="text-[12px] font-mono truncate" style={{ color: "var(--body)" }}>{scan.image}</p>
              <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{scan.duration}</p>
            </div>

            <div className="col-span-2">
              <div className="flex items-center gap-1.5 flex-wrap">
                <SevBadge label="C" count={scan.critical} color="var(--accent-red)" />
                <SevBadge label="H" count={scan.high} color="var(--accent-orange)" />
                <SevBadge label="M" count={scan.medium} color="var(--accent-yellow)" />
              </div>
              <p className="text-[11px] mt-1" style={{ color: "var(--muted)" }}>{scan.totalCves} total</p>
            </div>

            <div className="col-span-2">
              <StatusChip approved={scan.approved} total={scan.totalCves} />
              {scan.rejected > 0 && (
                <p className="text-[11px] mt-0.5" style={{ color: "var(--accent-red)" }}>{scan.rejected} rejected</p>
              )}
            </div>

            <div className="col-span-1 text-right">
              <span className="text-[11px]" style={{ color: "var(--muted)" }}>{scan.date}</span>
            </div>
          </Link>
        ))}
      </>)}
    </div>
  );
}
