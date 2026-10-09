"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import type { Project, ScanSummary } from "@/lib/api";
import { downloadReport } from "@/lib/api";
import { RunStatusBadge, type ScanStatus } from "./Badges";

function ReportControl({ runId }: { runId: string }) {
  const grab = (fmt: "csv" | "pdf") => downloadReport(runId, fmt).catch(() => alert("Report download failed."));
  return (
    <span className="inline-flex items-center gap-1">
      {(["csv", "pdf"] as const).map((fmt) => (
        <button
          key={fmt}
          type="button"
          onClick={() => grab(fmt)}
          className="text-[10px] font-bold uppercase px-1.5 py-1 rounded-md"
          style={{ background: "var(--surface2)", color: "var(--accent-blue)", border: "1px solid var(--border)" }}
          title={`Download ${fmt.toUpperCase()} report`}
        >
          {fmt}
        </button>
      ))}
    </span>
  );
}

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
  reportable = false,
}: {
  scans: ScanSummary[];
  projects: Project[];
  loading: boolean;
  error: string | null;
  emptyTitle: string;
  emptyBody: string;
  emptyActions?: ReactNode;
  reportable?: boolean;
}) {
  return (
    <div
      className="rounded-2xl overflow-hidden"
      style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}
    >
      {loading && (
        <div>
          <div className="grid grid-cols-12 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="col-span-1 h-3 ct-skeleton" style={{ width: "60%" }} />
            <div className="col-span-2 h-3 ct-skeleton mr-4" />
            <div className="col-span-3 h-3 ct-skeleton mr-4" />
            <div className="col-span-2 h-3 ct-skeleton mr-4" />
            <div className="col-span-2 h-3 ct-skeleton mr-4" />
            <div className="col-span-2 h-3 ct-skeleton" />
          </div>
          {[0, 1, 2, 3].map((r) => (
            <div key={r} className="grid grid-cols-12 items-center gap-4 px-5 py-4" style={{ borderBottom: r < 3 ? "1px solid var(--border)" : "none" }}>
              <div className="col-span-1 h-3.5 ct-skeleton" />
              <div className="col-span-2 h-6 ct-skeleton" />
              <div className="col-span-3 h-3.5 ct-skeleton" />
              <div className="col-span-2 h-5 ct-skeleton" />
              <div className="col-span-2 h-3.5 ct-skeleton" />
              <div className="col-span-2 h-3.5 ct-skeleton" />
            </div>
          ))}
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

      {!loading && !error && scans.length > 0 && (
      <div className="overflow-x-auto"><div className="min-w-[640px]">
        <div
          className="grid grid-cols-12 px-5 py-3 text-[11px] font-semibold uppercase tracking-wider"
          style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)" }}
        >
          <div className="col-span-1">ID</div>
          <div className="col-span-2">Project</div>
          <div className="col-span-3">Image</div>
          <div className="col-span-2">Findings</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-1 text-right">Date</div>
          <div className="col-span-1 text-right">{reportable ? "Report" : ""}</div>
        </div>

        {scans.map((scan, i) => (
          <div
            key={scan.id}
            className="grid grid-cols-12 items-center transition-colors"
            style={{ borderBottom: i < scans.length - 1 ? "1px solid var(--border)" : "none" }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <Link href={`/review?run=${scan.id}`} className="col-span-11 grid grid-cols-11 px-5 py-4 items-center">
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

              <div className="col-span-3 min-w-0">
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
                <RunStatusBadge status={scan.status as ScanStatus} />
                <div className="mt-1.5"><StatusChip approved={scan.approved} total={scan.totalCves} /></div>
                {scan.rejected > 0 && (
                  <p className="text-[11px] mt-0.5" style={{ color: "var(--accent-red)" }}>{scan.rejected} rejected</p>
                )}
              </div>

              <div className="col-span-1 text-right">
                <span className="text-[11px]" style={{ color: "var(--muted)" }}>{scan.date}</span>
              </div>
            </Link>

            <div className="col-span-1 pr-4 flex justify-end">
              {reportable && <ReportControl runId={scan.id} />}
            </div>
          </div>
        ))}
      </div></div>
      )}
    </div>
  );
}
