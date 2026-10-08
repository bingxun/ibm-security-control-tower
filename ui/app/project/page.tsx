"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import TopNav from "@/components/TopNav";
import { SevBadge, StatusChip, RunStatusBadge } from "@/components/Badges";
import { listScans, ScanSummary } from "@/lib/api";

interface ImageRow {
  image: string;
  scan: ScanSummary;
}

// ── Inner page (uses useSearchParams) ────────────────────────────────────
function ProjectPageInner() {
  const searchParams = useSearchParams();
  const name = searchParams.get("name");

  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!name) {
      setLoading(false);
      return;
    }
    listScans()
      .then((s) => setScans(s))
      .catch((e) => setError(e.message ?? "Failed to reach backend"))
      .finally(() => setLoading(false));
  }, [name]);

  const projectScans = useMemo(
    () => scans.filter((s) => s.project === name),
    [scans, name]
  );

  // API already returns newest-first, so the first scan seen per image is its latest.
  const images = useMemo<ImageRow[]>(() => {
    const seen = new Map<string, ImageRow>();
    for (const scan of projectScans) {
      if (!seen.has(scan.image)) {
        seen.set(scan.image, { image: scan.image, scan });
      }
    }
    return Array.from(seen.values());
  }, [projectScans]);

  return (
    <div
      className="flex flex-col h-screen overflow-hidden"
      style={{ background: "var(--bg)", color: "var(--heading)" }}
    >
      <TopNav projectName={name ?? undefined} />

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-8 py-8 flex flex-col gap-8">

          {/* ── Header ── */}
          <div className="flex items-start justify-between gap-6">
            <div>
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 text-[12px] mb-2 transition-opacity hover:opacity-70"
                style={{ color: "var(--muted)" }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <polyline points="15 18 9 12 15 6"/>
                </svg>
                Dashboard
              </Link>
              <h1
                className="text-[26px] font-black tracking-tight"
                style={{ color: "var(--heading)" }}
              >
                {name ?? "Project"}
              </h1>
              <p className="text-[14px] mt-1" style={{ color: "var(--subtle)" }}>
                Container images scanned under this project.
              </p>
            </div>
          </div>

          {/* ── Images table ── */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>
                Container Images
              </h2>
              <span className="text-[12px]" style={{ color: "var(--muted)" }}>
                {loading ? "Loading…" : `${images.length} images`}
              </span>
            </div>

            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                boxShadow: "var(--shadow-card)",
              }}
            >
              {/* Missing name param */}
              {!name && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--accent-red)" }}>
                  No project specified. Go back to{" "}
                  <Link href="/dashboard" style={{ color: "var(--accent-blue)" }}>Dashboard</Link>
                  {" "}and pick a project.
                </div>
              )}

              {/* Loading */}
              {name && loading && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--muted)" }}>
                  Loading images…
                </div>
              )}

              {/* Error */}
              {name && !loading && error && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--accent-red)" }}>
                  {error}
                </div>
              )}

              {/* Empty state */}
              {name && !loading && !error && images.length === 0 && (
                <div className="px-5 py-12 flex flex-col items-center gap-3">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" strokeWidth="1.5" strokeLinecap="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                  </svg>
                  <p className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>No images found</p>
                  <p className="text-[12px]" style={{ color: "var(--muted)" }}>No scans exist for this project yet.</p>
                </div>
              )}

              {/* Table header + rows */}
              {name && !loading && !error && images.length > 0 && (
              <div className="overflow-x-auto">
              <div className="min-w-[840px]">
              <div
                className="grid grid-cols-12 px-5 py-3 text-[11px] font-semibold uppercase tracking-wider"
                style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)" }}
              >
                <div className="col-span-4">Image</div>
                <div className="col-span-2">Findings</div>
                <div className="col-span-2">Approval</div>
                <div className="col-span-2">Scan Progress</div>
                <div className="col-span-2 text-right">Date</div>
              </div>

              {images.map((row, i) => (
                <Link
                  key={row.image}
                  href={`/review?run=${row.scan.id}`}
                  className="grid grid-cols-12 px-5 py-4 items-center transition-colors"
                  style={{
                    borderBottom: i < images.length - 1 ? "1px solid var(--border)" : "none",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  {/* Image */}
                  <div className="col-span-4 min-w-0">
                    <p
                      className="text-[12px] font-mono truncate"
                      style={{ color: "var(--body)" }}
                    >
                      {row.image}
                    </p>
                    <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>
                      {row.scan.duration}
                    </p>
                  </div>

                  {/* Findings */}
                  <div className="col-span-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <SevBadge label="C" count={row.scan.critical} color="var(--accent-red)"    />
                      <SevBadge label="H" count={row.scan.high}     color="var(--accent-orange)" />
                      <SevBadge label="M" count={row.scan.medium}   color="var(--accent-yellow)" />
                    </div>
                    <p className="text-[11px] mt-1" style={{ color: "var(--muted)" }}>
                      {row.scan.totalCves} total
                    </p>
                  </div>

                  {/* Approval bar */}
                  <div className="col-span-2">
                    <StatusChip
                      status={row.scan.status}
                      approved={row.scan.approved}
                      total={row.scan.totalCves}
                    />
                    {row.scan.rejected > 0 && (
                      <p className="text-[11px] mt-0.5" style={{ color: "var(--accent-red)" }}>
                        {row.scan.rejected} rejected
                      </p>
                    )}
                  </div>

                  {/* Scan Progress */}
                  <div className="col-span-2">
                    <RunStatusBadge status={row.scan.status} />
                  </div>

                  {/* Date */}
                  <div className="col-span-2 text-right">
                    <span className="text-[11px]" style={{ color: "var(--muted)" }}>
                      {row.scan.date}
                    </span>
                  </div>
                </Link>
              ))}
              </div>
              </div>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

// ── Export with Suspense boundary for useSearchParams ─────────────────────
export default function ProjectPage() {
  return (
    <Suspense>
      <ProjectPageInner />
    </Suspense>
  );
}
