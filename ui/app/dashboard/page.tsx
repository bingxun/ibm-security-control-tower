"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import TopNav from "@/components/TopNav";
import { SevBadge, StatusChip } from "@/components/Badges";
import RequireAuth from "@/components/RequireAuth";
import { listScans, getDashboardStats, ScanSummary, DashboardStats } from "@/lib/api";

interface ProjectSummary {
  project: string;
  imageCount: number;
  totalCves: number;
  critical: number;
  high: number;
  medium: number;
  approved: number;
  latestDate: string;
}

const EMPTY_STATS: DashboardStats = {
  totalScans: 0,
  cvesTriaged: 0,
  avgApprovalRate: 0,
  ragDecisions: 0,
  ragFirstPassRate: 0,
};

function DashboardPageInner() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [dashStats, setDashStats] = useState<DashboardStats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projectFilter, setProjectFilter] = useState<string>("");

  useEffect(() => {
    Promise.all([listScans(), getDashboardStats()])
      .then(([s, d]) => {
        setScans(s);
        setDashStats(d);
      })
      .catch((e) => setError(e.message ?? "Failed to reach backend"))
      .finally(() => setLoading(false));
  }, []);

  const projects = useMemo<ProjectSummary[]>(() => {
    const byProject = new Map<string, ProjectSummary & { images: Set<string> }>();
    for (const scan of scans) {
      let p = byProject.get(scan.project);
      if (!p) {
        p = {
          project: scan.project,
          imageCount: 0,
          totalCves: 0,
          critical: 0,
          high: 0,
          medium: 0,
          approved: 0,
          latestDate: scan.date,
          images: new Set<string>(),
        };
        byProject.set(scan.project, p);
      }
      p.images.add(scan.image);
      p.totalCves += scan.totalCves;
      p.critical += scan.critical;
      p.high += scan.high;
      p.medium += scan.medium;
      p.approved += scan.approved;
      if (scan.date > p.latestDate) p.latestDate = scan.date;
    }
    return Array.from(byProject.values()).map((p) => ({
      ...p,
      imageCount: p.images.size,
    }));
  }, [scans]);

  const filteredProjects = useMemo(
    () => (projectFilter ? projects.filter((p) => p.project === projectFilter) : projects),
    [projects, projectFilter]
  );

  const statsRow = [
    { label: "Total scans",        value: String(dashStats.totalScans),               sub: "all time",          color: "var(--accent-blue)"   },
    { label: "CVEs triaged",       value: String(dashStats.cvesTriaged),              sub: "across all scans",  color: "var(--accent-purple)" },
    { label: "Avg. approval rate", value: `${dashStats.avgApprovalRate}%`,            sub: "first-pass",        color: "var(--accent-green)"  },
    { label: "Time saved",         value: "~18h",                                     sub: "vs. manual triage", color: "var(--accent-yellow)" },
  ];

  return (
    <div
      className="flex flex-col h-screen overflow-hidden"
      style={{ background: "var(--bg)", color: "var(--heading)" }}
    >
      <TopNav />

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-8 py-8 flex flex-col gap-8">

          {/* ── Hero row ── */}
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div>
              <h1
                className="text-[26px] font-black tracking-tight"
                style={{ color: "var(--heading)" }}
              >
                Security Control Tower
              </h1>
              <p className="text-[14px] mt-1" style={{ color: "var(--subtle)" }}>
                Welcome back, <span style={{ color: "var(--heading)" }}>Auth Lead</span>.
                You have <span style={{ color: "var(--accent-yellow)" }}>5 CVEs</span> pending review.
              </p>
            </div>

            <Link
              href="/new-scan"
              className="flex items-center gap-2.5 px-6 py-3 rounded-xl text-[14px] font-bold flex-shrink-0 transition-opacity hover:opacity-85"
              style={{
                background: "var(--btn-accept-bg)",
                color: "var(--btn-accept-text)",
                boxShadow: "0 0 24px var(--btn-accept-glow)",
              }}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              New Scan
            </Link>
          </div>

          {/* ── Stats row ── */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {statsRow.map((s) => (
              <div
                key={s.label}
                className="rounded-2xl px-5 py-4"
                style={{
                  background: "var(--surface)",
                  border: "1px solid var(--border)",
                  boxShadow: "var(--shadow-card)",
                }}
              >
                <div
                  className="text-[28px] font-black leading-none"
                  style={{ color: s.color }}
                >
                  {s.value}
                </div>
                <div className="text-[12px] font-semibold mt-1.5" style={{ color: "var(--heading)" }}>
                  {s.label}
                </div>
                <div className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>
                  {s.sub}
                </div>
              </div>
            ))}
          </div>

          {/* ── Pipeline reminder ── */}
          <div
            className="rounded-2xl px-6 py-4 flex flex-wrap items-center gap-4 lg:gap-8"
            style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
          >
            <span className="text-[12px] font-semibold uppercase tracking-wider flex-shrink-0" style={{ color: "var(--muted)" }}>
              Agent pipeline
            </span>
            {[
              { step: "01", label: "Scan Ingest",    desc: "Parse CVE findings",         color: "var(--accent-blue)"   },
              { step: "02", label: "Synthesis",       desc: "Generate rationale",         color: "var(--accent-purple)" },
              { step: "03", label: "Human Approval",  desc: "Authority review gate",      color: "var(--accent-yellow)" },
              { step: "04", label: "Persistence",     desc: "Store to RAG memory",        color: "var(--accent-green)"  },
            ].map((p, i) => (
              <div key={p.step} className="flex items-center gap-3 flex-1 min-w-[160px]">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center text-[11px] font-black flex-shrink-0"
                  style={{ background: `${p.color}18`, color: p.color }}
                >
                  {p.step}
                </div>
                <div>
                  <div className="text-[12px] font-semibold" style={{ color: "var(--heading)" }}>{p.label}</div>
                  <div className="text-[11px]" style={{ color: "var(--muted)" }}>{p.desc}</div>
                </div>
                {i < 3 && (
                  <svg className="ml-auto flex-shrink-0 hidden lg:block" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" strokeWidth="2" strokeLinecap="round">
                    <polyline points="9 18 15 12 9 6"/>
                  </svg>
                )}
              </div>
            ))}
          </div>

          {/* ── Projects table ── */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>
                Projects
              </h2>
              <div className="flex items-center gap-3">
                <select
                  value={projectFilter}
                  onChange={(e) => setProjectFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg text-[13px] outline-none appearance-none"
                  style={{
                    background: "var(--surface2)",
                    border: "1px solid var(--border)",
                    color: "var(--body)",
                    backgroundImage:
                      "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236e7681' stroke-width='2.5' stroke-linecap='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E\")",
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "right 12px center",
                    paddingRight: "32px",
                  }}
                >
                  <option value="">All Projects</option>
                  {projects.map((p) => (
                    <option key={p.project} value={p.project}>{p.project}</option>
                  ))}
                </select>
                <span className="text-[12px]" style={{ color: "var(--muted)" }}>
                  {loading
                    ? "Loading…"
                    : `${filteredProjects.length} project${filteredProjects.length === 1 ? "" : "s"}`}
                </span>
              </div>
            </div>

            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "var(--surface)",
                border: "1px solid var(--border)",
                boxShadow: "var(--shadow-card)",
              }}
            >
              {/* Loading */}
              {loading && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--muted)" }}>
                  Loading scans…
                </div>
              )}

              {/* Error */}
              {!loading && error && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--accent-red)" }}>
                  {error}
                </div>
              )}

              {/* Empty state */}
              {!loading && !error && projects.length === 0 && (
                <div className="px-5 py-12 flex flex-col items-center gap-3">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" strokeWidth="1.5" strokeLinecap="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                  </svg>
                  <p className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>No scans yet</p>
                  <p className="text-[12px]" style={{ color: "var(--muted)" }}>Run your first scan to see results here.</p>
                  <Link
                    href="/new-scan"
                    className="mt-1 px-4 py-2 rounded-lg text-[12px] font-bold"
                    style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)" }}
                  >
                    New Scan
                  </Link>
                </div>
              )}

              {/* Filtered-empty state (no project matches the selected filter) */}
              {!loading && !error && projects.length > 0 && filteredProjects.length === 0 && (
                <div className="px-5 py-10 text-center text-[13px]" style={{ color: "var(--muted)" }}>
                  No project matches the selected filter.
                </div>
              )}

              {/* Table header + rows */}
              {!loading && !error && projects.length > 0 && filteredProjects.length > 0 && (
              <div className="overflow-x-auto">
              <div className="min-w-[720px]">
              <div
                className="grid grid-cols-12 px-5 py-3 text-[11px] font-semibold uppercase tracking-wider"
                style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)" }}
              >
                <div className="col-span-3">Project</div>
                <div className="col-span-3">Images</div>
                <div className="col-span-2">Findings</div>
                <div className="col-span-3">Approval</div>
                <div className="col-span-1 text-right">Date</div>
              </div>

              {filteredProjects.map((p, i) => (
                <Link
                  key={p.project}
                  href={`/project?name=${encodeURIComponent(p.project)}`}
                  className="grid grid-cols-12 px-5 py-4 items-center transition-colors"
                  style={{
                    borderBottom: i < filteredProjects.length - 1 ? "1px solid var(--border)" : "none",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  {/* Project */}
                  <div className="col-span-3">
                    <span
                      className="text-[12px] font-mono font-semibold px-2 py-0.5 rounded"
                      style={{ background: "var(--surface2)", color: "var(--faint)", border: "1px solid var(--border)" }}
                    >
                      {p.project}
                    </span>
                  </div>

                  {/* Images */}
                  <div className="col-span-3 min-w-0">
                    <p className="text-[12px]" style={{ color: "var(--body)" }}>
                      {p.imageCount} container image{p.imageCount === 1 ? "" : "s"}
                    </p>
                  </div>

                  {/* Findings */}
                  <div className="col-span-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <SevBadge label="C" count={p.critical} color="var(--accent-red)"    />
                      <SevBadge label="H" count={p.high}     color="var(--accent-orange)" />
                      <SevBadge label="M" count={p.medium}   color="var(--accent-yellow)" />
                    </div>
                    <p className="text-[11px] mt-1" style={{ color: "var(--muted)" }}>
                      {p.totalCves} total
                    </p>
                  </div>

                  {/* Approval bar */}
                  <div className="col-span-3">
                    <StatusChip
                      status="completed"
                      approved={p.approved}
                      total={p.totalCves}
                    />
                  </div>

                  {/* Date */}
                  <div className="col-span-1 text-right">
                    <span className="text-[11px]" style={{ color: "var(--muted)" }}>
                      {p.latestDate}
                    </span>
                  </div>
                </Link>
              ))}
              </div>
              </div>
              )}
            </div>
          </div>

          {/* ── RAG memory callout ── */}
          <div
            className="rounded-2xl px-6 py-5 flex items-center gap-5"
            style={{
              background: "var(--accent-purple-bg)",
              border: "1px solid var(--accent-purple-bdr)",
            }}
          >
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-[18px]"
              style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}
            >
              ◈
            </div>
            <div className="flex-1">
              <p className="text-[13px] font-bold" style={{ color: "var(--accent-purple)" }}>
                RAG Memory Store — {dashStats.ragDecisions} decisions persisted
              </p>
              <p className="text-[12px] mt-0.5" style={{ color: "var(--subtle)" }}>
                Every approved rationale is stored and reused for future scans. Your team's security knowledge compounds over time — reducing synthesis time and improving first-pass approval rates.
              </p>
            </div>
            <div className="text-right flex-shrink-0">
              <div className="text-[22px] font-black" style={{ color: "var(--accent-purple)" }}>{dashStats.ragFirstPassRate}%</div>
              <div className="text-[11px]" style={{ color: "var(--muted)" }}>first-pass rate</div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <RequireAuth>
      <DashboardPageInner />
    </RequireAuth>
  );
}
