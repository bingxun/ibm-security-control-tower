"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import { listScans, getDashboardStats, ScanSummary, DashboardStats } from "@/lib/api";

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

function StatusChip({ status, approved, total }: { status: string; approved: number; total: number }) {
  const pct = Math.round((approved / total) * 100);
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

  useEffect(() => {
    Promise.all([listScans(), getDashboardStats()])
      .then(([s, d]) => {
        setScans(s);
        setDashStats(d);
      })
      .catch((e) => setError(e.message ?? "Failed to reach backend"))
      .finally(() => setLoading(false));
  }, []);

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
          <div className="flex items-start justify-between gap-6">
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
          <div className="grid grid-cols-4 gap-4">
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
            className="rounded-2xl px-6 py-4 flex items-center gap-8"
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
              <div key={p.step} className="flex items-center gap-3 flex-1">
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
                  <svg className="ml-auto flex-shrink-0" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--dim)" strokeWidth="2" strokeLinecap="round">
                    <polyline points="9 18 15 12 9 6"/>
                  </svg>
                )}
              </div>
            ))}
          </div>

          {/* ── Recent scans table ── */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>
                Recent Scans
              </h2>
              <span className="text-[12px]" style={{ color: "var(--muted)" }}>
                {loading ? "Loading…" : `${scans.length} scans`}
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
              {!loading && !error && scans.length === 0 && (
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

              {/* Table header + rows */}
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
                  style={{
                    borderBottom: i < scans.length - 1 ? "1px solid var(--border)" : "none",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  {/* ID */}
                  <div className="col-span-1">
                    <span
                      className="text-[11px] font-mono font-semibold"
                      style={{ color: "var(--accent-blue)" }}
                    >
                      {scan.id}
                    </span>
                  </div>

                  {/* Project */}
                  <div className="col-span-2">
                    <span
                      className="text-[12px] font-mono font-semibold px-2 py-0.5 rounded"
                      style={{ background: "var(--surface2)", color: "var(--faint)", border: "1px solid var(--border)" }}
                    >
                      {scan.project}
                    </span>
                  </div>

                  {/* Image */}
                  <div className="col-span-4 min-w-0">
                    <p
                      className="text-[12px] font-mono truncate"
                      style={{ color: "var(--body)" }}
                    >
                      {scan.image}
                    </p>
                    <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>
                      {scan.duration}
                    </p>
                  </div>

                  {/* Findings */}
                  <div className="col-span-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <SevBadge label="C" count={scan.critical} color="var(--accent-red)"    />
                      <SevBadge label="H" count={scan.high}     color="var(--accent-orange)" />
                      <SevBadge label="M" count={scan.medium}   color="var(--accent-yellow)" />
                    </div>
                    <p className="text-[11px] mt-1" style={{ color: "var(--muted)" }}>
                      {scan.totalCves} total
                    </p>
                  </div>

                  {/* Approval bar */}
                  <div className="col-span-2">
                    <StatusChip
                      status={scan.status}
                      approved={scan.approved}
                      total={scan.totalCves}
                    />
                    {scan.rejected > 0 && (
                      <p className="text-[11px] mt-0.5" style={{ color: "var(--accent-red)" }}>
                        {scan.rejected} rejected
                      </p>
                    )}
                  </div>

                  {/* Date */}
                  <div className="col-span-1 text-right">
                    <span className="text-[11px]" style={{ color: "var(--muted)" }}>
                      {scan.date}
                    </span>
                  </div>
                </Link>
              ))}
              </>)}
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
