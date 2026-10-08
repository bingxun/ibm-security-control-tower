"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import ScansTable from "@/components/ScansTable";
import ProjectReports from "@/components/ProjectReports";
import ProjectIcon from "@/components/ProjectIcon";
import { PostureCard } from "@/components/home/HomeKit";
import management from "@/components/Management.module.css";
import { useAuth } from "@/lib/auth";
import { listScans, listProjects, type Project, type ScanSummary } from "@/lib/api";

type ScanFilter = "all" | "review" | "progress" | "done";
const FILTERS: { key: ScanFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "review", label: "Awaiting review" },
  { key: "progress", label: "In progress" },
  { key: "done", label: "Completed" },
];
function matchesFilter(s: ScanSummary, f: ScanFilter): boolean {
  if (f === "all") return true;
  if (f === "review") return s.status === "awaiting_approval";
  if (f === "done") return s.status === "completed";
  return ["queued", "scanning", "running"].includes(s.status);
}

function NewScanButton() {
  return (
    <Link
      href="/new-scan"
      className="flex items-center gap-2.5 px-5 py-2.5 rounded-xl text-[13px] font-bold flex-shrink-0 transition-opacity hover:opacity-85"
      style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 24px var(--btn-accept-glow)" }}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
        <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
      </svg>
      New Scan
    </Link>
  );
}

function ProjectScansInner() {
  const searchParams = useSearchParams();
  const projectId = searchParams.get("project") ?? undefined;
  const { permissions } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const [filter, setFilter] = useState<ScanFilter>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    Promise.all([listScans(projectId), listProjects()])
      .then(([s, p]) => { if (!cancelled) { setScans(s); setProjects(p); setError(null); } })
      .catch((e) => { if (!cancelled) setError(e.message ?? "Failed to reach backend"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [projectId, retry]);

  const project = projects.find(p => p.id === projectId);

  // Drill-down shows the latest scan per image (scans arrive newest-first).
  const latestPerImage = Array.from(
    scans.reduce((map, s) => (map.has(s.image) ? map : map.set(s.image, s)), new Map<string, ScanSummary>()).values()
  );

  const q = query.trim().toLowerCase();
  const visibleScans = latestPerImage.filter((s) => {
    if (!matchesFilter(s, filter)) return false;
    if (!q) return true;
    const projName = (projects.find((p) => p.id === s.project)?.name ?? "").toLowerCase();
    return s.image.toLowerCase().includes(q) || projName.includes(q);
  });

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: "var(--bg)", color: "var(--heading)" }}>
      <TopNav />
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-8 py-8 flex flex-col gap-6">

          <div>
            <Link href="/dashboard" className="inline-flex items-center gap-1.5 text-[12px] font-semibold" style={{ color: "var(--accent-blue)" }}>
              <span aria-hidden="true">←</span> Back to dashboard
            </Link>
            <div className="flex items-start justify-between gap-6 mt-3">
              <div className="flex items-center gap-3 min-w-0">
                <span className={management.projectIcon}><ProjectIcon /></span>
                <div className="min-w-0">
                  <h1 className="text-[24px] font-black tracking-tight truncate" style={{ color: "var(--heading)" }}>
                    {projectId ? (project?.name ?? "Project") : "All scans"}
                  </h1>
                  <p className="text-[13px] mt-0.5" style={{ color: "var(--subtle)" }}>
                    {projectId ? (project?.description || "Container security workspace") : "Scans across your accessible projects"}
                  </p>
                </div>
              </div>
              {permissions?.canScan && <NewScanButton />}
            </div>
          </div>

          {!loading && !error && latestPerImage.length > 0 && (
            <div className="ct-fade-up"><PostureCard scans={latestPerImage} /></div>
          )}

          {projectId && project && <ProjectReports key={projectId} projectId={projectId} onImported={() => setRetry(n => n + 1)} />}

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-1.5 p-1 rounded-xl" style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}>
              {FILTERS.map((f) => {
                const n = latestPerImage.filter((s) => matchesFilter(s, f.key)).length;
                const active = filter === f.key;
                return (
                  <button key={f.key} type="button" onClick={() => setFilter(f.key)}
                    className="px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors"
                    style={{ background: active ? "var(--surface)" : "transparent", color: active ? "var(--heading)" : "var(--muted)", boxShadow: active ? "var(--shadow-card)" : "none" }}>
                    {f.label}<span className="ml-1.5 font-mono" style={{ color: active ? "var(--accent-blue)" : "var(--dim)" }}>{n}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-3">
              <div className="relative">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="2" strokeLinecap="round" className="absolute left-3 top-1/2 -translate-y-1/2">
                  <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search image or project…"
                  className="pl-9 pr-3 py-2 rounded-xl text-[12px] outline-none w-60"
                  style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }} />
              </div>
              <button type="button" className={management.button} onClick={() => { setLoading(true); setError(null); setRetry(n => n + 1); }} disabled={loading}>Refresh</button>
            </div>
          </div>

          <ScansTable
            scans={visibleScans}
            projects={projects}
            loading={loading}
            error={error}
            reportable
            emptyTitle={query || filter !== "all" ? "No matching scans" : project ? `No scans in ${project.name}` : "No scans yet"}
            emptyBody={query || filter !== "all" ? "Try a different filter or search term." : "Run a scan to see results here."}
            emptyActions={permissions?.canScan && !query && filter === "all" ? <NewScanButton /> : undefined}
          />

        </div>
      </div>
    </div>
  );
}

export default function ProjectScansPage() {
  return (
    <RequireAuth>
      <Suspense fallback={null}>
        <ProjectScansInner />
      </Suspense>
    </RequireAuth>
  );
}
