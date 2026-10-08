"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import ScansTable from "@/components/ScansTable";
import ProjectIcon from "@/components/ProjectIcon";
import management from "@/components/Management.module.css";
import { useAuth } from "@/lib/auth";
import { listScans, listProjects, type Project, type ScanSummary } from "@/lib/api";

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

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(null);
    Promise.all([listScans(projectId), listProjects()])
      .then(([s, p]) => { if (!cancelled) { setScans(s); setProjects(p); } })
      .catch((e) => { if (!cancelled) setError(e.message ?? "Failed to reach backend"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [projectId, retry]);

  const project = projects.find(p => p.id === projectId);

  // Drill-down shows the latest scan per image (scans arrive newest-first).
  const latestPerImage = Array.from(
    scans.reduce((map, s) => (map.has(s.image) ? map : map.set(s.image, s)), new Map<string, ScanSummary>()).values()
  );

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

          <div className="flex items-center justify-between gap-3">
            <h2 className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>Images</h2>
            <div className="flex items-center gap-3">
              <span className="text-[12px]" style={{ color: "var(--muted)" }}>{loading ? "Loading…" : `${latestPerImage.length} ${latestPerImage.length === 1 ? "image" : "images"}`}</span>
              <button type="button" className={management.button} onClick={() => setRetry(n => n + 1)} disabled={loading}>Refresh</button>
            </div>
          </div>

          <ScansTable
            scans={latestPerImage}
            projects={projects}
            loading={loading}
            error={error}
            reportable
            emptyTitle={project ? `No scans in ${project.name}` : "No scans yet"}
            emptyBody="Run a scan to see results here."
            emptyActions={permissions?.canScan ? <NewScanButton /> : undefined}
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
