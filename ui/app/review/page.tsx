"use client";

import { useState, useMemo, useEffect, useCallback, useRef, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import CveQueue from "@/components/CveQueue";
import CveReview from "@/components/CveReview";
import ContextPanel from "@/components/ContextPanel";
import { MOCK_STATS } from "@/lib/mockData";
import { CveRecord, AgentStep, RunStats, cveKey } from "@/lib/types";
import { streamRun, submitDecision, getRun } from "@/lib/api";

// ── Synthesis progress screen ──────────────────────────────────────────────
function SynthesisLoader({
  agentSteps,
  cves,
  trivyLogs,
  imageRef,
}: {
  agentSteps: import("@/lib/types").AgentStep[];
  cves: import("@/lib/types").CveRecord[];
  trivyLogs: string[];
  imageRef: string;
}) {
  const total     = cves.length;
  const synthesised = cves.filter((c) => c.status === "pending" || c.status === "approved" || c.status === "rejected").length;
  const pct       = total > 0 ? Math.round((synthesised / total) * 100) : 0;

  const sevCounts = cves.reduce<Record<string, number>>((acc, c) => {
    acc[c.severity] = (acc[c.severity] ?? 0) + 1; return acc;
  }, {});

  const stages = [
    { label: "Image Scan", done: true  },
    { label: "Ingest",     done: true  },
    { label: "Synthesis",  done: false, active: true },
    { label: "Approval",   done: false, active: false },
  ];

  return (
    <div className="flex-1 overflow-y-auto flex flex-col gap-5 px-8 py-7" style={{ background: "var(--bg)" }}>

      {/* ── Pipeline stages ── */}
      <div className="rounded-2xl px-6 py-4 flex items-center gap-3"
        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
        <span className="text-[11px] font-bold uppercase tracking-wider flex-shrink-0" style={{ color: "var(--muted)" }}>
          Pipeline
        </span>
        <div className="flex items-center gap-2 flex-1">
          {stages.map((s, i) => (
            <div key={s.label} className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold" style={{
                background: s.active ? "var(--accent-purple-bg)" : s.done ? "var(--accent-green-bg)" : "var(--surface2)",
                color:      s.active ? "var(--accent-purple)"    : s.done ? "var(--accent-green)"   : "var(--dim)",
                border:     `1px solid ${s.active ? "var(--accent-purple-bdr)" : s.done ? "var(--accent-green-bdr)" : "var(--border)"}`,
              }}>
                {s.active && <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-purple)" }} />}
                {s.done   && <span>✓</span>}
                {!s.active && !s.done && <span>—</span>}
                {s.label}
              </div>
              {i < stages.length - 1 && <div className="w-4 h-px" style={{ background: "var(--border)" }} />}
            </div>
          ))}
        </div>
      </div>

      {/* ── Synthesis progress ── */}
      <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
          <span className="w-2 h-2 rounded-full animate-pulse flex-shrink-0" style={{ background: "var(--accent-purple)" }} />
          <span className="text-[13px] font-semibold" style={{ color: "var(--accent-purple)" }}>
            Synthesising rationale via Bob MCP…
          </span>
          <span className="ml-auto text-[12px] font-mono font-bold" style={{ color: "var(--heading)" }}>
            {synthesised} / {total}
          </span>
        </div>

        {/* Progress bar */}
        <div className="px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px]" style={{ color: "var(--muted)" }}>CVEs synthesised</span>
            <span className="text-[11px] font-bold" style={{ color: "var(--accent-purple)" }}>{pct}%</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
            <div className="h-full rounded-full transition-all duration-500"
              style={{ width: `${pct}%`, background: "linear-gradient(90deg, var(--accent-purple), var(--accent-blue))" }} />
          </div>
          {/* Severity breakdown */}
          {total > 0 && (
            <div className="flex items-center gap-3 mt-3">
              {[
                { sev: "critical", color: "var(--accent-red)",    label: "C" },
                { sev: "high",     color: "var(--accent-orange)", label: "H" },
                { sev: "medium",   color: "var(--accent-yellow)", label: "M" },
                { sev: "low",      color: "var(--accent-green)",  label: "L" },
              ].filter(s => sevCounts[s.sev]).map(s => (
                <span key={s.sev} className="text-[11px] font-bold px-2 py-0.5 rounded"
                  style={{ background: `${s.color}18`, color: s.color }}>
                  {s.label} {sevCounts[s.sev]}
                </span>
              ))}
              <span className="text-[11px] ml-auto" style={{ color: "var(--muted)" }}>
                {imageRef}
              </span>
            </div>
          )}
        </div>

        {/* Live agent steps */}
        <div className="px-6 py-4 flex flex-col gap-2 max-h-48 overflow-y-auto">
          {agentSteps.length === 0 ? (
            <p className="text-[12px]" style={{ color: "var(--dim)" }}>Waiting for agent steps…</p>
          ) : (
            [...agentSteps].reverse().slice(0, 8).map((step) => (
              <div key={step.id} className="flex items-start gap-2.5">
                <span className="text-[10px] mt-0.5 flex-shrink-0" style={{
                  color: step.state === "done" ? "var(--accent-green)" : "var(--accent-purple)"
                }}>
                  {step.state === "done" ? "✓" : "●"}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[11.5px] font-medium leading-tight truncate" style={{ color: "var(--body)" }}>
                    {step.title}
                  </p>
                  {step.desc && (
                    <p className="text-[10px] mt-0.5 truncate" style={{ color: "var(--muted)" }}>{step.desc}</p>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* ── Scanner log summary ── */}
      {trivyLogs.length > 0 && (
        <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <div className="flex items-center gap-2 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
            <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
              Scanner Log
            </span>
            <span className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded"
              style={{ background: "var(--surface2)", color: "var(--muted)", border: "1px solid var(--border)" }}>
              ✓ complete · {trivyLogs.length} lines
            </span>
          </div>
          <div className="px-4 py-3 font-mono text-[10.5px] leading-relaxed max-h-32 overflow-y-auto"
            style={{ background: "var(--surface2)" }}>
            {trivyLogs.map((line, i) => {
              const color = /ERROR|FATAL/.test(line) ? "var(--accent-red)"
                : /WARN/.test(line) ? "var(--accent-yellow)"
                : /INFO/.test(line) ? "var(--accent-blue)"
                : "var(--body)";
              return <div key={i} style={{ color }}>{line}</div>;
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Inner page (uses useSearchParams) ────────────────────────────────────
function ReviewPageInner() {
  const searchParams = useSearchParams();
  const runId = searchParams.get("run");

  // ── State ────────────────────────────────────────────────────────────────
  const [cves, setCves] = useState<CveRecord[]>([]);
  const [agentSteps, setAgentSteps] = useState<AgentStep[]>([]);
  const [stats, setStats] = useState<RunStats>(MOCK_STATS);
  const [tokenFragment, setTokenFragment] = useState("");
  const [selectedId, setSelectedId] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [agentStatus, setAgentStatus] = useState<"running" | "awaiting" | "done" | "error">("running");
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);
  const [trivyLogs, setTrivyLogs] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string>("");
  const [imageRef, setImageRef] = useState<string>("");
  const logEndRef = useRef<HTMLDivElement>(null);

  const streamCleanup = useRef<(() => void) | null>(null);

  // Auto-scroll Trivy log
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [trivyLogs]);

  // ── Toast helper ─────────────────────────────────────────────────────────
  const showToast = useCallback((msg: string, type: "success" | "error") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // ── Load / stream data ───────────────────────────────────────────────────
  useEffect(() => {
    if (!runId) {
      setLoading(false);
      return;
    }

    // Quick existence check before opening SSE — gives a clear 404 message
    // if the backend restarted and lost the run from memory.
    let cancelled = false;
    getRun(runId)
      .catch(() => {
        if (!cancelled) {
          setRunError("Run not found — the backend restarted and lost this session. Please start a new scan.");
          setLoading(false);
        }
      });

    // Helper: apply a run snapshot to all state setters
    const applySnapshot = (event: Partial<ReturnType<typeof getRun> extends Promise<infer T> ? T : never> & Record<string, any>) => {
      if (event.project_id) setProjectId(event.project_id);
      if (event.image_ref)  setImageRef(event.image_ref);
      if (event.trivy_logs && event.trivy_logs.length > 0) setTrivyLogs(event.trivy_logs);
      if (event.status === "scanning") { setIsScanning(true); return; }
      setIsScanning(false);
      if (event.cves) {
        setCves(event.cves);
        setSelectedId((prev) => {
          if (prev) return prev;
          const firstActionable = event.cves!.find((c: any) => c.status === "pending" || c.status === "queued");
          const fallback = event.cves![0];
          return firstActionable ? cveKey(firstActionable) : fallback ? cveKey(fallback) : "";
        });
      }
      if (event.agent_steps) setAgentSteps(event.agent_steps);
      if (event.token_fragment !== undefined) setTokenFragment(event.token_fragment);
      if (event.stats) setStats(event.stats);
      if (event.status === "awaiting_approval") { setAgentStatus("awaiting"); setLoading(false); }
      else if (event.status === "completed")    { setAgentStatus("done");     setLoading(false); }
      else if (event.status === "error")        { setAgentStatus("error");    setLoading(false); }
      else if (event.status === "running") {
        setAgentStatus("running");
        // If we already have CVEs synthesised, show them — don't wait for completion
        if (event.cves && event.cves.length > 0) setLoading(false);
      }
    };

    // Poll fallback — called when SSE ends without a terminal status
    const pollFallback = () => {
      getRun(runId).then(applySnapshot).catch(() => {
        setRunError("Run not found — the backend may have restarted. Please start a new scan.");
        setLoading(false);
      });
    };

    const cleanup = streamRun(
      runId,
      applySnapshot,
      () => {
        // SSE stream ended cleanly — if still loading, poll once for final state
        setLoading((prev) => { if (prev) pollFallback(); return prev; });
      },
      (err) => {
        console.warn("SSE error:", err);
        if (err.message?.includes("404") || err.message?.includes("not found")) {
          setRunError("Run not found — the backend may have restarted and lost this session. Please start a new scan.");
          setLoading(false);
        } else {
          // Non-404 SSE error — try polling once before showing error
          pollFallback();
        }
      }
    );

    streamCleanup.current = cleanup;

    // Safety-net: poll every 4s while still loading in case SSE events were missed
    const pollInterval = setInterval(() => {
      setLoading((isStillLoading) => {
        if (isStillLoading && !cancelled) pollFallback();
        return isStillLoading;
      });
    }, 4000);

    return () => { cancelled = true; cleanup(); clearInterval(pollInterval); };
  }, [runId]);

  // ── Decision handler ──────────────────────────────────────────────────────
  const handleDecision = useCallback(async (
    id: string,
    decision: "approved" | "rejected",
    editedRationale?: string,
    pkg?: string,
    editedByRole?: string
  ) => {
    // `pkg` disambiguates CVEs that share an id across multiple packages in
    // the same run (e.g. musl + musl-utils) — match on both when available
    // so a decision never lands on the wrong (or every matching) entry.
    const matches = (c: CveRecord) => c.id === id && (pkg === undefined || c.pkg === pkg);

    // Optimistic update
    setCves((prev) =>
      prev.map((c) =>
        matches(c)
          ? {
              ...c,
              status: decision,
              manualNotes: editedRationale ?? c.manualNotes,
              edited: editedRationale ? true : c.edited,
              editedByRole: editedRationale ? editedByRole : c.editedByRole,
            }
          : c
      )
    );

    // Auto-advance to next pending CVE
    setCves((prev) => {
      const currentIndex = prev.findIndex(matches);
      const next = prev
        .slice(currentIndex + 1)
        .find((c) => c.status === "pending" || c.status === "queued");
      if (next) setSelectedId(cveKey(next));
      return prev;
    });

    // Update stats
    setStats((prev) => ({
      ...prev,
      approved: decision === "approved" ? prev.approved + 1 : prev.approved,
      rejected: decision === "rejected" ? prev.rejected + 1 : prev.rejected,
    }));

    // Submit to backend if we have a real run
    if (runId) {
      try {
        await submitDecision(runId, {
          cve_id: id,
          decision,
          edited_rationale: editedRationale,
          pkg,
          edited_by_role: editedByRole,
        });
        showToast(
          decision === "approved" ? "Decision accepted and queued for persistence" : "CVE rejected",
          "success"
        );
      } catch (err) {
        console.warn("Failed to submit decision:", err);
        showToast("Decision saved locally (backend unavailable)", "error");
      }
    } else {
      showToast(
        decision === "approved" ? "Accepted" : "Rejected",
        "success"
      );
    }
  }, [runId, showToast]);

  // ── Derived ───────────────────────────────────────────────────────────────
  const selectedCve = cves.find((c) => cveKey(c) === selectedId) ?? cves[0];
  const reviewedCount = useMemo(
    () => cves.filter((c) => c.status === "approved" || c.status === "rejected").length,
    [cves]
  );
  const liveStats = useMemo<RunStats>(() => ({
    ...stats,
    total: cves.length || stats.total,
    approved: cves.filter((c) => c.status === "approved").length || stats.approved,
    rejected: cves.filter((c) => c.status === "rejected").length || stats.rejected,
  }), [cves, stats]);

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-screen overflow-hidden bg-bg text-text">
      <TopNav agentStatus={agentStatus} projectId={projectId} imageRef={imageRef} />

      {/* Toast */}
      {toast && (
        <div
          className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 px-5 py-3 rounded-xl text-[13px] font-medium shadow-xl"
          style={{
            background: toast.type === "success" ? "var(--accent-green-bg)" : "var(--accent-red-bg)",
            border: `1px solid ${toast.type === "success" ? "var(--accent-green-bdr)" : "var(--accent-red-bdr)"}`,
            color: toast.type === "success" ? "var(--accent-green)" : "var(--accent-red)",
          }}
        >
          {toast.type === "success" ? "✓" : "✕"} {toast.msg}
        </div>
      )}

      <div className="flex flex-1 min-h-0 overflow-hidden">
        {runError ? (
          /* ── Run lost / error screen ── */
          <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" strokeWidth="1.5" strokeLinecap="round">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <p className="text-[15px] font-semibold text-center" style={{ color: "var(--heading)" }}>
              Session Lost
            </p>
            <p className="text-[13px] text-center max-w-sm" style={{ color: "var(--muted)" }}>
              {runError}
            </p>
            <a
              href="/new-scan"
              className="mt-2 px-5 py-2.5 rounded-xl text-[13px] font-bold"
              style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)" }}
            >
              Start New Scan
            </a>
          </div>
        ) : isScanning ? (
          /* ── Scanning phase ── */
          <div className="flex-1 flex flex-col items-center justify-center gap-6 px-8">
            <div className="w-full max-w-2xl rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--accent-blue-bdr, var(--border))" }}>
              {/* Header */}
              <div className="flex items-center gap-3 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2.5" strokeLinecap="round" className="animate-spin flex-shrink-0">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                </svg>
                <span className="text-[13px] font-semibold" style={{ color: "var(--accent-blue)" }}>
                  Scanning image…
                </span>
                <span className="ml-auto text-[11px] font-mono px-2 py-0.5 rounded" style={{ background: "var(--surface2)", color: "var(--muted)" }}>
                  {trivyLogs.length} lines
                </span>
              </div>
              {/* Pipeline steps */}
              <div className="flex items-center gap-0 px-5 py-3" style={{ borderBottom: "1px solid var(--border)" }}>
                {[
                  { label: "Image Scan",    active: true  },
                  { label: "CVE Ingest",    active: false },
                  { label: "AI Synthesis",  active: false },
                  { label: "Human Review",  active: false },
                ].map((s, i) => (
                  <div key={s.label} className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium" style={{
                      background: s.active ? "var(--accent-blue-bg)" : "var(--surface2)",
                      color: s.active ? "var(--accent-blue)" : "var(--dim)",
                      border: `1px solid ${s.active ? "var(--accent-blue-bdr, var(--border))" : "var(--border)"}`,
                    }}>
                      {s.active && <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-blue)" }} />}
                      {s.label}
                    </div>
                    {i < 3 && <div className="w-6 h-px mx-1" style={{ background: "var(--border)" }} />}
                  </div>
                ))}
              </div>
              {/* Log output */}
              <div className="px-4 py-3 font-mono text-[11px] leading-relaxed overflow-y-auto max-h-64" style={{ background: "var(--surface2)", color: "var(--body)" }}>
                {trivyLogs.length === 0 ? (
                  <span style={{ color: "var(--dim)" }}>Connecting to Trivy…</span>
                ) : (
                  trivyLogs.map((line, i) => {
                    const color = /ERROR|FATAL/.test(line) ? "var(--accent-red)"
                      : /WARN/.test(line) ? "var(--accent-yellow)"
                      : /INFO/.test(line) ? "var(--accent-blue)"
                      : "var(--body)";
                    return <div key={i} style={{ color }}>{line}</div>;
                  })
                )}
                <div ref={logEndRef} />
              </div>
            </div>
          </div>
        ) : loading ? (
          <SynthesisLoader
            agentSteps={agentSteps}
            cves={cves}
            trivyLogs={trivyLogs}
            imageRef={imageRef}
          />
        ) : (
          <>
            <CveQueue
              cves={cves}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
            {selectedCve && (
              <div className="flex-1 flex flex-col overflow-hidden min-h-0">
                <div
                  className="flex items-center px-8 py-3 flex-shrink-0"
                  style={{ background: "var(--bg)", borderBottom: "1px solid var(--border)" }}
                >
                  <Link
                    href={projectId ? `/project?name=${encodeURIComponent(projectId)}` : "/dashboard"}
                    className="flex items-center gap-1.5 text-[12px] font-semibold transition-opacity hover:opacity-70"
                    style={{ color: "var(--muted)" }}
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                      <polyline points="15 18 9 12 15 6"/>
                    </svg>
                    Back to Images
                  </Link>
                </div>
                <CveReview
                  cve={selectedCve}
                  agentSteps={agentSteps}
                  tokenFragment={tokenFragment}
                  totalCves={cves.length}
                  reviewedCount={reviewedCount}
                  approvedCount={liveStats.approved}
                  onDecision={handleDecision}
                />
              </div>
            )}
            <ContextPanel stats={liveStats} cves={cves} />
          </>
        )}
      </div>
    </div>
  );
}

// ── Export with Suspense boundary for useSearchParams ─────────────────────
export default function ReviewPage() {
  return (
    <RequireAuth>
      <Suspense>
        <ReviewPageInner />
      </Suspense>
    </RequireAuth>
  );
}
