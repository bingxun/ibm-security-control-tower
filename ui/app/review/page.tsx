"use client";

import { useState, useMemo, useEffect, useCallback, useRef, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import CveQueue from "@/components/CveQueue";
import CveReview from "@/components/CveReview";
import ContextPanel from "@/components/ContextPanel";
import MissionControl from "@/components/MissionControl";

import { CveRecord, AgentStep, RunStats, DecisionExtra, cveKey } from "@/lib/types";
import { streamRun, submitDecision, getRun, applyBaselines, listScans, type ScanRun } from "@/lib/api";

type Decision = "approved" | "rejected" | "submitted" | "changes_requested";
const DECISION_TOAST: Record<Decision, string> = {
  submitted: "Submitted for approval",
  changes_requested: "Changes requested — returned to DevOps",
  approved: "Approved",
  rejected: "Rejected",
};

// ── Synthesis progress screen ──────────────────────────────────────────────
function SynthesisLoader({
  agentSteps,
  cves,
  trivyLogs,
  imageRef,
  stats,
  tokenFragment,
}: {
  agentSteps: import("@/lib/types").AgentStep[];
  cves: import("@/lib/types").CveRecord[];
  trivyLogs: string[];
  imageRef: string;
  stats: import("@/lib/types").RunStats;
  tokenFragment: string;
}) {
  const stages = [
    { label: "Image Scan", done: true  },
    { label: "Ingest",     done: true  },
    { label: "Master → CVE slaves", done: false, active: true },
    { label: "Approval",   done: false, active: false },
  ];

  return (
    <div className="flex-1 overflow-y-auto flex flex-col gap-5 px-4 sm:px-8 py-5 sm:py-7" style={{ background: "var(--bg)" }}>

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

      {/* ── Live multi-agent mission control ── */}
      {agentSteps.length === 0 && cves.length === 0 ? (
        <div className="rounded-2xl px-6 py-8 text-center" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <p className="text-[12px]" style={{ color: "var(--dim)" }}>Dispatching agent workers…</p>
        </div>
      ) : (
        <MissionControl agentSteps={agentSteps} cves={cves} tokenFragment={tokenFragment} stats={stats} imageRef={imageRef} />
      )}

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
  return <ReviewContent key={runId} runId={runId} />;
}

function ReviewContent({ runId }: { runId: string | null }) {
  // ── State ────────────────────────────────────────────────────────────────
  const [cves, setCves] = useState<CveRecord[]>([]);
  const [agentSteps, setAgentSteps] = useState<AgentStep[]>([]);
  const [stats, setStats] = useState<RunStats>({ total: 0, approved: 0, rejected: 0, avgSynthesisS: 0, ragHits: 0, tokensUsed: 0 });
  const [tokenFragment, setTokenFragment] = useState("");
  const [selectedId, setSelectedId] = useState<string>("");
  // Mobile master-detail: on phones show either the queue or the detail (lg+ shows both).
  const [mobileView, setMobileView] = useState<"queue" | "detail">("queue");
  const [loading, setLoading] = useState(Boolean(runId));
  const [agentStatus, setAgentStatus] = useState<"running" | "awaiting" | "done" | "error">("running");
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);
  const [trivyLogs, setTrivyLogs] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string>("");
  const [imageRef, setImageRef] = useState<string>("");
  const [scanSeq, setScanSeq] = useState<number | undefined>(undefined);
  const logEndRef = useRef<HTMLDivElement>(null);

  const streamCleanup = useRef<(() => void) | null>(null);
  const reconciledRef = useRef(false);

  // Auto-scroll Trivy log
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [trivyLogs]);

  // Resolve this run's scan number (#seq) for the breadcrumb.
  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    listScans()
      .then((rows) => { if (!cancelled) { const m = rows.find((r) => r.id === runId); if (m) setScanSeq(m.seq); } })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [runId]);

  // ── Toast helper ─────────────────────────────────────────────────────────
  const showToast = useCallback((msg: string, type: "success" | "error") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // When an awaiting run opens, reconcile it against published baselines once:
  // any finding that exactly matches a baseline a Cyber Manager already approved
  // is auto-approved by the agent (the SSE stream then reflects the new statuses).
  useEffect(() => {
    if (!runId || agentStatus !== "awaiting" || reconciledRef.current) return;
    reconciledRef.current = true;
    applyBaselines(runId)
      .then((r) => { if (r.applied > 0) showToast(`${r.applied} finding${r.applied === 1 ? "" : "s"} auto-approved from a published baseline`, "success"); })
      .catch(() => { /* non-fatal */ });
  }, [runId, agentStatus, showToast]);

  // ── Load / stream data ───────────────────────────────────────────────────
  useEffect(() => {
    if (!runId) return;

    // Quick existence check before opening SSE — gives a clear 404 message
    // if the backend restarted and lost the run from memory.
    let cancelled = false;
    getRun(runId)
      .catch(() => {
        if (!cancelled) {
          setRunError("This run is unavailable or no longer assigned to you.");
          setLoading(false);
        }
      });

    // Helper: apply a run snapshot to all state setters
    const applySnapshot = (event: Partial<ScanRun>) => {
      if (cancelled) return;
      if (event.project_id) setProjectId(event.project_id);
      if (event.image_ref)  setImageRef(event.image_ref);
      if (event.trivy_logs && event.trivy_logs.length > 0) setTrivyLogs(event.trivy_logs);
      if (event.status === "scanning") { setIsScanning(true); return; }
      setIsScanning(false);
      if (event.cves) {
        setCves(event.cves);
        setSelectedId((prev) => {
          if (prev) return prev;
          const first = event.cves!.find((c) => c.status === "submitted" || c.status === "pending" || c.status === "queued") ?? event.cves![0];
          return first ? cveKey(first) : "";
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
        if (cancelled) return;
        setCves([]); setAgentSteps([]); setTrivyLogs([]); setProjectId(""); setImageRef("");
        setRunError("This run is unavailable or no longer assigned to you.");
        setLoading(false);
      });
    };

    const cleanup = streamRun(
      runId,
      applySnapshot,
      () => {
        // Recheck access when a stream closes, including membership revocation.
        pollFallback();
      },
      (err) => {
        console.warn("SSE error:", err);
        if (err.message?.includes("404") || err.message?.includes("not found")) {
          setRunError("This run is unavailable or no longer assigned to you.");
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

  // ── Decision handler (approve / reject / submit / request-changes) ─────────
  const handleDecision = useCallback(async (
    id: string,
    decision: Decision,
    pkg?: string,
    extra?: DecisionExtra,
  ) => {
    if (!runId) return;
    try {
      await submitDecision(runId, { cve_id: id, decision, pkg, ...extra });
      // Match on id AND pkg — the same CVE id can span multiple packages.
      setCves(prev => prev.map(c => (c.id === id && (pkg === undefined || c.pkg === pkg))
        ? { ...c, status: decision,
            rationale: extra?.justification ?? c.rationale,
            remediation: extra?.remediation ?? c.remediation,
            manualNotes: extra?.notes ?? c.manualNotes,
            edited: (extra?.notes || extra?.justification || extra?.remediation) ? true : c.edited,
            editedByRole: extra?.edited_by_role ?? c.editedByRole }
        : c));
      showToast(DECISION_TOAST[decision], "success");
    } catch {
      showToast(decision === "submitted" ? "Could not submit. Check your access and try again." : "Decision was not saved. Check your project access and try again.", "error");
    }
  }, [runId, showToast]);

  // ── Derived ───────────────────────────────────────────────────────────────
  // Keep the live mission-control view up for the whole synthesis phase — not
  // just the first SSE tick — so the agent's work is actually visible.
  const synthesizing = agentStatus === "running" && cves.some((c) => c.status === "queued");
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
      <TopNav agentStatus={agentStatus} projectId={projectId} imageRef={imageRef} scanSeq={scanSeq} />

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

      <div className="flex flex-1 overflow-hidden">
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
        ) : loading || synthesizing ? (
          <SynthesisLoader
            agentSteps={agentSteps}
            cves={cves}
            trivyLogs={trivyLogs}
            imageRef={imageRef}
            stats={liveStats}
            tokenFragment={tokenFragment}
          />
        ) : (
          <>
            {/* Queue — full width on phones (master view), fixed rail on lg+ */}
            <div className={`${mobileView === "detail" ? "hidden" : "flex"} lg:flex w-full lg:w-auto flex-shrink-0 min-h-0`}>
              <CveQueue
                cves={cves}
                selectedId={selectedId}
                onSelect={(k) => { setSelectedId(k); setMobileView("detail"); }}
              />
            </div>
            {/* Detail — hidden on phones while browsing the queue */}
            <div className={`${mobileView === "queue" ? "hidden" : "flex"} lg:flex flex-1 min-w-0 min-h-0 flex-col`}>
              {/* Mobile back-to-queue bar */}
              <button
                onClick={() => setMobileView("queue")}
                className="lg:hidden flex items-center gap-2 px-4 py-2.5 text-[13px] font-semibold flex-shrink-0"
                style={{ background: "var(--bg-nav)", borderBottom: "1px solid var(--border)", color: "var(--accent-blue)" }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="15 18 9 12 15 6" /></svg>
                Findings{cves.length ? ` (${cves.length})` : ""}
              </button>
              {selectedCve && (
                <CveReview
                  key={cveKey(selectedCve)}
                  runId={runId ?? undefined}
                  cve={selectedCve}
                  agentSteps={agentSteps}
                  tokenFragment={tokenFragment}
                  totalCves={cves.length}
                  reviewedCount={reviewedCount}
                  approvedCount={liveStats.approved}
                  onDecision={handleDecision}
                />
              )}
            </div>
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
