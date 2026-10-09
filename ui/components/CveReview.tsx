"use client";

import { useEffect, useState } from "react";
import { CveRecord, cveKey, DecisionExtra, ReviewSuggestion, RevisionRecord } from "@/lib/types";
import { AgentStep } from "@/lib/types";
import BaselinePublisher from "./BaselinePublisher";
import AgentDrawer from "./AgentDrawer";
import ReviewAssistant from "./ReviewAssistant";
import RevisionTimeline from "./RevisionTimeline";
import { getRevisions } from "@/lib/api";
import { usePermission, useAuth } from "@/lib/auth";
import { ROLE_LABELS, UserRole } from "@/lib/types";

type Decision = "approved" | "rejected" | "submitted" | "changes_requested";

interface Props {
  runId?: string;
  cve: CveRecord;
  agentSteps: AgentStep[];
  tokenFragment: string;
  totalCves: number;
  reviewedCount: number;
  approvedCount: number;
  onDecision: (id: string, decision: Decision, pkg?: string, extra?: DecisionExtra) => void;
}

const SEV_COLOR: Record<string, string> = {
  critical: "var(--accent-red)",
  high:     "var(--accent-orange)",
  medium:   "var(--accent-yellow)",
  low:      "var(--accent-green)",
};

const SEV_BG: Record<string, string> = {
  critical: "var(--accent-red-bg)",
  high:     "rgba(var(--accent-orange-rgb, 240,136,62),0.1)",
  medium:   "rgba(var(--accent-yellow-rgb, 210,153,34),0.1)",
  low:      "var(--accent-green-bg)",
};

// ── Reject & request changes modal ──────────────────────────────────────────
function RejectModal({ cve, onCancel, onConfirm }: {
  cve: CveRecord;
  onCancel: () => void;
  onConfirm: (reason: string, requested: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [requested, setRequested] = useState("");
  const ready = reason.trim().length > 0 && requested.trim().length > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div className="w-full max-w-2xl rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
        <div className="px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
          <p className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>Reject &amp; request changes</p>
          <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{cve.id} · {cve.pkg} — this returns the finding to DevOps for revision.</p>
        </div>
        <div className="px-6 py-5 flex flex-col gap-4">
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>Reason for rejection</label>
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3}
              className="w-full px-4 py-3 rounded-xl text-[13px] leading-relaxed outline-none resize-none"
              style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
              placeholder="Why this cannot be approved as written…" />
          </div>
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>What DevOps must provide</label>
            <textarea value={requested} onChange={(e) => setRequested(e.target.value)} rows={3}
              className="w-full px-4 py-3 rounded-xl text-[13px] leading-relaxed outline-none resize-none"
              style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
              placeholder="The specific evidence or changes required to resubmit…" />
          </div>
        </div>
        <div className="flex items-center gap-3 px-6 py-4" style={{ borderTop: "1px solid var(--border)", background: "var(--surface3)" }}>
          <button onClick={() => onConfirm(reason, requested)} disabled={!ready}
            className="px-6 py-2.5 rounded-xl text-[13px] font-bold transition-all"
            style={{ background: ready ? "var(--accent-red-bg)" : "var(--surface2)", color: ready ? "var(--accent-red)" : "var(--dim)",
              border: `1px solid ${ready ? "var(--accent-red-bdr)" : "var(--border)"}`, cursor: ready ? "pointer" : "not-allowed" }}>
            Reject &amp; request changes
          </button>
          <button onClick={onCancel} className="px-5 py-2.5 rounded-xl text-[13px] font-semibold hover:opacity-80"
            style={{ background: "var(--surface2)", color: "var(--faint)", border: "1px solid var(--border2)" }}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ── Editable draft field ─────────────────────────────────────────────────────
function DraftField({ label, color, value, onChange, placeholder }: {
  label: string; color: string; value: string; onChange: (v: string) => void; placeholder: string;
}) {
  return (
    <div className="pl-4" style={{ borderLeft: `2px solid ${color}` }}>
      <div className="text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color }}>{label}</div>
      <textarea value={value} onChange={(e) => onChange(e.target.value)} rows={3}
        className="w-full px-3 py-2 rounded-xl text-[14px] leading-[1.7] outline-none resize-y"
        style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
        placeholder={placeholder} />
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────
export default function CveReview({
  runId, cve, agentSteps, tokenFragment, totalCves, reviewedCount, approvedCount, onDecision,
}: Props) {
  const canApprove            = usePermission("canApprove");
  const canReject             = usePermission("canReject");
  const canSubmitForApproval  = usePermission("canSubmitForApproval");
  const canApproveSubmitted   = usePermission("canApproveSubmitted");
  const { user } = useAuth();

  const isSubmitted = cve.status === "submitted";
  const isTerminal = cve.status === "approved" || cve.status === "rejected";
  const isDraftState = cve.status === "pending" || cve.status === "changes_requested";
  // Anyone who can submit (DevOps, Super Admin) prepares & submits an unsubmitted finding.
  const editable = canSubmitForApproval && isDraftState;

  const [draft, setDraft] = useState({
    justification: cve.rationale ?? "",
    remediation: cve.remediation ?? "",
    notes: cve.manualNotes ?? "",
  });
  const [appliedIds, setAppliedIds] = useState<string[]>([]);
  const [reviewComment, setReviewComment] = useState("");
  const [showAssistant, setShowAssistant] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [revisions, setRevisions] = useState<RevisionRecord[]>([]);

  // Load (and refresh after any decision) the finding's revision history.
  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    getRevisions(runId, cve.id, cve.pkg)
      .then((rows) => { if (!cancelled) setRevisions(rows); })
      .catch(() => { if (!cancelled) setRevisions([]); });
    return () => { cancelled = true; };
  }, [runId, cve.id, cve.pkg, cve.status]);

  const assistantMode: "draft" | "review" = editable ? "draft" : "review";
  const applySuggestion = (s: ReviewSuggestion) => {
    if (assistantMode === "review") {
      setReviewComment((prev) => (prev ? `${prev}\n${s.suggestedText ?? ""}` : s.suggestedText ?? ""));
    } else if (s.type !== "review_comment" && s.suggestedText) {
      setDraft((d) => ({ ...d, justification: s.suggestedText as string }));
    }
    setAppliedIds((ids) => (ids.includes(s.id) ? ids : [...ids, s.id]));
  };

  const sevColor = SEV_COLOR[cve.severity] ?? "var(--faint)";
  const cvssColor =
    cve.cvss >= 9 ? "var(--accent-red)" :
    cve.cvss >= 7 ? "var(--accent-orange)" :
    cve.cvss >= 4 ? "var(--accent-yellow)" : "var(--accent-green)";

  const isStub = cve.rationale?.startsWith("[Auto-generated stub");
  const displayRationale = isStub ? cve.rationale.replace(/^\[Auto-generated stub[^\]]*\]\s*/, "") : cve.rationale;
  const manualNotesText = cve.manualNotes && cve.manualNotes.trim().length > 0 ? cve.manualNotes : null;

  // Latest "sent back" decision — shown prominently when DevOps revises.
  const lastSentBack = [...revisions].reverse().find((r) => r.action === "changes_requested");

  // ── Learning loop surfacing ──────────────────────────────────────────────
  // The agent auto-approved this finding from a Cyber-published baseline.
  const autoApproved = cve.editedByRole === "AGENT" && cve.status === "approved";
  // A pending finding the agent *recommends* a decision on, grounded in memory.
  const memoryRecommendation = !autoApproved && !isTerminal && cve.ragMatch
    ? cve.ragMatch : null;

  const submitDraft = (decision: "submitted") => {
    onDecision(cve.id, decision, cve.pkg, {
      justification: draft.justification,
      remediation: draft.remediation,
      notes: draft.notes,
      ai_suggestions_applied: appliedIds,
      edited_by_role: user?.roles?.[0],
    });
  };

  return (
    <>
      {rejectOpen && (
        <RejectModal cve={cve} onCancel={() => setRejectOpen(false)}
          onConfirm={(reason, requested) => {
            setRejectOpen(false);
            onDecision(cve.id, "changes_requested", cve.pkg, {
              review_comment: reason, requested_changes: requested, ai_suggestions_applied: appliedIds,
            });
          }} />
      )}

      <main className="flex-1 min-h-0 overflow-y-auto px-8 py-7 space-y-6"
        style={{ background: "var(--bg)", overscrollBehavior: "contain" }}>

        {/* ── Agent auto-approval hero (the learning loop paid off) ── */}
        {autoApproved && (
          <div className="rounded-2xl px-6 py-4 flex items-center gap-4 ct-fade-up"
            style={{ background: "linear-gradient(135deg, rgba(63,185,80,0.16), rgba(88,166,255,0.08))", border: "1px solid var(--accent-green-bdr)" }}>
            <span className="grid place-items-center w-10 h-10 rounded-2xl flex-shrink-0 text-[18px]"
              style={{ background: "var(--accent-green-bg)", color: "var(--accent-green)", border: "1px solid var(--accent-green-bdr)" }}>⚡</span>
            <div className="min-w-0">
              <div className="text-[13px] font-bold" style={{ color: "var(--heading)" }}>Autonomously approved by the agent</div>
              <div className="text-[12px] mt-0.5" style={{ color: "var(--subtle)" }}>
                Grounded in a Cyber Manager baseline{cve.ragMatch?.approver ? <> originally approved by <span style={{ color: "var(--body)" }}>{cve.ragMatch.approver}</span></> : null}
                {cve.ragMatch?.date ? <> · {cve.ragMatch.date}</> : null} — no human review needed.
              </div>
            </div>
          </div>
        )}

        {/* ── Agent recommendation from memory (pending finding) ── */}
        {memoryRecommendation && (
          <div className="rounded-2xl px-6 py-4 flex items-center gap-4 ct-fade-up"
            style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}>
            <span className="grid place-items-center w-10 h-10 rounded-2xl flex-shrink-0 text-[18px]"
              style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>◈</span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-bold" style={{ color: "var(--accent-purple)" }}>
                Agent recommends approval · {memoryRecommendation.pct}% memory match
              </div>
              <div className="text-[12px] mt-0.5" style={{ color: "var(--subtle)" }}>
                {memoryRecommendation.note ? (
                  <span style={{ color: "var(--body)" }}>{memoryRecommendation.note}</span>
                ) : (
                  <>
                    A similar finding was approved by <span style={{ color: "var(--body)" }}>{memoryRecommendation.approver}</span>
                    {memoryRecommendation.date ? <> on {memoryRecommendation.date}</> : null}
                    {memoryRecommendation.project ? <> ({memoryRecommendation.project})</> : null}.
                  </>
                )}
              </div>
            </div>
            {canApprove && !isSubmitted && !editable && (
              <button onClick={() => onDecision(cve.id, "approved", cve.pkg)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-bold flex-shrink-0 transition-opacity hover:opacity-85"
                style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 16px var(--btn-accept-glow)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
                Approve as recommended
              </button>
            )}
          </div>
        )}

        {/* ── 1. CVE Identity bar ── */}
        <div className="rounded-2xl p-6 flex items-start gap-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <div className="w-20 h-20 rounded-2xl flex flex-col items-center justify-center flex-shrink-0"
            style={{ background: `rgba(${cvssColor === "var(--accent-red)" ? "248,81,73" : cvssColor === "var(--accent-orange)" ? "240,136,62" : cvssColor === "var(--accent-yellow)" ? "210,153,34" : "63,185,80"}, 0.08)`, border: `1px solid ${cvssColor}33` }}>
            <span className="text-3xl font-black leading-none" style={{ color: cvssColor }}>{cve.cvss}</span>
            <span className="text-[10px] font-bold uppercase tracking-widest mt-0.5" style={{ color: cvssColor + "99" }}>CVSS</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap mb-1">
              <h1 className="text-[22px] font-black tracking-tight" style={{ color: "var(--heading)" }}>{cve.id}</h1>
              <span className="text-[11px] font-bold px-3 py-1 rounded-full uppercase tracking-wide"
                style={{ background: SEV_BG[cve.severity], color: sevColor, border: `1px solid ${sevColor}33` }}>{cve.severity}</span>
            </div>
            <p className="text-[13px] leading-relaxed" style={{ color: "var(--subtle)" }}>
              <span style={{ color: "var(--body)" }}>{cve.pkg}</span>{" "}<span style={{ color: "var(--dim)" }}>·</span>{" "}
              <span>v{cve.version}</span>{" "}<span style={{ color: "var(--dim)" }}>→</span>{" "}
              <span style={{ color: "var(--accent-green)" }}>fix: {cve.fixedIn}</span>
            </p>
            <p className="text-[13px] mt-1 break-words" style={{ color: "var(--muted)" }}>{cve.description}</p>
          </div>
          <div className="flex flex-col gap-2 flex-shrink-0 w-40">
            {[
              { label: "Vector",  value: cve.vector },
              { label: "Auth",    value: cve.authRequired, warn: cve.authRequired === "None" },
              { label: "Impact",  value: cve.impact.split("—")[0].trim() },
            ].map((f) => (
              <div key={f.label} className="text-right">
                <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--dim)" }}>{f.label}</div>
                <div className="text-[12px] font-semibold break-words" style={{ color: f.warn ? "var(--accent-red)" : "var(--faint)" }}>{f.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Sent-back banner (DevOps revising) ── */}
        {cve.status === "changes_requested" && lastSentBack && (
          <div className="rounded-2xl px-6 py-4" style={{ background: "var(--accent-yellow-bg, rgba(210,153,34,0.08))", border: "1px solid rgba(210,153,34,0.3)" }}>
            <div className="text-[12px] font-bold uppercase tracking-wider mb-1.5" style={{ color: "var(--accent-yellow)" }}>
              Changes requested by {lastSentBack.actor}
            </div>
            <p className="text-[13px] leading-relaxed mb-2" style={{ color: "var(--body)" }}>{lastSentBack.review_comment}</p>
            {lastSentBack.requested_changes && (
              <p className="text-[13px] leading-relaxed" style={{ color: "var(--body)" }}>
                <span className="font-semibold" style={{ color: "var(--accent-yellow)" }}>Required: </span>{lastSentBack.requested_changes}
              </p>
            )}
          </div>
        )}

        {/* ── 2. Rationale card ── */}
        <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>
                  {editable ? "Justification & Remediation" : "Mitigation Rationale"}
                </span>
                {!editable && (isStub ? (
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider"
                    style={{ background: "rgba(210,153,34,0.1)", color: "var(--accent-yellow)", border: "1px solid rgba(210,153,34,0.3)" }}>
                    ⚠ Offline stub — LLM quota exhausted
                  </span>
                ) : (
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider"
                    style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>
                    AI Generated
                  </span>
                ))}
                {editable && (
                  <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider"
                    style={{ background: "var(--accent-blue-bg, rgba(68,147,248,0.12))", color: "var(--accent-blue)", border: "1px solid var(--accent-blue-bdr, rgba(68,147,248,0.25))" }}>
                    Editable draft
                  </span>
                )}
              </div>
            </div>
            {cve.ragMatch && (
              <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl" style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}>
                <div>
                  <div className="text-[20px] font-black leading-none" style={{ color: "var(--accent-purple)" }}>{cve.ragMatch.pct}%</div>
                  <div className="text-[10px]" style={{ color: "var(--accent-purple)" }}>memory match</div>
                </div>
                <div className="w-px h-8" style={{ background: "var(--accent-purple-bdr)" }} />
                <div>
                  <div className="text-[11px] font-semibold" style={{ color: "var(--body)" }}>{cve.ragMatch.project}</div>
                  <div className="text-[10px]" style={{ color: "var(--muted)" }}>{cve.ragMatch.approver} · {cve.ragMatch.date}</div>
                </div>
              </div>
            )}
          </div>

          {/* Body — editable draft (DevOps) or read-only display */}
          <div className="px-6 py-5">
            {editable ? (
              <div className="flex flex-col gap-4">
                <DraftField label="Justification" color="var(--accent-purple)" value={draft.justification}
                  onChange={(v) => setDraft((d) => ({ ...d, justification: v }))}
                  placeholder="Assess whether this vulnerability is exploitable in your environment…" />
                <DraftField label="Proposed Remediation" color="var(--accent-green)" value={draft.remediation}
                  onChange={(v) => setDraft((d) => ({ ...d, remediation: v }))}
                  placeholder="Patch version, config change, or accepted-risk statement…" />
                <DraftField label="Notes" color="var(--accent-blue)" value={draft.notes}
                  onChange={(v) => setDraft((d) => ({ ...d, notes: v }))}
                  placeholder="Any additional remarks for the reviewer…" />
              </div>
            ) : displayRationale ? (
              <div className="flex flex-col gap-4">
                <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-purple)" }}>
                  <div className="text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--accent-purple)" }}>Justification</div>
                  <p className="text-[14px] leading-[1.8] break-words whitespace-pre-wrap" style={{ color: "var(--body)" }}>{displayRationale}</p>
                </div>
                {cve.remediation && cve.remediation.trim() && (
                  <>
                    <div style={{ borderTop: "1px solid var(--border)" }} />
                    <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-green)" }}>
                      <div className="text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--accent-green)" }}>Recommended Remediation</div>
                      <p className="text-[14px] leading-[1.8] break-words whitespace-pre-wrap" style={{ color: "var(--body)" }}>{cve.remediation}</p>
                    </div>
                  </>
                )}
                {manualNotesText && (
                  <>
                    <div style={{ borderTop: "1px solid var(--border)" }} />
                    <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-blue)" }}>
                      <div className="text-[11px] font-semibold uppercase tracking-wider mb-1.5 flex items-center gap-2" style={{ color: "var(--accent-blue)" }}>
                        Manual Input
                        {cve.editedByRole && (
                          <span className="text-[11px] font-normal normal-case tracking-normal" style={{ color: "var(--muted)" }}>
                            — added by {ROLE_LABELS[cve.editedByRole as UserRole] ?? cve.editedByRole}
                          </span>
                        )}
                      </div>
                      <p className="text-[14px] leading-[1.8] break-words whitespace-pre-wrap" style={{ color: "var(--body)" }}>{manualNotesText}</p>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-3 py-4">
                <span className="w-2 h-2 rounded-full animate-pulse" style={{ background: "var(--accent-purple)" }} />
                <span className="text-[13px]" style={{ color: "var(--muted)" }}>Agent is synthesising rationale…</span>
              </div>
            )}
          </div>

          {/* Cyber: optional review comment on approval */}
          {isSubmitted && canApproveSubmitted && (
            <div className="px-6 pb-4">
              <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>Review comment (optional on approve)</label>
              <textarea value={reviewComment} onChange={(e) => setReviewComment(e.target.value)} rows={2}
                className="w-full px-3 py-2 rounded-xl text-[13px] leading-relaxed outline-none resize-y"
                style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
                placeholder="Note recorded with your approval…" />
            </div>
          )}

          {/* ── Action row ── */}
          <div className="flex items-center gap-3 px-6 py-5 flex-wrap" style={{ borderTop: "1px solid var(--border)", background: "var(--surface3)" }}>
            {isTerminal ? (
              <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px] font-semibold"
                style={{ background: cve.status === "approved" ? "var(--accent-green-bg)" : "var(--accent-red-bg)", border: `1px solid ${cve.status === "approved" ? "var(--accent-green-bdr)" : "var(--accent-red-bdr)"}`, color: cve.status === "approved" ? "var(--accent-green)" : "var(--accent-red)" }}>
                {cve.status === "approved" ? "✓ Approved" : "✕ Rejected"} — decision recorded. See the revision history below.
              </div>
            ) : isSubmitted && canApproveSubmitted ? (
              <>
                <button onClick={() => onDecision(cve.id, "approved", cve.pkg, { review_comment: reviewComment || undefined, ai_suggestions_applied: appliedIds })}
                  className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all hover:opacity-90 active:scale-[0.98]"
                  style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 20px var(--btn-accept-glow)" }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
                  Approve
                </button>
                <button onClick={() => setShowAssistant((v) => !v)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all hover:opacity-80"
                  style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>
                  {showAssistant ? "Hide Review AI" : "Review AI"}
                </button>
                <button onClick={() => setRejectOpen(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all hover:opacity-80"
                  style={{ background: "var(--accent-red-bg)", color: "var(--accent-red)", border: "1px solid var(--accent-red-bdr)" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                  Reject &amp; request changes
                </button>
              </>
            ) : isSubmitted ? (
              <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px]"
                style={{ background: "var(--accent-blue-bg, rgba(68,147,248,0.08))", border: "1px solid var(--accent-blue-bdr, rgba(68,147,248,0.25))", color: "var(--accent-blue)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M22 2 11 13" /><path d="M22 2 15 22 11 13 2 9z" /></svg>
                Submitted — awaiting Cyber Manager approval.
              </div>
            ) : editable ? (
              <>
                <button onClick={() => submitDraft("submitted")}
                  className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all hover:opacity-90 active:scale-[0.98]"
                  style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 20px var(--btn-accept-glow)" }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M22 2 11 13" /><path d="M22 2 15 22 11 13 2 9z" /></svg>
                  {cve.status === "changes_requested" ? "Resubmit for approval" : "Submit for approval"}
                </button>
                <button onClick={() => setShowAssistant((v) => !v)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all hover:opacity-80"
                  style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>
                  {showAssistant ? "Hide Review AI" : "Review AI"}
                </button>
              </>
            ) : canApproveSubmitted && isDraftState ? (
              <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px]"
                style={{ background: "var(--surface2)", border: "1px solid var(--border2)", color: "var(--muted)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                {cve.status === "changes_requested" ? "Sent back — awaiting DevOps revision & resubmission." : "Awaiting DevOps submission before you can review."}
              </div>
            ) : canReject ? (
              <>
                <button onClick={() => onDecision(cve.id, "approved", cve.pkg)}
                  className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all hover:opacity-90 active:scale-[0.98]"
                  style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 20px var(--btn-accept-glow)" }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
                  Accept
                </button>
                <button onClick={() => onDecision(cve.id, "rejected", cve.pkg)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all hover:opacity-80"
                  style={{ background: "var(--accent-red-bg)", color: "var(--accent-red)", border: "1px solid var(--accent-red-bdr)" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                  Reject
                </button>
              </>
            ) : canApprove ? (
              <button onClick={() => onDecision(cve.id, "approved", cve.pkg)}
                className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all hover:opacity-90 active:scale-[0.98]"
                style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 20px var(--btn-accept-glow)" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
                Approve
              </button>
            ) : (
              <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px]"
                style={{ background: "var(--surface2)", border: "1px solid var(--border2)", color: "var(--muted)" }}>
                This finding has already been {cve.status.replace("_", " ")}. No action needed.
              </div>
            )}

            <div className="ml-auto flex items-center gap-3">
              <div className="text-right">
                <div className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>
                  {reviewedCount} <span style={{ color: "var(--dim)" }}>/</span> {totalCves}
                </div>
                <div className="text-[11px]" style={{ color: "var(--muted)" }}>{approvedCount} approved</div>
              </div>
              <svg width="36" height="36" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="14" fill="none" stroke="var(--border)" strokeWidth="3" />
                <circle cx="18" cy="18" r="14" fill="none" stroke="var(--accent-green)" strokeWidth="3"
                  strokeDasharray={`${totalCves > 0 ? (reviewedCount / totalCves) * 88 : 0} 88`} strokeLinecap="round" transform="rotate(-90 18 18)" />
              </svg>
            </div>
          </div>
        </div>

        {/* ── Review AI assistant ── */}
        {showAssistant && (isSubmitted ? canApproveSubmitted : editable) && (
          <ReviewAssistant runId={runId} cve={cve} mode={assistantMode}
            draft={editable ? draft : { justification: cve.rationale ?? "", remediation: cve.remediation ?? "", notes: cve.manualNotes ?? "" }}
            appliedIds={appliedIds} onApply={applySuggestion} />
        )}

        {/* ── Revision history ── */}
        <RevisionTimeline revisions={revisions} />

        {runId && <BaselinePublisher key={`${runId}:${cveKey(cve)}`} runId={runId} cve={cve} />}

        {/* ── Agent drawer ── */}
        <AgentDrawer steps={agentSteps} tokenFragment={tokenFragment} />
      </main>
    </>
  );
}
