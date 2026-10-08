"use client";

import { useState } from "react";
import { CveRecord } from "@/lib/types";
import { AgentStep } from "@/lib/types";
import AgentDrawer from "./AgentDrawer";
import { usePermission, useAuth } from "@/lib/auth";
import { ROLE_LABELS, UserRole } from "@/lib/types";

interface Props {
  cve: CveRecord;
  agentSteps: AgentStep[];
  tokenFragment: string;
  totalCves: number;
  reviewedCount: number;
  approvedCount: number;
  onDecision: (id: string, decision: "approved" | "rejected", editedRationale?: string, pkg?: string, editedByRole?: string) => void;
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

// Marker embedded in old-format `rationale` strings, before the backend
// started sending `remediation` as its own field. Case-insensitive.
const LEGACY_REMEDIATION_MARKER = /recommended remediation:/i;

/**
 * Splits an old-format `rationale` string (one that still has the fix
 * instruction embedded inline) into its Justification and Remediation
 * parts. Used only when `cve.remediation` is empty — new-format records
 * already come pre-split from the backend.
 */
function splitLegacyRationale(rationale: string): { justification: string; remediation: string | null } {
  const match = LEGACY_REMEDIATION_MARKER.exec(rationale);
  if (!match) {
    return { justification: rationale, remediation: null };
  }
  const justification = rationale.slice(0, match.index).trim();
  const remediation = rationale.slice(match.index + match[0].length).trim();
  return { justification, remediation: remediation.length > 0 ? remediation : null };
}

// ── Edit Modal ─────────────────────────────────────────────────────────────
function EditModal({
  cve,
  onCancel,
  onAccept,
}: {
  cve: CveRecord;
  onCancel: () => void;
  onAccept: (notes: string) => void;
}) {
  const [draft, setDraft] = useState(cve.manualNotes ?? "");

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
    >
      <div
        className="w-full max-w-2xl rounded-2xl overflow-hidden"
        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <div>
            <p className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>
              Add Manual Notes
            </p>
            <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>
              {cve.id} · {cve.pkg} {cve.version}
            </p>
          </div>
          <button
            onClick={onCancel}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-[13px] transition-colors"
            style={{ background: "var(--surface2)", color: "var(--muted)" }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface3)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "var(--surface2)")}
          >
            ✕
          </button>
        </div>

        {/* Textarea */}
        <div className="px-6 py-5">
          <label
            className="block text-[11px] font-semibold uppercase tracking-wider mb-2"
            style={{ color: "var(--muted)" }}
          >
            Your Remarks
          </label>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={8}
            className="w-full px-4 py-3 rounded-xl text-[13px] leading-relaxed outline-none resize-none"
            style={{
              background: "var(--surface2)",
              border: "1px solid var(--border)",
              color: "var(--body)",
            }}
            onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
            onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
            placeholder="Add your remarks or comments here…"
          />
          <p className="text-[11px] mt-2" style={{ color: "var(--muted)" }}>
            {draft.length} characters · These notes are stored separately from the AI-generated justification and remediation.
          </p>
        </div>

        {/* Actions */}
        <div
          className="flex items-center gap-3 px-6 py-4"
          style={{ borderTop: "1px solid var(--border)", background: "var(--surface3)" }}
        >
          <button
            onClick={() => onAccept(draft)}
            disabled={!draft.trim()}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl text-[13px] font-bold transition-all"
            style={{
              background: draft.trim() ? "var(--btn-accept-bg)" : "var(--surface2)",
              color: draft.trim() ? "var(--btn-accept-text)" : "var(--dim)",
              boxShadow: draft.trim() ? "0 0 16px var(--btn-accept-glow)" : "none",
              cursor: draft.trim() ? "pointer" : "not-allowed",
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="20 6 9 17 4 12" />
            </svg>
            Save notes & accept
          </button>
          <button
            onClick={onCancel}
            className="px-5 py-2.5 rounded-xl text-[13px] font-semibold transition-opacity hover:opacity-80"
            style={{
              background: "var(--surface2)",
              color: "var(--faint)",
              border: "1px solid var(--border2)",
            }}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────
export default function CveReview({
  cve,
  agentSteps,
  tokenFragment,
  totalCves,
  reviewedCount,
  approvedCount,
  onDecision,
}: Props) {
  const [editOpen, setEditOpen] = useState(false);
  const canApprove  = usePermission("canApprove");
  const canReject   = usePermission("canReject");
  const { user }    = useAuth();

  const sevColor = SEV_COLOR[cve.severity] ?? "var(--faint)";
  const cvssColor =
    cve.cvss >= 9 ? "var(--accent-red)" :
    cve.cvss >= 7 ? "var(--accent-orange)" :
    cve.cvss >= 4 ? "var(--accent-yellow)" :
                    "var(--accent-green)";

  const isStub = cve.rationale?.startsWith("[Auto-generated stub");
  const displayRationale = isStub
    ? cve.rationale.replace(/^\[Auto-generated stub[^\]]*\]\s*/, "")
    : cve.rationale;

  // New-format records come pre-split from the backend (`remediation` is a
  // clean, separate field). Old-format records still have the remediation
  // instruction embedded inside `rationale` — fall back to splitting it out.
  const hasCleanRemediation = !!cve.remediation && cve.remediation.trim().length > 0;
  const legacySplit = !hasCleanRemediation && displayRationale ? splitLegacyRationale(displayRationale) : null;
  const justificationText = hasCleanRemediation
    ? displayRationale
    : legacySplit
    ? legacySplit.justification
    : displayRationale;
  const remediationText = hasCleanRemediation
    ? cve.remediation
    : legacySplit
    ? legacySplit.remediation
    : null;
  const manualNotesText = cve.manualNotes && cve.manualNotes.trim().length > 0 ? cve.manualNotes : null;

  return (
    <>
      {editOpen && (
        <EditModal
          cve={cve}
          onCancel={() => setEditOpen(false)}
          onAccept={(notes) => {
            setEditOpen(false);
            onDecision(cve.id, "approved", notes, cve.pkg, user?.roles?.[0]);
          }}
        />
      )}

      <main
        className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-6 px-8 py-7"
        style={{ background: "var(--bg)", overscrollBehavior: "contain" }}
      >

        {/* ── 1. CVE Identity bar ── */}
        <div
          className="rounded-2xl p-6 flex items-start gap-5"
          style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
        >
          {/* CVSS gauge */}
          <div
            className="w-20 h-20 rounded-2xl flex flex-col items-center justify-center flex-shrink-0"
            style={{
              background: `rgba(${cvssColor === "var(--accent-red)" ? "248,81,73" : cvssColor === "var(--accent-orange)" ? "240,136,62" : cvssColor === "var(--accent-yellow)" ? "210,153,34" : "63,185,80"}, 0.08)`,
              border: `1px solid ${cvssColor}33`,
            }}
          >
            <span className="text-3xl font-black leading-none" style={{ color: cvssColor }}>
              {cve.cvss}
            </span>
            <span className="text-[10px] font-bold uppercase tracking-widest mt-0.5" style={{ color: cvssColor + "99" }}>
              CVSS
            </span>
          </div>

          {/* Identity */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap mb-1">
              <h1 className="text-[22px] font-black tracking-tight" style={{ color: "var(--heading)" }}>
                {cve.id}
              </h1>
              <span
                className="text-[11px] font-bold px-3 py-1 rounded-full uppercase tracking-wide"
                style={{ background: SEV_BG[cve.severity], color: sevColor, border: `1px solid ${sevColor}33` }}
              >
                {cve.severity}
              </span>
            </div>
            <p className="text-[13px] leading-relaxed" style={{ color: "var(--subtle)" }}>
              <span style={{ color: "var(--body)" }}>{cve.pkg}</span>{" "}
              <span style={{ color: "var(--dim)" }}>·</span>{" "}
              <span>v{cve.version}</span>{" "}
              <span style={{ color: "var(--dim)" }}>→</span>{" "}
              <span style={{ color: "var(--accent-green)" }}>fix: {cve.fixedIn}</span>
            </p>
            <p className="text-[13px] mt-1 break-words" style={{ color: "var(--muted)" }}>
              {cve.description}
            </p>
          </div>

          {/* Quick facts */}
          <div className="flex flex-col gap-2 flex-shrink-0">
            {[
              { label: "Vector",  value: cve.vector },
              { label: "Auth",    value: cve.authRequired, warn: cve.authRequired === "None" },
              { label: "Impact",  value: cve.impact.split("—")[0].trim() },
            ].map((f) => (
              <div key={f.label} className="text-right">
                <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--dim)" }}>
                  {f.label}
                </div>
                <div
                  className="text-[12px] font-semibold"
                  style={{ color: f.warn ? "var(--accent-red)" : "var(--faint)" }}
                >
                  {f.value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── 2. Rationale card ── */}
        <div
          className="rounded-2xl overflow-hidden"
          style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
        >
          {/* Card header */}
          <div
            className="flex items-center gap-3 px-6 py-4"
            style={{ borderBottom: "1px solid var(--border)" }}
          >
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>
                  Mitigation Rationale
                </span>
                {isStub ? (
                  <span
                    className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider"
                    style={{
                      background: "rgba(210,153,34,0.1)",
                      color: "var(--accent-yellow)",
                      border: "1px solid rgba(210,153,34,0.3)",
                    }}
                  >
                    ⚠ Offline stub — LLM quota exhausted
                  </span>
                ) : (
                  <span
                    className="text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase tracking-wider"
                    style={{
                      background: "var(--accent-purple-bg)",
                      color: "var(--accent-purple)",
                      border: "1px solid var(--accent-purple-bdr)",
                    }}
                  >
                    AI Generated
                  </span>
                )}
              </div>
            </div>

            {/* RAG confidence */}
            {cve.ragMatch && (
              <div
                className="flex items-center gap-2.5 px-4 py-2 rounded-xl"
                style={{
                  background: "var(--accent-purple-bg)",
                  border: "1px solid var(--accent-purple-bdr)",
                }}
              >
                <div>
                  <div className="text-[20px] font-black leading-none" style={{ color: "var(--accent-purple)" }}>
                    {cve.ragMatch.pct}%
                  </div>
                  <div className="text-[10px]" style={{ color: "var(--accent-purple)" }}>
                    memory match
                  </div>
                </div>
                <div className="w-px h-8" style={{ background: "var(--accent-purple-bdr)" }} />
                <div>
                  <div className="text-[11px] font-semibold" style={{ color: "var(--body)" }}>
                    {cve.ragMatch.project}
                  </div>
                  <div className="text-[10px]" style={{ color: "var(--muted)" }}>
                    {cve.ragMatch.approver} · {cve.ragMatch.date}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Rationale body */}
          <div className="px-6 py-5">
            {displayRationale ? (
              <div className="flex flex-col gap-4">
                {/* Justification — always shown */}
                <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-purple)" }}>
                  <div
                    className="text-[11px] font-semibold uppercase tracking-wider mb-1.5"
                    style={{ color: "var(--accent-purple)" }}
                  >
                    Justification
                  </div>
                  <p
                    className="text-[14px] leading-[1.8] font-normal break-words whitespace-pre-wrap"
                    style={{ color: "var(--body)" }}
                  >
                    {justificationText}
                  </p>
                </div>

                {/* Recommended Remediation — shown whenever there's remediation content */}
                {remediationText && (
                  <>
                    <div style={{ borderTop: "1px solid var(--border)" }} />
                    <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-green)" }}>
                      <div
                        className="text-[11px] font-semibold uppercase tracking-wider mb-1.5"
                        style={{ color: "var(--accent-green)" }}
                      >
                        Recommended Remediation
                      </div>
                      <p
                        className="text-[14px] leading-[1.8] font-normal break-words whitespace-pre-wrap"
                        style={{ color: "var(--body)" }}
                      >
                        {remediationText}
                      </p>
                    </div>
                  </>
                )}

                {/* Manual Input — read-only display of human-added remarks */}
                {manualNotesText && (
                  <>
                    <div style={{ borderTop: "1px solid var(--border)" }} />
                    <div className="pl-4" style={{ borderLeft: "2px solid var(--accent-blue)" }}>
                      <div
                        className="text-[11px] font-semibold uppercase tracking-wider mb-1.5 flex items-center gap-2"
                        style={{ color: "var(--accent-blue)" }}
                      >
                        Manual Input
                        {cve.editedByRole && (
                          <span
                            className="text-[11px] font-normal normal-case tracking-normal"
                            style={{ color: "var(--muted)" }}
                          >
                            — added by {ROLE_LABELS[cve.editedByRole as UserRole] ?? cve.editedByRole}
                          </span>
                        )}
                      </div>
                      <p
                        className="text-[14px] leading-[1.8] font-normal break-words whitespace-pre-wrap"
                        style={{ color: "var(--body)" }}
                      >
                        {manualNotesText}
                      </p>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-3 py-4">
                <span
                  className="w-2 h-2 rounded-full animate-pulse"
                  style={{ background: "var(--accent-purple)" }}
                />
                <span className="text-[13px]" style={{ color: "var(--muted)" }}>
                  Agent is synthesising rationale…
                </span>
              </div>
            )}
          </div>

          {/* Memory source row */}
          {cve.ragMatch && (
            <div
              className="mx-6 mb-5 flex items-start gap-3 px-4 py-3 rounded-xl"
              style={{
                background: "var(--accent-purple-bg)",
                border: "1px solid var(--accent-purple-bdr)",
              }}
            >
              <div
                className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 mt-0.5 text-[12px]"
                style={{ background: "var(--accent-purple-bdr)", color: "var(--accent-purple)" }}
              >
                ◈
              </div>
              <p className="text-[12px] leading-relaxed break-words" style={{ color: "var(--subtle)" }}>
                <span style={{ color: "var(--accent-purple)" }}>Grounded from memory</span>
                {" — "}{cve.ragMatch.summary} Approved by{" "}
                <span style={{ color: "var(--body)" }}>{cve.ragMatch.approver}</span>
                {cve.ragMatch.date && <> on {cve.ragMatch.date}</>}
                {" "}({cve.ragMatch.project}).
              </p>
            </div>
          )}

          {/* ── Action row ── */}
          <div
            className="flex items-center gap-3 px-6 py-5"
            style={{ borderTop: "1px solid var(--border)", background: "var(--surface3)" }}
          >
            {canReject ? (
              <>
                {/* Primary — Accept */}
                <button
                  onClick={() => onDecision(cve.id, "approved", undefined, cve.pkg)}
                  className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all duration-150 hover:opacity-90 active:scale-[0.98]"
                  style={{
                    background: "var(--btn-accept-bg)",
                    color: "var(--btn-accept-text)",
                    boxShadow: "0 0 20px var(--btn-accept-glow)",
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Accept
                </button>

                {/* Secondary — Edit */}
                <button
                  onClick={() => setEditOpen(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all duration-150 hover:opacity-80"
                  style={{
                    background: "var(--surface2)",
                    color: "var(--faint)",
                    border: "1px solid var(--border2)",
                  }}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                  </svg>
                  Add Notes
                </button>

                {/* Danger — Reject */}
                <button
                  onClick={() => onDecision(cve.id, "rejected", undefined, cve.pkg)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all duration-150 hover:opacity-80"
                  style={{
                    background: "var(--accent-red-bg)",
                    color: "var(--accent-red)",
                    border: "1px solid var(--accent-red-bdr)",
                  }}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  Reject
                </button>
              </>
            ) : canApprove ? (
              <>
                {/* Primary — Submit (submit-only workflow: no reject) */}
                <button
                  onClick={() => onDecision(cve.id, "approved", undefined, cve.pkg)}
                  className="flex items-center gap-2 px-8 py-3 rounded-xl text-[14px] font-bold transition-all duration-150 hover:opacity-90 active:scale-[0.98]"
                  style={{
                    background: "var(--btn-accept-bg)",
                    color: "var(--btn-accept-text)",
                    boxShadow: "0 0 20px var(--btn-accept-glow)",
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Submit
                </button>

                {/* Secondary — Edit */}
                <button
                  onClick={() => setEditOpen(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-[14px] font-semibold transition-all duration-150 hover:opacity-80"
                  style={{
                    background: "var(--surface2)",
                    color: "var(--faint)",
                    border: "1px solid var(--border2)",
                  }}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                  </svg>
                  Add Notes
                </button>
              </>
            ) : (
              /* Read-only notice for non-approvers — unreachable by any of
                 today's 4 roles (ADMIN/DEVOPS_ENGINEER/DSO_MANAGER/CYBER_MANAGER
                 all have canApprove: true), kept for any future role that needs it */
              <div
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px]"
                style={{ background: "var(--accent-yellow-bg, rgba(210,153,34,0.08))", border: "1px solid rgba(210,153,34,0.2)", color: "var(--accent-yellow)" }}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                Read-only — your role ({user ? user.roles.map(r => ROLE_LABELS[r]).join(", ") : "current role"}) cannot approve or reject CVEs. A Cyber Manager must review this finding.
              </div>
            )}

            {/* Progress indicator */}
            <div className="ml-auto flex items-center gap-3">
              <div className="text-right">
                <div className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>
                  {reviewedCount} <span style={{ color: "var(--dim)" }}>/</span> {totalCves}
                </div>
                <div className="text-[11px]" style={{ color: "var(--muted)" }}>
                  {approvedCount} approved
                </div>
              </div>
              {/* Mini donut */}
              <svg width="36" height="36" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="14" fill="none" stroke="var(--border)" strokeWidth="3" />
                <circle
                  cx="18" cy="18" r="14"
                  fill="none"
                  stroke="var(--accent-green)"
                  strokeWidth="3"
                  strokeDasharray={`${totalCves > 0 ? (reviewedCount / totalCves) * 88 : 0} 88`}
                  strokeLinecap="round"
                  transform="rotate(-90 18 18)"
                />
              </svg>
            </div>
          </div>
        </div>

        {/* ── 3. Agent drawer ── */}
        <AgentDrawer steps={agentSteps} tokenFragment={tokenFragment} />
      </main>
    </>
  );
}
