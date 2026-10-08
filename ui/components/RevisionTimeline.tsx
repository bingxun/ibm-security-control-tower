"use client";

import { RevisionRecord, ROLE_LABELS, UserRole } from "@/lib/types";

const ACTION: Record<RevisionRecord["action"], { label: string; color: string }> = {
  submitted:          { label: "Submitted",         color: "var(--accent-blue)"   },
  approved:           { label: "Approved",           color: "var(--accent-green)"  },
  rejected:           { label: "Rejected",           color: "var(--accent-red)"    },
  changes_requested:  { label: "Changes requested",  color: "var(--accent-yellow)" },
};

function when(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function RevisionTimeline({ revisions }: { revisions: RevisionRecord[] }) {
  if (!revisions.length) return null;

  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
      <div className="px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
        <span className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>Revision history</span>
        <span className="ml-2 text-[11px]" style={{ color: "var(--muted)" }}>{revisions.length} event(s)</span>
      </div>
      <div className="px-6 py-4 flex flex-col gap-3">
        {revisions.map((r, i) => {
          const a = ACTION[r.action];
          const role = ROLE_LABELS[r.actor_role as UserRole] ?? r.actor_role;
          return (
            <div key={i} className="flex gap-3">
              <div className="flex flex-col items-center flex-shrink-0">
                <span className="w-2.5 h-2.5 rounded-full mt-1" style={{ background: a.color }} />
                {i < revisions.length - 1 && <span className="w-px flex-1 mt-1" style={{ background: "var(--border)" }} />}
              </div>
              <div className="flex-1 min-w-0 pb-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12px] font-bold" style={{ color: a.color }}>{a.label}</span>
                  <span className="text-[11px]" style={{ color: "var(--muted)" }}>round {r.round}</span>
                  <span className="text-[11px]" style={{ color: "var(--subtle)" }}>{r.actor} · {role}</span>
                  <span className="text-[10px] ml-auto" style={{ color: "var(--dim)" }}>{when(r.created_at)}</span>
                </div>
                {r.review_comment && (
                  <p className="text-[12px] mt-1 leading-relaxed break-words" style={{ color: "var(--body)" }}>
                    {r.review_comment}
                  </p>
                )}
                {r.requested_changes && (
                  <p className="text-[12px] mt-1 leading-relaxed break-words" style={{ color: "var(--accent-yellow)" }}>
                    Requested: {r.requested_changes}
                  </p>
                )}
                {r.action === "submitted" && r.justification && (
                  <p className="text-[11px] mt-1 leading-relaxed break-words line-clamp-3" style={{ color: "var(--muted)" }}>
                    {r.justification}
                  </p>
                )}
                {r.ai_suggestions_applied.length > 0 && (
                  <span className="inline-block text-[10px] mt-1 px-2 py-0.5 rounded-full"
                    style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)" }}>
                    {r.ai_suggestions_applied.length} AI suggestion(s) applied
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
