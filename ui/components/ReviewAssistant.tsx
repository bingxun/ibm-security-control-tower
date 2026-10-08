"use client";

import { useState } from "react";
import { CveRecord, ReviewSuggestion } from "@/lib/types";
import { requestReviewAI } from "@/lib/api";

const TYPE_LABEL: Record<ReviewSuggestion["type"], string> = {
  missing_evidence: "Missing evidence",
  unclear_assumption: "Unclear assumption",
  improvement: "Improvement",
  review_comment: "Review comment",
};

interface Props {
  runId?: string;
  cve: CveRecord;
  mode: "draft" | "review";
  /** Current (possibly unsaved) draft text to evaluate. */
  draft: { justification: string; remediation: string; notes: string };
  /** Suggestion ids the user has already applied. */
  appliedIds: string[];
  /** Fired when the user applies a suggestion — parent fills the field + records the id. */
  onApply: (s: ReviewSuggestion) => void;
}

export default function ReviewAssistant({ runId, cve, mode, draft, appliedIds, onApply }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<string>("");
  const [source, setSource] = useState<"rad" | "stub" | null>(null);
  const [suggestions, setSuggestions] = useState<ReviewSuggestion[]>([]);
  const [dismissed, setDismissed] = useState<string[]>([]);

  const run = async () => {
    if (!runId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await requestReviewAI(runId, {
        cve_id: cve.id, pkg: cve.pkg, mode,
        justification: draft.justification, remediation: draft.remediation, notes: draft.notes,
      });
      setSummary(result.summary);
      setSource(result.source);
      setSuggestions(result.suggestions);
      setDismissed([]);
    } catch {
      setError("Review AI is unavailable right now. Try again shortly.");
    } finally {
      setLoading(false);
    }
  };

  const visible = suggestions.filter((s) => !dismissed.includes(s.id));

  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--accent-purple-bdr)" }}>
      <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
        <span className="text-[14px] font-bold" style={{ color: "var(--accent-purple)" }}>Review AI</span>
        <span className="text-[11px]" style={{ color: "var(--muted)" }}>
          {mode === "review" ? "Assess the submission & draft comments" : "Evaluate your draft before submitting"}
        </span>
        <button
          onClick={run}
          disabled={loading || !runId}
          className="ml-auto flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-bold transition-all"
          style={{
            background: "var(--accent-purple-bg)", color: "var(--accent-purple)",
            border: "1px solid var(--accent-purple-bdr)", cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Analyzing…" : suggestions.length ? "Re-run Review AI" : "Run Review AI"}
        </button>
      </div>

      <div className="px-6 py-4 flex flex-col gap-3">
        {error && <p className="text-[12px]" style={{ color: "var(--accent-red)" }}>{error}</p>}
        {!error && !suggestions.length && !loading && (
          <p className="text-[12px]" style={{ color: "var(--muted)" }}>
            Suggestions are advisory — nothing is changed or submitted until you apply and act on it yourself.
          </p>
        )}
        {summary && (
          <p className="text-[12px] leading-relaxed" style={{ color: "var(--subtle)" }}>
            {summary}
            {source === "stub" && (
              <span className="ml-2 text-[10px] font-bold uppercase tracking-wider" style={{ color: "var(--accent-yellow)" }}>
                offline stub
              </span>
            )}
          </p>
        )}

        {visible.map((s) => {
          const applied = appliedIds.includes(s.id);
          return (
            <div key={s.id} className="rounded-xl p-3.5" style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider"
                  style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)" }}>
                  {TYPE_LABEL[s.type]}
                </span>
                <span className="text-[12px] font-semibold" style={{ color: "var(--heading)" }}>{s.title}</span>
              </div>
              <p className="text-[12px] leading-relaxed mb-2" style={{ color: "var(--body)" }}>{s.detail}</p>
              {s.suggestedText && (
                <div className="rounded-lg px-3 py-2 mb-2 text-[12px] leading-relaxed whitespace-pre-wrap"
                  style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--subtle)" }}>
                  {s.suggestedText}
                </div>
              )}
              <div className="flex items-center gap-2">
                {s.suggestedText && (
                  <button
                    onClick={() => onApply(s)}
                    disabled={applied}
                    className="px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all"
                    style={{
                      background: applied ? "var(--surface2)" : "var(--accent-green-bg)",
                      color: applied ? "var(--dim)" : "var(--accent-green)",
                      border: `1px solid ${applied ? "var(--border)" : "var(--accent-green-bdr)"}`,
                      cursor: applied ? "default" : "pointer",
                    }}
                  >
                    {applied ? "✓ Applied" : "Apply suggestion"}
                  </button>
                )}
                <button
                  onClick={() => setDismissed((d) => [...d, s.id])}
                  className="px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-opacity hover:opacity-70"
                  style={{ background: "var(--surface)", color: "var(--muted)", border: "1px solid var(--border)" }}
                >
                  Dismiss
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
