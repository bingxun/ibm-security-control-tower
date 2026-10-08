"use client";

import { useState, useEffect, useRef } from "react";
import { AgentStep } from "@/lib/types";

interface Props {
  steps: AgentStep[];
  tokenFragment: string;
}

// Static pipeline stage labels shown in the mini-preview strip.
// Steps from the backend have dynamic IDs (e.g. "rag-CVE-2024-3094"),
// so we match by prefix rather than exact ID.
const STAGES = [
  { prefix: "ingest",  label: "Ingest",  },
  { prefix: "master", label: "Master" },
  { prefix: "rag",     label: "Memory slave",  },
  { prefix: "draft",   label: "Assessment slave",   },
  { prefix: "auto-triage", label: "Auto-triage" },
  { prefix: "approval",label: "Approval",},
  { prefix: "persist", label: "Persist", },
];

const CHIP_STYLE: Record<string, { bg: string; color: string }> = {
  rag:    { bg: "var(--accent-purple-bdr)", color: "var(--accent-purple)" },
  tool:   { bg: "rgba(210,153,34,0.12)",  color: "var(--accent-yellow)"  },
  llm:    { bg: "rgba(68,147,248,0.12)",  color: "var(--accent-blue)"  },
  done:   { bg: "rgba(63,185,80,0.12)",   color: "var(--accent-green)"  },
  stream: { bg: "var(--accent-purple-bg)", color: "var(--accent-purple)"  },
};

export default function AgentDrawer({ steps, tokenFragment }: Props) {
  // Open by default — the agent's reasoning trace is a headline feature, not a footnote.
  const [open, setOpen] = useState(true);

  // Progressive reveal — the trace "streams in" step-by-step so it reads as the
  // agent thinking live (works whether steps arrive via SSE or are replayed).
  const [revealed, setRevealed] = useState(0);
  const lenRef = useRef(0);
  useEffect(() => { lenRef.current = steps.length; }, [steps.length]);
  useEffect(() => {
    const id = setInterval(() => {
      setRevealed((r) => {
        const len = lenRef.current;
        if (r >= len) return r;
        return Math.min(r + Math.max(1, Math.ceil(len / 40)), len); // ~finish in <12s even for big traces
      });
    }, 280);
    return () => clearInterval(id);
  }, []);
  const shown = steps.slice(0, revealed);
  const streaming = revealed < steps.length;

  // Match a stage prefix against step IDs (handles dynamic IDs like "rag-CVE-2024-3094")
  const stageState = (prefix: string): "done" | "active" | "waiting" => {
    const matching = steps.filter((s) => s.id === prefix || s.id.startsWith(prefix + "-"));
    if (matching.length === 0) return "waiting";
    if (matching.some((s) => s.state === "active")) return "active";
    if (matching.every((s) => s.state === "done")) return "done";
    return "active";
  };

  return (
    <div
      className="rounded-2xl overflow-hidden"
      style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
    >
      {/* Trigger row */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-5 py-4 transition-colors text-left"
        style={{ borderBottom: open ? "1px solid var(--border)" : "1px solid transparent" }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface2)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        {/* Pipeline mini-preview */}
        <div className="flex items-center gap-1.5 flex-1">
          {STAGES.map((n, i) => {
            const state = stageState(n.prefix);
            return (
              <div key={n.prefix} className="flex items-center gap-1.5">
                <div
                  className="flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] font-medium"
                  style={
                    state === "done"
                      ? { background: "var(--accent-green-bg)", color: "var(--accent-green)" }
                      : state === "active"
                      ? { background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid rgba(163,113,247,0.25)" }
                      : { background: "var(--surface2)", color: "var(--dim)" }
                  }
                >
                  {state === "done" && <span>✓</span>}
                  {state === "active" && (
                    <span
                      className="w-1.5 h-1.5 rounded-full inline-block"
                      style={{ background: "var(--accent-purple)" }}
                    />
                  )}
                  {n.label}
                </div>
                {i < STAGES.length - 1 && (
                  <div
                    className="w-3 h-px"
                    style={{ background: state === "done" ? "var(--accent-green)" : "var(--border)" }}
                  />
                )}
              </div>
            );
          })}
        </div>

        <span className="text-[11px] font-semibold flex-shrink-0" style={{ color: "var(--accent-purple)" }}>
          ◈ Agent reasoning{steps.length ? ` · ${steps.length} steps` : ""}
        </span>
        <span
          className="text-[12px] transition-transform duration-200 inline-block"
          style={{
            color: "var(--muted)",
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
          }}
        >
          ▾
        </span>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="p-5 flex flex-col gap-4">
          {/* Stream controls */}
          <div className="flex items-center gap-2">
            {streaming ? (
              <span className="flex items-center gap-2 text-[11px] font-semibold" style={{ color: "var(--accent-purple)" }}>
                <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-purple)", boxShadow: "0 0 6px var(--accent-purple-glow)" }} />
                Streaming agent reasoning… {revealed}/{steps.length}
              </span>
            ) : (
              <span className="text-[11px]" style={{ color: "var(--muted)" }}>Trace complete · {steps.length} steps</span>
            )}
            <button
              onClick={() => setRevealed(0)}
              className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-opacity hover:opacity-80"
              style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}
            >
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M3 2v6h6" /><path d="M3 13a9 9 0 1 0 3-7.7L3 8" /></svg>
              Replay
            </button>
          </div>

          {/* Timeline steps */}
          <div className="flex flex-col gap-0">
            {shown.map((step, i) => (
              <div key={step.id} className="flex gap-4 ct-fade-up">
                {/* Timeline line */}
                <div className="flex flex-col items-center">
                  <div
                    className="w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold flex-shrink-0 z-10"
                    style={
                      step.state === "done"
                        ? { background: "var(--accent-green)", color: "var(--surface)" }
                        : step.state === "active"
                        ? { background: "var(--accent-purple-bdr)", color: "var(--accent-purple)", border: "1px solid rgba(163,113,247,0.5)" }
                        : { background: "var(--surface2)", color: "var(--dim)", border: "1px solid var(--border)" }
                    }
                  >
                    {step.state === "done" ? "✓" : step.state === "active" ? "●" : i + 1}
                  </div>
                  {i < shown.length - 1 && (
                    <div
                      className="w-px flex-1 my-1"
                      style={{
                        background: step.state === "done" ? "var(--accent-green)" : "var(--border)",
                        minHeight: "16px",
                      }}
                    />
                  )}
                </div>

                {/* Content */}
                <div
                  className="flex-1 pb-4 min-w-0"
                  style={{ paddingTop: "2px" }}
                >
                  <p
                    className="text-[13px] font-semibold leading-snug"
                    style={{ color: step.state === "active" ? "var(--heading)" : step.state === "done" ? "var(--faint)" : "var(--muted)" }}
                  >
                    {step.title}
                  </p>
                  <p className="text-[12px] mt-0.5 leading-relaxed" style={{ color: "var(--muted)" }}>
                    {step.desc}
                  </p>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {step.chips.map((chip, ci) => {
                      const s = CHIP_STYLE[chip.variant] ?? CHIP_STYLE.done;
                      return (
                        <span
                          key={ci}
                          className="text-[10px] font-medium px-2 py-0.5 rounded-md font-mono"
                          style={{ background: s.bg, color: s.color }}
                        >
                          {chip.label}
                        </span>
                      );
                    })}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Live token output */}
          <div
            className="rounded-xl overflow-hidden"
            style={{ border: "1px solid var(--accent-purple-bdr)" }}
          >
            <div
              className="flex items-center gap-2 px-4 py-2.5"
              style={{
                background: "var(--accent-purple-bg)",
                borderBottom: "1px solid rgba(163,113,247,0.12)",
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ background: "var(--accent-purple)", boxShadow: "0 0 6px rgba(163,113,247,0.6)" }}
              />
              <span className="text-[11px] font-semibold" style={{ color: "var(--accent-purple)" }}>
                Latest assessment
              </span>
            </div>
            <div className="px-4 py-3" style={{ background: "var(--surface3)" }}>
              <p className="text-[12px] font-mono leading-relaxed" style={{ color: "var(--subtle)" }}>
                {tokenFragment}
                <span
                  className="inline-block w-1.5 h-3.5 rounded-sm ml-0.5 align-text-bottom"
                  style={{ background: "var(--accent-purple)" }}
                />
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
