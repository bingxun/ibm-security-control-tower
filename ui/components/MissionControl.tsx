"use client";

import { useEffect, useRef, useState } from "react";
import { CveRecord, AgentStep, RunStats, cveKey } from "@/lib/types";

interface Props {
  agentSteps: AgentStep[];
  cves: CveRecord[];
  tokenFragment: string;
  stats: RunStats;
  imageRef: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "var(--accent-red)",
  high:     "var(--accent-orange)",
  medium:   "var(--accent-yellow)",
  low:      "var(--accent-green)",
};

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener?.("change", update);
    return () => mq.removeEventListener?.("change", update);
  }, []);
  return reduced;
}

/** Animate a number from its previous value to the next one. Snaps if reduced-motion. */
function useCountUp(value: number, reduced: boolean): number {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (reduced) return; // reduced-motion: render `value` directly (see return)
    const from = fromRef.current;
    const to = value;
    if (from === to) return;
    const start = performance.now();
    const dur = 500;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (to - from) * eased)); // in rAF callback, not sync in effect
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
      else fromRef.current = to;
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [value, reduced]);

  return reduced ? value : display;
}

function chipLabel(step: AgentStep | undefined, test: (l: string) => boolean): string | null {
  if (!step) return null;
  const hit = step.chips.find((c) => test(c.label));
  return hit?.label ?? null;
}

type Slave = {
  key: string;
  id: string;
  pkg: string;
  severity: string;
  done: boolean;
  source: "rad" | "stub" | null;
  elapsed: string | null;
  ragHits: string | null;
};

function Stat({ label, value, color, reduced }: { label: string; value: number; color: string; reduced: boolean }) {
  const shown = useCountUp(value, reduced);
  return (
    <div className="text-center">
      <div className="text-[22px] font-black leading-none tabular-nums" style={{ color }}>{shown.toLocaleString()}</div>
      <div className="text-[10px] uppercase tracking-wider mt-1" style={{ color: "var(--muted)" }}>{label}</div>
    </div>
  );
}

export default function MissionControl({ agentSteps, cves, tokenFragment, stats, imageRef }: Props) {
  const reduced = usePrefersReducedMotion();

  const total = cves.length;
  const synthesised = cves.filter((c) => c.status !== "queued").length;
  const autoTriage = agentSteps.find((s) => s.id === "auto-triage");

  // One slave agent per CVE; status/metadata derived from its two synthesis steps.
  const slaves: Slave[] = cves.map((cve) => {
    const draft = agentSteps.find((s) => s.id === `draft-${cve.id}-${cve.pkg}`);
    const mem = agentSteps.find((s) => s.id === `rag-${cve.id}-${cve.pkg}`);
    const done = cve.status !== "queued" || Boolean(draft);
    const srcLabel = chipLabel(draft, (l) => l === "ibm_rad" || l === "offline_stub");
    return {
      key: cveKey(cve),
      id: cve.id,
      pkg: cve.pkg,
      severity: cve.severity,
      done,
      source: srcLabel === "ibm_rad" ? "rad" : srcLabel === "offline_stub" ? "stub" : null,
      elapsed: chipLabel(draft, (l) => /s$/.test(l) && /\d/.test(l)),
      ragHits: chipLabel(mem, (l) => /hit/.test(l)) ?? (mem ? "no prior match" : null),
    };
  });

  // Approximate the in-flight workers: the first few not-yet-done cards pulse.
  let activeBudget = 4;

  return (
    <div className="flex flex-col gap-5">
      {/* ── Master coordinator + live counters ── */}
      <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--accent-purple-bdr)" }}>
        <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: "1px solid var(--border)", background: "linear-gradient(135deg, rgba(176,131,255,0.14), rgba(88,166,255,0.06))" }}>
          <span className="grid place-items-center w-9 h-9 rounded-xl flex-shrink-0" style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" /></svg>
          </span>
          <div className="min-w-0">
            <div className="text-[13px] font-bold" style={{ color: "var(--heading)" }}>Master agent · orchestrating {total} CVE workers</div>
            <div className="text-[11px] truncate" style={{ color: "var(--muted)" }}>{imageRef || "container image"} · bounded parallel assessment</div>
          </div>
          <span className="ml-auto flex items-center gap-1.5 text-[11px] font-bold px-2.5 py-1 rounded-full flex-shrink-0" style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)", border: "1px solid var(--accent-purple-bdr)" }}>
            <span className={`w-1.5 h-1.5 rounded-full ${reduced ? "" : "animate-pulse"}`} style={{ background: "var(--accent-purple)" }} />
            LIVE
          </span>
        </div>
        <div className="grid grid-cols-4 gap-2 px-6 py-4">
          <Stat label="Synthesised" value={synthesised} color="var(--accent-blue)" reduced={reduced} />
          <Stat label="Workers" value={total} color="var(--heading)" reduced={reduced} />
          <Stat label="Memory hits" value={stats.ragHits ?? 0} color="var(--accent-purple)" reduced={reduced} />
          <Stat label="Tokens" value={stats.tokensUsed ?? 0} color="var(--accent-green)" reduced={reduced} />
        </div>

        {/* Live token stream from the active worker */}
        {tokenFragment && (
          <div className="px-6 pb-4">
            <div className="rounded-xl px-4 py-3 font-mono text-[11px] leading-relaxed" style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--subtle)" }}>
              <span style={{ color: "var(--accent-purple)" }}>▍synthesising </span>
              {tokenFragment.slice(-280)}
              <span className={reduced ? "" : "animate-pulse"} style={{ color: "var(--accent-purple)" }}>▋</span>
            </div>
          </div>
        )}
      </div>

      {/* ── Auto-triage banner (learning loop in action) ── */}
      {autoTriage && (
        <div className="rounded-2xl px-5 py-3.5 flex items-center gap-3 ct-fade-up" style={{ background: "var(--accent-green-bg)", border: "1px solid var(--accent-green-bdr)" }}>
          <span className="text-[15px]" style={{ color: "var(--accent-green)" }}>⚡</span>
          <p className="text-[12px] font-medium" style={{ color: "var(--body)" }}>{autoTriage.title}</p>
        </div>
      )}

      {/* ── Slave agent grid ── */}
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))" }}>
        {slaves.map((s) => {
          const pulsing = !s.done && activeBudget-- > 0;
          const sev = SEV_COLOR[s.severity] ?? "var(--faint)";
          return (
            <div
              key={s.key}
              className={`rounded-xl px-4 py-3 ${reduced ? "" : "ct-fade-up"}`}
              style={{
                background: "var(--surface)",
                border: `1px solid ${s.done ? "var(--accent-green-bdr)" : pulsing ? "var(--accent-purple-bdr)" : "var(--border)"}`,
                opacity: s.done || pulsing ? 1 : 0.6,
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: sev }} />
                <span className="text-[11.5px] font-mono font-semibold truncate" style={{ color: "var(--heading)" }}>{s.id}</span>
                <span className="ml-auto text-[13px] flex-shrink-0" style={{ color: s.done ? "var(--accent-green)" : "var(--accent-purple)" }}>
                  {s.done ? "✓" : <span className={reduced ? "" : "animate-pulse"}>●</span>}
                </span>
              </div>
              <div className="text-[10px] truncate mb-2" style={{ color: "var(--muted)" }}>{s.pkg}</div>

              {/* Stage pips: Memory → Assess */}
              <div className="flex items-center gap-1.5">
                <StagePip label="Memory" active={Boolean(s.ragHits) || s.done} />
                <div className="flex-1 h-px" style={{ background: "var(--border)" }} />
                <StagePip label="Assess" active={s.done} />
              </div>

              {/* Metadata badges */}
              <div className="flex items-center gap-1.5 mt-2.5 flex-wrap">
                {s.ragHits && (
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--accent-purple-bg)", color: "var(--accent-purple)" }}>◈ {s.ragHits}</span>
                )}
                {s.source && (
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded" style={{
                    background: s.source === "rad" ? "rgba(88,166,255,0.12)" : "rgba(210,153,34,0.12)",
                    color: s.source === "rad" ? "var(--accent-blue)" : "var(--accent-yellow)",
                  }}>{s.source === "rad" ? "IBM RAD" : "offline stub"}</span>
                )}
                {s.elapsed && (
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{ background: "var(--surface2)", color: "var(--muted)" }}>{s.elapsed}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StagePip({ label, active }: { label: string; active: boolean }) {
  return (
    <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded" style={{
      background: active ? "var(--accent-green-bg)" : "var(--surface2)",
      color: active ? "var(--accent-green)" : "var(--dim)",
    }}>{label}</span>
  );
}
