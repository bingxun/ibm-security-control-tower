import { RunStats, CveRecord } from "@/lib/types";

interface Props {
  stats: RunStats;
  cves: CveRecord[];
}

export default function ContextPanel({ stats, cves }: Props) {
  const remaining = stats.total - stats.approved - stats.rejected;
  const pct = Math.round((stats.approved / stats.total) * 100);

  // Only show unique RAG matches (deduplicate by project)
  const ragMatches = Object.values(
    cves
      .filter((c) => c.ragMatch)
      .reduce<Record<string, NonNullable<CveRecord["ragMatch"]>>>((acc, c) => {
        if (c.ragMatch && !acc[c.ragMatch.project]) {
          acc[c.ragMatch.project] = c.ragMatch;
        }
        return acc;
      }, {})
  );

  return (
    <aside
      className="hidden lg:flex lg:w-64 flex-shrink-0 flex-col overflow-hidden"
      style={{ background: "var(--surface)", borderLeft: "1px solid var(--border)" }}
    >
      {/* ── Session overview ── */}
      <div className="p-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <p className="text-[11px] font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--muted)" }}>
          Session Overview
        </p>

        {/* Big progress ring */}
        <div className="flex items-center gap-4 mb-4">
          <svg width="56" height="56" viewBox="0 0 56 56" className="flex-shrink-0">
            <circle cx="28" cy="28" r="22" fill="none" stroke="var(--border)" strokeWidth="4" />
            <circle
              cx="28" cy="28" r="22"
              fill="none"
              stroke="var(--accent-green)"
              strokeWidth="4"
              strokeDasharray={`${pct * 1.382} 138.2`}
              strokeLinecap="round"
              transform="rotate(-90 28 28)"
              style={{ transition: "stroke-dasharray 0.5s ease" }}
            />
            <text x="28" y="32" textAnchor="middle" fontSize="12" fontWeight="bold" fill="var(--heading)">
              {pct}%
            </text>
          </svg>
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ background: "var(--accent-green)" }} />
              <span className="text-[12px]" style={{ color: "var(--faint)" }}>
                {stats.approved} approved
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ background: "var(--accent-red)" }} />
              <span className="text-[12px]" style={{ color: "var(--faint)" }}>
                {stats.rejected} rejected
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ background: "var(--accent-yellow)" }} />
              <span className="text-[12px]" style={{ color: "var(--faint)" }}>
                {remaining} remaining
              </span>
            </div>
          </div>
        </div>

        {/* Metric pills */}
        <div className="grid grid-cols-2 gap-2">
          {[
            { label: "Avg. synthesis", value: `${stats.avgSynthesisS}s`, color: "var(--accent-green)" },
            { label: "Tokens used",    value: stats.tokensUsed.toLocaleString(), color: "var(--accent-blue)" },
          ].map((m) => (
            <div
              key={m.label}
              className="rounded-xl px-3 py-2.5 text-center"
              style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
            >
              <div className="text-[15px] font-black" style={{ color: m.color }}>
                {m.value}
              </div>
              <div className="text-[10px] mt-0.5" style={{ color: "var(--muted)" }}>
                {m.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── RAG Memory ── */}
      <div className="flex flex-col flex-1 min-h-0 overflow-hidden">
        <p
          className="px-5 pt-4 pb-2 text-[11px] font-semibold uppercase tracking-wider flex-shrink-0"
          style={{ color: "var(--muted)" }}
        >
          Memory Matches
        </p>
        <div className="px-4 pb-4 flex flex-col gap-3 overflow-y-auto flex-1 min-h-0">
          {ragMatches.map((m) => (
            <div
              key={m.project}
              className="rounded-xl p-3.5"
              style={{ background: "var(--surface3)", border: "1px solid var(--border)" }}
            >
              {/* Match score bar */}
              <div className="flex items-center justify-between mb-2">
                <span
                  className="text-[11px] font-bold font-mono"
                  style={{ color: "var(--accent-blue)" }}
                >
                  {m.project}
                </span>
                <span
                  className="text-[11px] font-bold"
                  style={{ color: "var(--accent-purple)" }}
                >
                  {m.pct}%
                </span>
              </div>
              <div
                className="h-1 rounded-full overflow-hidden mb-3"
                style={{ background: "var(--border)" }}
              >
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${m.pct}%`,
                    background: "linear-gradient(90deg, #7c5cd8, #a371f7)",
                  }}
                />
              </div>
              <p className="text-[11px] leading-relaxed" style={{ color: "var(--subtle)" }}>
                {m.summary}
              </p>
              <p className="text-[10px] mt-1.5" style={{ color: "var(--dim)" }}>
                {m.approver} · {m.date}
              </p>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
