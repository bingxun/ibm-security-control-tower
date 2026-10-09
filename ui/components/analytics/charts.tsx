"use client";

import { useEffect, useRef, useState } from "react";

// Measure a container's pixel width so SVGs render crisp (no viewBox scaling of strokes)
// and hover math is exact.
function useWidth(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement | null>(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => setW(entries[0].contentRect.width));
    ro.observe(el);
    setW(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

// ── Horizontal bar chart ─────────────────────────────────────────────────────
// Job: magnitude across a small set of labeled categories. Each bar is direct-
// labeled (name + value), so identity never rests on color alone.
export function HBarChart({ data, formatValue }: {
  data: { label: string; value: number; color: string }[];
  formatValue?: (n: number) => string;
}) {
  const max = Math.max(1, ...data.map((d) => d.value));
  const fmt = formatValue ?? ((n: number) => n.toLocaleString());
  return (
    <div className="flex flex-col gap-3">
      {data.map((d) => (
        <div key={d.label} className="group flex items-center gap-3">
          <div className="w-28 flex-shrink-0 flex items-center gap-2 min-w-0">
            <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: d.color }} />
            <span className="text-[12px] truncate" style={{ color: "var(--subtle)" }} title={d.label}>{d.label}</span>
          </div>
          <div className="flex-1 h-5 rounded-md relative overflow-hidden" style={{ background: "var(--surface2)" }}>
            <div
              className="h-full rounded-md transition-[width] duration-500"
              style={{ width: `${(d.value / max) * 100}%`, background: d.color, minWidth: d.value > 0 ? 4 : 0 }}
              title={`${d.label}: ${fmt(d.value)}`}
            />
          </div>
          <span className="w-14 text-right text-[12px] font-bold tabular-nums flex-shrink-0" style={{ color: "var(--heading)" }}>{fmt(d.value)}</span>
        </div>
      ))}
    </div>
  );
}

// ── Area chart (single series over time) ─────────────────────────────────────
// Job: change over time. Single series → no legend; the title names it. Area
// fill + 2px line + emphasized endpoint + hover crosshair/tooltip.
export function AreaChart({ data, color = "var(--accent-purple)", height = 180, formatValue }: {
  data: { label: string; value: number }[];
  color?: string;
  height?: number;
  formatValue?: (n: number) => string;
}) {
  const [ref, w] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const fmt = formatValue ?? ((n: number) => n.toLocaleString());

  const padL = 8, padR = 8, padT = 12, padB = 26;
  const innerW = Math.max(0, w - padL - padR);
  const innerH = height - padT - padB;
  const max = Math.max(1, ...data.map((d) => d.value));
  const n = data.length;
  const x = (i: number) => padL + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => padT + innerH - (v / max) * innerH;

  const pts = data.map((d, i) => [x(i), y(d.value)] as const);
  const line = pts.map(([px, py], i) => `${i === 0 ? "M" : "L"}${px},${py}`).join(" ");
  const area = n > 0 ? `${line} L${x(n - 1)},${padT + innerH} L${x(0)},${padT + innerH} Z` : "";
  const gid = `area-grad-${Math.round(height)}`;

  const onMove = (e: React.MouseEvent) => {
    if (w <= 0 || n === 0) return;
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const rx = e.clientX - rect.left;
    let best = 0, bd = Infinity;
    for (let i = 0; i < n; i++) { const d = Math.abs(x(i) - rx); if (d < bd) { bd = d; best = i; } }
    setHover(best);
  };

  return (
    <div ref={ref} className="relative w-full" style={{ height }} onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
      {w > 0 && (
        <svg width={w} height={height} role="img" aria-label="Scan activity over time">
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.28" />
              <stop offset="100%" stopColor={color} stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {/* baseline */}
          <line x1={padL} y1={padT + innerH} x2={w - padR} y2={padT + innerH} stroke="var(--border)" strokeWidth="1" />
          {area && <path d={area} fill={`url(#${gid})`} />}
          {line && <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />}
          {/* endpoint + hover markers */}
          {pts.map(([px, py], i) => {
            const active = hover === i || (hover === null && i === n - 1);
            return active ? <circle key={i} cx={px} cy={py} r={i === n - 1 && hover === null ? 4 : 5} fill={color} stroke="var(--surface)" strokeWidth="2" /> : null;
          })}
          {hover !== null && <line x1={x(hover)} y1={padT} x2={x(hover)} y2={padT + innerH} stroke={color} strokeWidth="1" strokeDasharray="3 3" opacity="0.5" />}
          {/* x labels */}
          {data.map((d, i) => (
            <text key={i} x={x(i)} y={height - 8} textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"} fontSize="10" fill="var(--muted)">{d.label}</text>
          ))}
        </svg>
      )}
      {hover !== null && data[hover] && (
        <div
          className="absolute pointer-events-none px-2.5 py-1.5 rounded-lg text-[11px] whitespace-nowrap z-10"
          style={{
            left: Math.min(Math.max(x(hover), 48), w - 48), top: 4, transform: "translateX(-50%)",
            background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "0 4px 14px rgba(0,0,0,0.25)", color: "var(--body)",
          }}
        >
          <span style={{ color: "var(--muted)" }}>{data[hover].label}</span> · <span className="font-bold" style={{ color: "var(--heading)" }}>{fmt(data[hover].value)}</span>
        </div>
      )}
    </div>
  );
}

// ── Chart card wrapper ───────────────────────────────────────────────────────
export function ChartCard({ title, subtitle, right, children }: {
  title: string; subtitle?: string; right?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}>
      <div className="flex items-start justify-between gap-3 px-5 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="min-w-0">
          <h2 className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>{title}</h2>
          {subtitle && <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{subtitle}</p>}
        </div>
        {right}
      </div>
      <div className="px-5 py-5">{children}</div>
    </div>
  );
}
