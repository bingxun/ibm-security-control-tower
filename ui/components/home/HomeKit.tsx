"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import TopNav from "@/components/TopNav";
import ProjectIcon from "@/components/ProjectIcon";
import management from "@/components/Management.module.css";
import type { Project, ScanSummary } from "@/lib/api";

// ── Derived scan metrics (ScanSummary has no "awaiting_approval"; derive it) ──
export const pending = (s: ScanSummary) => Math.max(0, s.totalCves - s.approved - s.rejected);
export const awaitingReview = (scans: ScanSummary[]) => scans.filter((s) => pending(s) > 0);
export const inProgress = (scans: ScanSummary[]) => scans.filter((s) => s.status === "running");
// Findings a Cyber Manager sent back to DevOps to revise and resubmit.
export const changesRequested = (s: ScanSummary) => s.changesRequested ?? 0;
export const needsMyAction = (scans: ScanSummary[]) => scans.filter((s) => changesRequested(s) > 0);

// ── Page scaffold shared by every role home ──────────────────────────────────
export function HomeShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: "var(--bg)", color: "var(--heading)" }}>
      <TopNav />
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-8 py-8 flex flex-col gap-8">
          {children}
        </div>
      </div>
    </div>
  );
}

// ── Hero: title + subtitle on the left, actions on the right ──────────────────
export function Hero({ title, subtitle, actions }: { title: string; subtitle: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-6 flex-wrap">
      <div>
        <h1 className="text-[26px] font-black tracking-tight" style={{ color: "var(--heading)" }}>{title}</h1>
        <p className="text-[14px] mt-1" style={{ color: "var(--subtle)" }}>{subtitle}</p>
      </div>
      {actions && <div className="flex items-center gap-3 flex-shrink-0">{actions}</div>}
    </div>
  );
}

// ── Buttons ───────────────────────────────────────────────────────────────────
export function PrimaryLink({ href, icon, children }: { href: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-2.5 px-6 py-3 rounded-xl text-[14px] font-bold flex-shrink-0 transition-opacity hover:opacity-85"
      style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 24px var(--btn-accept-glow)" }}
    >
      {icon}
      {children}
    </Link>
  );
}

export function SecondaryLink({ href, icon, children }: { href: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-2.5 px-5 py-3 rounded-xl text-[14px] font-bold flex-shrink-0 transition-colors"
      style={{ background: "var(--surface)", color: "var(--body)", border: "1px solid var(--border2)" }}
    >
      {icon}
      {children}
    </Link>
  );
}

export const PlusIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

export const ReviewIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
  </svg>
);

// ── KPI card ──────────────────────────────────────────────────────────────────
export function StatCard({ value, label, sub, color, icon }: { value: string; label: string; sub: string; color: string; icon?: ReactNode }) {
  return (
    <div
      className="group relative rounded-2xl px-5 py-4 overflow-hidden transition-transform duration-200 hover:-translate-y-0.5"
      style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}
    >
      {/* top accent strip */}
      <div className="absolute inset-x-0 top-0 h-[3px] opacity-80" style={{ background: color }} />
      {/* soft color wash in the corner */}
      <div className="absolute -right-6 -top-6 w-20 h-20 rounded-full blur-2xl opacity-20 group-hover:opacity-35 transition-opacity" style={{ background: color }} />
      <div className="relative flex items-start justify-between">
        <div className="text-[30px] font-black leading-none tracking-tight tabular-nums" style={{ color }}>{value}</div>
        {icon && (
          <span className="grid place-items-center w-8 h-8 rounded-xl" style={{ background: `${color}1a`, color, border: `1px solid ${color}2e` }}>{icon}</span>
        )}
      </div>
      <div className="relative text-[12.5px] font-semibold mt-2" style={{ color: "var(--heading)" }}>{label}</div>
      <div className="relative text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{sub}</div>
    </div>
  );
}

export function StatGrid({ children, cols = 4 }: { children: ReactNode; cols?: 3 | 4 }) {
  return <div className={`grid gap-4 ${cols === 3 ? "grid-cols-3" : "grid-cols-4"}`}>{children}</div>;
}

// ── Security posture: severity distribution + review funnel ───────────────────
const SEV_DEF = [
  { key: "critical", label: "Critical", color: "var(--accent-red)" },
  { key: "high",     label: "High",     color: "var(--accent-orange)" },
  { key: "medium",   label: "Medium",   color: "var(--accent-yellow)" },
  { key: "low",      label: "Low",      color: "var(--accent-green)" },
] as const;

export function PostureCard({ scans }: { scans: ScanSummary[] }) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0, approved = 0, rejected = 0;
  for (const s of scans) {
    sev.critical += s.critical; sev.high += s.high; sev.medium += s.medium;
    sev.low += Math.max(0, s.totalCves - s.critical - s.high - s.medium);
    total += s.totalCves; approved += s.approved; rejected += s.rejected;
  }
  const open = Math.max(0, total - approved - rejected);
  const sevTotal = sev.critical + sev.high + sev.medium + sev.low || 1;
  const reviewed = approved + rejected;
  const pct = total ? Math.round((reviewed / total) * 100) : 0;

  const funnel = [
    { label: "Approved", value: approved, color: "var(--accent-green)" },
    { label: "Rejected", value: rejected, color: "var(--accent-red)" },
    { label: "Open",     value: open,     color: "var(--accent-yellow)" },
  ];

  return (
    <div className="rounded-2xl overflow-hidden" style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}>
      <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
        <h2 className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>Security posture</h2>
        <span className="text-[11px] font-mono" style={{ color: "var(--muted)" }}>{total} findings · {scans.length} scans</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6 px-6 py-5">
        {/* Severity distribution — stacked bar (fixed order, 2px gaps) */}
        <div className="md:col-span-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider mb-2.5" style={{ color: "var(--muted)" }}>Severity distribution</div>
          <div className="flex h-3 rounded-full overflow-hidden" style={{ gap: "2px", background: "var(--surface2)" }}>
            {SEV_DEF.map((s) => {
              const v = sev[s.key as keyof typeof sev];
              return v > 0 ? <div key={s.key} title={`${s.label}: ${v}`} style={{ width: `${(v / sevTotal) * 100}%`, background: s.color }} /> : null;
            })}
          </div>
          <div className="grid grid-cols-4 gap-2 mt-3.5">
            {SEV_DEF.map((s) => (
              <div key={s.key} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: s.color }} />
                <div className="min-w-0">
                  <div className="text-[15px] font-black leading-none tabular-nums" style={{ color: "var(--heading)" }}>{sev[s.key as keyof typeof sev]}</div>
                  <div className="text-[10px] mt-0.5" style={{ color: "var(--muted)" }}>{s.label}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        {/* Review funnel */}
        <div className="md:col-span-2 md:pl-6 md:border-l" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center justify-between mb-2.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>Review progress</span>
            <span className="text-[12px] font-bold" style={{ color: pct === 100 ? "var(--accent-green)" : "var(--accent-blue)" }}>{pct}%</span>
          </div>
          <div className="flex flex-col gap-2.5">
            {funnel.map((f) => (
              <div key={f.label} className="flex items-center gap-2.5">
                <span className="text-[10px] w-14 flex-shrink-0" style={{ color: "var(--muted)" }}>{f.label}</span>
                <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "var(--surface2)" }}>
                  <div className="h-full rounded-full" style={{ width: `${total ? (f.value / total) * 100 : 0}%`, background: f.color }} />
                </div>
                <span className="text-[11px] font-bold tabular-nums w-6 text-right" style={{ color: "var(--heading)" }}>{f.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Section heading with optional count + right-aligned action link ───────────
export function SectionTitle({ title, count, action }: { title: string; count?: number; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2">
        <h2 className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>{title}</h2>
        {count !== undefined && <span className={management.count}>{count}</span>}
      </div>
      {action}
    </div>
  );
}

// ── Quick-action tile ─────────────────────────────────────────────────────────
export function ActionTile({ href, title, desc, accent, icon }: { href: string; title: string; desc: string; accent: string; icon: ReactNode }) {
  return (
    <Link
      href={href}
      className="group flex items-start gap-3 rounded-2xl px-5 py-4 transition-colors hover:border-[color:var(--border2)]"
      style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
    >
      <span className="grid place-items-center w-9 h-9 rounded-xl flex-shrink-0" style={{ background: `${accent}18`, color: accent, border: `1px solid ${accent}30` }}>
        {icon}
      </span>
      <span className="min-w-0">
        <span className="flex items-center gap-1.5 text-[13px] font-bold" style={{ color: "var(--heading)" }}>
          {title}
          <span aria-hidden="true" className="transition-transform group-hover:translate-x-0.5" style={{ color: accent }}>→</span>
        </span>
        <span className="block text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{desc}</span>
      </span>
    </Link>
  );
}

// ── Projects grid (navigates to the per-project scans page) ───────────────────
export function ProjectGrid({ projects }: { projects: Project[] }) {
  return (
    <div className={management.projectGrid}>
      {projects.map((project) => (
        <Link key={project.id} href={`/scans?project=${project.id}`} className={management.projectCard}>
          <span className={management.projectIcon}><ProjectIcon /></span>
          <div>
            <h3 className={management.projectTitle}>{project.name}</h3>
            <p className={management.projectDescription}>{project.description || "Container security workspace"}</p>
          </div>
          <span className={management.projectAction}>View scans <span aria-hidden="true">→</span></span>
        </Link>
      ))}
    </div>
  );
}

// ── RAG memory callout ────────────────────────────────────────────────────────
export function RagCallout({ decisions, rate }: { decisions: number; rate: number }) {
  return (
    <div className="rounded-2xl px-6 py-5 flex items-center gap-5" style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}>
      <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 text-[18px]" style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)", color: "var(--accent-purple)" }}>◈</div>
      <div className="flex-1">
        <p className="text-[13px] font-bold" style={{ color: "var(--accent-purple)" }}>RAG Memory Store — {decisions} decisions persisted</p>
        <p className="text-[12px] mt-0.5" style={{ color: "var(--subtle)" }}>
          Every approved rationale is stored and reused for future scans. Your team&apos;s security knowledge compounds over time — reducing synthesis time and improving first-pass approval rates.
        </p>
      </div>
      <div className="text-right flex-shrink-0">
        <div className="text-[22px] font-black" style={{ color: "var(--accent-purple)" }}>{rate}%</div>
        <div className="text-[11px]" style={{ color: "var(--muted)" }}>first-pass rate</div>
      </div>
    </div>
  );
}

// ── Empty / no-projects helper ────────────────────────────────────────────────
export function NoProjects({ canManage }: { canManage: boolean }) {
  return (
    <div className="rounded-2xl px-6 py-10 flex flex-col items-center text-center gap-3 ct-fade-up"
      style={{ background: "var(--surface)", border: "1px dashed var(--border2)", boxShadow: "var(--shadow-card)" }}>
      <span className="grid place-items-center w-12 h-12 rounded-2xl" style={{ background: "var(--accent-blue-bg)", color: "var(--accent-blue)", border: "1px solid var(--accent-blue-bdr)" }}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
        </svg>
      </span>
      <div>
        <p className="text-[14px] font-bold" style={{ color: "var(--heading)" }}>
          {canManage ? "Create your first project" : "No projects assigned yet"}
        </p>
        <p className="text-[12.5px] mt-1 max-w-sm mx-auto leading-relaxed" style={{ color: "var(--muted)" }}>
          {canManage
            ? "Projects group container scans and control who can review their findings. Create one to start scanning."
            : "Ask your administrator to assign you to a project, then your scans and reviews will appear here."}
        </p>
      </div>
      {canManage && (
        <Link href="/settings" className="mt-1 flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-bold transition-opacity hover:opacity-85"
          style={{ background: "var(--btn-accept-bg)", color: "var(--btn-accept-text)", boxShadow: "0 0 20px var(--btn-accept-glow)" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
          New project
        </Link>
      )}
    </div>
  );
}
