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
export function StatCard({ value, label, sub, color }: { value: string; label: string; sub: string; color: string }) {
  return (
    <div className="rounded-2xl px-5 py-4" style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "var(--shadow-card)" }}>
      <div className="text-[28px] font-black leading-none" style={{ color }}>{value}</div>
      <div className="text-[12px] font-semibold mt-1.5" style={{ color: "var(--heading)" }}>{label}</div>
      <div className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{sub}</div>
    </div>
  );
}

export function StatGrid({ children, cols = 4 }: { children: ReactNode; cols?: 3 | 4 }) {
  return <div className={`grid gap-4 ${cols === 3 ? "grid-cols-3" : "grid-cols-4"}`}>{children}</div>;
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
    <p className="text-sm" style={{ color: "var(--faint)" }}>
      {canManage ? "Create a project in Settings to get started." : "No projects assigned. Contact your super admin for access."}
    </p>
  );
}
