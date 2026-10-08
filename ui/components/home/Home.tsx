"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import ScansTable from "@/components/ScansTable";
import { useAuth } from "@/lib/auth";
import {
  listScans, getDashboardStats, listProjects, listUsers,
  type ScanSummary, type DashboardStats, type Project, type PlatformUser,
} from "@/lib/api";
import {
  HomeShell, Hero, PrimaryLink, SecondaryLink, PlusIcon, ReviewIcon,
  StatCard, StatGrid, SectionTitle, ActionTile, ProjectGrid, RagCallout, NoProjects, PostureCard,
  awaitingReview, inProgress, pending, needsMyAction, changesRequested,
} from "./HomeKit";

const ScanKpi   = <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="7" y1="12" x2="17" y2="12"/></svg>;
const ClockKpi  = <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>;
const BugKpi    = <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8 2l1.5 1.5M16 2l-1.5 1.5"/><rect x="8" y="6" width="8" height="12" rx="4"/><path d="M8 10H4M20 10h-4M8 14H4M20 14h-4M12 18v3"/></svg>;
const CheckKpi  = <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>;

const EMPTY: DashboardStats = { totalScans: 0, cvesTriaged: 0, avgApprovalRate: 0, ragDecisions: 0, ragFirstPassRate: 0 };

const UsersIcon = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>;
const ProjIcon = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /></svg>;
const GearIcon = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>;
const InfoIcon = <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></svg>;


export default function Home() {
  const { user, permissions } = useAuth();
  const p = permissions ?? { canScan: false, canApprove: false, canReject: false, canViewSettings: false, canManageProjects: false, canManageUsers: false };

  const [stats, setStats] = useState<DashboardStats>(EMPTY);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const base = Promise.all([getDashboardStats(), listScans(), listProjects()]);
    base
      .then(async ([d, s, pr]) => {
        if (cancelled) return;
        setStats(d); setScans(s); setProjects(pr);
        if (p.canManageUsers) {
          try { const u = await listUsers(); if (!cancelled) setUsers(u); } catch { /* non-fatal */ }
        }
      })
      .catch((e) => { if (!cancelled) setError(e.message ?? "Failed to reach backend"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [p.canManageUsers]);

  const review = awaitingReview(scans);
  const openFindings = review.reduce((n, s) => n + pending(s), 0);
  const running = inProgress(scans).length;
  const scanOnly = p.canScan && !p.canApprove;
  const actionScans = needsMyAction(scans);
  const actionFindings = actionScans.reduce((n, s) => n + changesRequested(s), 0);
  // Approval rate should read semantically — low is not "good" (green).
  const approvalColor = stats.avgApprovalRate >= 70 ? "var(--accent-green)"
    : stats.avgApprovalRate >= 40 ? "var(--accent-yellow)" : "var(--accent-red)";

  // Hero actions, composed from capabilities (union of all the user's roles).
  const actions = <>
    {p.canManageUsers && <SecondaryLink href="/settings" icon={UsersIcon}>Manage users</SecondaryLink>}
    {p.canApprove && !p.canScan && <PrimaryLink href="/review" icon={ReviewIcon}>Open review queue</PrimaryLink>}
    {p.canScan && <PrimaryLink href="/new-scan" icon={PlusIcon}>New scan</PrimaryLink>}
  </>;

  const heroTitle = p.canManageUsers ? "Security Control Tower"
    : scanOnly ? "Launch a container scan"
    : p.canApprove && !p.canScan ? "Review & Approvals"
    : "Operations Dashboard";
  const scopeNote = p.canManageUsers ? "Org-wide view across all projects and teams." : "Across your assigned projects.";

  return (
    <HomeShell>
      <Hero
        title={heroTitle}
        subtitle={<>Welcome back, <span style={{ color: "var(--heading)" }}>{user?.name}</span>. {scopeNote}</>}
        actions={actions}
      />

      {/* Core KPIs — always shown */}
      <StatGrid>
        {p.canApprove
          ? <StatCard value={String(review.length)} label="Awaiting review" sub={`${openFindings} open findings`} color="var(--accent-red)" icon={ReviewIcon} />
          : <StatCard value={String(stats.totalScans)} label="Total scans" sub="your projects" color="var(--accent-blue)" icon={ScanKpi} />}
        {scanOnly
          ? <StatCard value={String(running)} label="In progress" sub="currently scanning" color="var(--accent-yellow)" icon={ClockKpi} />
          : <StatCard value={String(stats.totalScans)} label="Total scans" sub="all projects" color="var(--accent-blue)" icon={ScanKpi} />}
        <StatCard value={String(stats.cvesTriaged)} label="CVEs triaged" sub="across scans" color="var(--accent-purple)" icon={BugKpi} />
        <StatCard value={`${stats.avgApprovalRate}%`} label="Avg. approval rate" sub="first-pass" color={approvalColor} icon={CheckKpi} />
      </StatGrid>

      {/* Security posture — severity distribution + review progress */}
      {scans.length > 0 && <PostureCard scans={scans} />}

      {/* Governance strip — only for user managers (super admins) */}
      {p.canManageUsers && (
        <StatGrid cols={3}>
          <StatCard value={String(projects.length)} label="Projects" sub="workspaces" color="var(--accent-blue)" />
          <StatCard value={`${users.filter(u => Boolean(u.is_active)).length}/${users.length}`} label="Active users" sub="of total accounts" color="var(--accent-orange)" />
          <StatCard value={String(review.length)} label="Awaiting review" sub="scans with open findings" color="var(--accent-red)" />
        </StatGrid>
      )}

      {/* Approval queue — only if the user can approve */}
      {p.canApprove && (
        <section className="space-y-4">
          <SectionTitle
            title="Awaiting your review"
            count={review.length}
            action={review.length > 0 ? <Link href="/review" className="text-xs font-semibold" style={{ color: "var(--accent-blue)" }}>Open review queue →</Link> : undefined}
          />
          <ScansTable
            scans={review} projects={projects} loading={loading} error={error}
            emptyTitle="You're all caught up" emptyBody="No scans are waiting on a decision right now."
          />
        </section>
      )}

      {/* Quick actions — each tile gated by capability */}
      <section className="space-y-4">
        <SectionTitle title="Quick actions" />
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          {p.canManageUsers && <ActionTile href="/settings" title="Manage users" desc="Create accounts and assign roles" accent="var(--accent-orange)" icon={UsersIcon} />}
          {p.canManageProjects && <ActionTile href="/settings" title="Manage projects" desc="Create projects and assign access" accent="var(--accent-blue)" icon={ProjIcon} />}
          {p.canScan && <ActionTile href="/new-scan" title="New scan" desc="Scan a container image for CVEs" accent="var(--accent-purple)" icon={PlusIcon} />}
          {p.canApprove && <ActionTile href="/review" title="Review queue" desc="Approve or reject pending findings" accent="var(--accent-green)" icon={ReviewIcon} />}
          {p.canViewSettings && <ActionTile href="/settings" title="Settings" desc="Profile and preferences" accent="var(--accent-blue)" icon={GearIcon} />}
        </div>
      </section>

      {/* Projects — always */}
      <section className="space-y-4">
        <SectionTitle title={p.canManageUsers ? "Workspace projects" : "Assigned projects"} count={projects.length} />
        {!loading && !error && projects.length === 0 ? <NoProjects canManage={p.canManageProjects} /> : <ProjectGrid projects={projects} />}
      </section>

      {/* DevOps: findings sent back for revision — actionable */}
      {scanOnly && actionScans.length > 0 && (
        <section className="space-y-4">
          <SectionTitle
            title="Needs my action"
            count={actionFindings}
            action={<Link href="/review" className="text-xs font-semibold" style={{ color: "var(--accent-yellow)" }}>Revise &amp; resubmit →</Link>}
          />
          <ScansTable
            scans={actionScans} projects={projects} loading={loading} error={error}
            emptyTitle="Nothing to revise" emptyBody="No findings have been sent back to you."
          />
        </section>
      )}

      {/* DevOps context note — scan-only users with nothing to revise */}
      {scanOnly && actionScans.length === 0 && (
        <div className="rounded-2xl px-6 py-4 flex items-center gap-4" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <span className="grid place-items-center w-9 h-9 rounded-xl flex-shrink-0" style={{ background: "var(--accent-blue-bg)", color: "var(--accent-blue)", border: "1px solid var(--border)" }}>{InfoIcon}</span>
          <p className="text-[12px]" style={{ color: "var(--subtle)" }}>
            You prepare and submit findings for approval. A <span style={{ color: "var(--heading)" }}>Cyber Manager</span> then approves or sends them back with requested changes — anything returned to you appears here as <span style={{ color: "var(--heading)" }}>Needs my action</span>.
          </p>
        </div>
      )}

      {/* RAG callout — reviewers & admins */}
      {(p.canApprove || p.canManageUsers) && <RagCallout decisions={stats.ragDecisions} rate={stats.ragFirstPassRate} />}
    </HomeShell>
  );
}
