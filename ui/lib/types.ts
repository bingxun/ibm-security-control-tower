// ── Auth / RBAC ────────────────────────────────────────────────────────────

export type UserRole = "ADMIN" | "DEVOPS_ENGINEER" | "CYBER_MANAGER" | "DSO_MANAGER";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarInitials: string;
}

/** Fine-grained permissions derived from role */
export interface RolePermissions {
  canScan: boolean;       // start new scans
  canApprove: boolean;    // act on CVEs at all (submit, or accept/reject)
  canReject: boolean;     // can reject CVEs — distinguishes the approval
                           // workflow (Cyber Manager: accept + reject) from
                           // the submit-only workflow (everyone else who can act)
  canViewSettings: boolean; // access settings page
  canManageUsers: boolean;  // user management (admin only)
}

export const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  ADMIN:           { canScan: true,  canApprove: true, canReject: false, canViewSettings: true,  canManageUsers: true  },
  DEVOPS_ENGINEER: { canScan: true,  canApprove: true, canReject: false, canViewSettings: false, canManageUsers: false },
  CYBER_MANAGER:   { canScan: false, canApprove: true, canReject: true,  canViewSettings: true,  canManageUsers: false },
  // DSO_MANAGER shares the DevOps Engineer's scope/settings access — mirrors
  // DEVOPS_ENGINEER for canScan/canViewSettings/canManageUsers as a reasonable
  // default (not specified by the user); CVE-page workflow (canApprove/canReject)
  // is explicitly submit-only per the user's request, same as ADMIN/DEVOPS_ENGINEER.
  DSO_MANAGER:     { canScan: true,  canApprove: true, canReject: false, canViewSettings: false, canManageUsers: false },
};

export const ROLE_LABELS: Record<UserRole, string> = {
  ADMIN:           "Admin",
  DEVOPS_ENGINEER: "DevOps Engineer",
  CYBER_MANAGER:   "Cyber Manager",
  DSO_MANAGER:     "DSO Manager",
};

export const ROLE_COLORS: Record<UserRole, { bg: string; text: string; border: string }> = {
  ADMIN:           { bg: "rgba(124,92,216,0.12)", text: "#7c5cd8", border: "rgba(124,92,216,0.25)" },
  DEVOPS_ENGINEER: { bg: "rgba(68,147,248,0.12)", text: "#4493f8", border: "rgba(68,147,248,0.25)" },
  CYBER_MANAGER:   { bg: "rgba(34,197,94,0.12)",  text: "#22c55e", border: "rgba(34,197,94,0.25)"  },
  DSO_MANAGER:     { bg: "rgba(240,136,62,0.12)", text: "#f0883e", border: "rgba(240,136,62,0.25)" },
};

// ── Domain types ───────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";
export type CveStatus = "approved" | "rejected" | "pending" | "queued";

export interface CveRecord {
  id: string;
  severity: Severity;
  pkg: string;
  version: string;
  fixedIn: string;
  cvss: number;
  vector: string;
  authRequired: string;
  impact: string;
  description: string;
  rationale: string;
  remediation: string;
  manualNotes?: string;
  edited?: boolean;
  editedByRole?: string;
  ragMatch?: {
    pct: number;
    project: string;
    approver: string;
    date: string;
    summary: string;
  };
  status: CveStatus;
}

/**
 * A CVE id alone isn't always unique within a run — the same CVE can affect
 * multiple packages (e.g. musl + musl-utils share one advisory). Use this
 * composite key for list `key`s, selection state, and lookups instead of
 * `cve.id` alone, so two such entries are never conflated.
 */
export function cveKey(cve: Pick<CveRecord, "id" | "pkg">): string {
  return `${cve.id}::${cve.pkg}`;
}

export interface AgentStep {
  id: string;
  title: string;
  desc: string;
  chips: { label: string; variant: "rag" | "tool" | "llm" | "done" | "stream" }[];
  state: "done" | "active" | "waiting";
}

export interface RunStats {
  total: number;
  approved: number;
  rejected: number;
  avgSynthesisS: number;
  ragHits: number;
  tokensUsed: number;
}
