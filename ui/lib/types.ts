// ── Auth / RBAC ────────────────────────────────────────────────────────────

export type UserRole = "SUPER_ADMIN" | "ADMIN" | "DEVOPS_ENGINEER" | "CYBER_MANAGER" | "DSO_MANAGER";

export interface User {
  id: string;
  name: string;
  email: string;
  roles: UserRole[];
  avatarInitials: string;
}

/** Fine-grained permissions derived from role */
export interface RolePermissions {
  canScan: boolean;       // start new scans
  canApprove: boolean;    // act on CVEs at all (submit, or accept/reject)
  canReject: boolean;     // reject CVEs — splits the full accept/reject workflow
                          // (Cyber Manager / Super Admin) from submit-only approvers
  canViewSettings: boolean; // access settings page
  canManageProjects: boolean;
  canManageUsers: boolean;  // user management (super admin only)
}

/** Combine several roles into a single permission set (logical OR per capability). */
export function permissionsForRoles(roles: UserRole[]): RolePermissions {
  return (roles ?? []).reduce<RolePermissions>((acc, role) => {
    const p = ROLE_PERMISSIONS[role] ?? ROLE_PERMISSIONS.DEVOPS_ENGINEER;
    return {
      canScan: acc.canScan || p.canScan,
      canApprove: acc.canApprove || p.canApprove,
      canReject: acc.canReject || p.canReject,
      canViewSettings: acc.canViewSettings || p.canViewSettings,
      canManageProjects: acc.canManageProjects || p.canManageProjects,
      canManageUsers: acc.canManageUsers || p.canManageUsers,
    };
  }, { canScan: false, canApprove: false, canReject: false, canViewSettings: false, canManageProjects: false, canManageUsers: false });
}

export const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  SUPER_ADMIN:     { canScan: true,  canApprove: true,  canReject: true,  canViewSettings: true,  canManageUsers: true,  canManageProjects: true  },
  ADMIN:           { canScan: true,  canApprove: true,  canReject: false, canViewSettings: true,  canManageUsers: false, canManageProjects: false },
  DEVOPS_ENGINEER: { canScan: true,  canApprove: false, canReject: false, canViewSettings: false, canManageUsers: false, canManageProjects: false },
  CYBER_MANAGER:   { canScan: false, canApprove: true,  canReject: true,  canViewSettings: true,  canManageUsers: false, canManageProjects: false },
  // DSO Manager is a reviewer-like approver: it can act on findings (submit) and
  // view settings, but not reject, scan, or administer users/projects.
  DSO_MANAGER:     { canScan: false, canApprove: true,  canReject: false, canViewSettings: true,  canManageUsers: false, canManageProjects: false },
};

export const ROLE_LABELS: Record<UserRole, string> = {
  SUPER_ADMIN:     "Super Admin",
  ADMIN:           "Admin",
  DEVOPS_ENGINEER: "DevOps Engineer",
  CYBER_MANAGER:   "Cyber Manager",
  DSO_MANAGER:     "DSO Manager",
};

export const ROLE_COLORS: Record<UserRole, { bg: string; text: string; border: string }> = {
  SUPER_ADMIN:     { bg: "rgba(240,136,62,0.12)", text: "var(--accent-orange)", border: "var(--border2)" },
  ADMIN:           { bg: "rgba(124,92,216,0.12)", text: "#7c5cd8", border: "rgba(124,92,216,0.25)" },
  DEVOPS_ENGINEER: { bg: "rgba(68,147,248,0.12)", text: "#4493f8", border: "rgba(68,147,248,0.25)" },
  CYBER_MANAGER:   { bg: "rgba(34,197,94,0.12)",  text: "#22c55e", border: "rgba(34,197,94,0.25)"  },
  DSO_MANAGER:     { bg: "rgba(45,212,191,0.12)", text: "#2dd4bf", border: "rgba(45,212,191,0.25)" },
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
