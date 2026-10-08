"use client";

/**
 * RequireAuth — client-side route guard.
 *
 * Wraps any page that needs authentication. Optionally accepts a
 * `permission` key to enforce role-based access (e.g. only DEVOPS_ENGINEER
 * and ADMIN can reach /new-scan).
 *
 * Usage:
 *   <RequireAuth permission="canScan">
 *     <NewScanPage />
 *   </RequireAuth>
 */

import { useEffect, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import type { RolePermissions } from "@/lib/types";
import { ROLE_LABELS, ROLE_COLORS } from "@/lib/types";

interface Props {
  children: ReactNode;
  /** If set, user must have this permission or they see a 403 screen. */
  permission?: keyof RolePermissions;
}

export default function RequireAuth({ children, permission }: Props) {
  const router                       = useRouter();
  const { user, permissions, isLoading } = useAuth();

  useEffect(() => {
    if (!isLoading && !user) {
      router.replace("/login");
    }
  }, [user, isLoading, router]);

  // Still checking session
  if (isLoading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ background: "var(--bg)" }}
      >
        <div className="flex flex-col items-center gap-3">
          <svg className="animate-spin" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ color: "var(--muted)" }}>
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <span className="text-[13px]" style={{ color: "var(--muted)" }}>Loading…</span>
        </div>
      </div>
    );
  }

  // Not authenticated
  if (!user) return null;

  // Authenticated but lacks required permission
  if (permission && permissions && !permissions[permission]) {
    const colors = ROLE_COLORS[user.role];
    return (
      <div
        className="min-h-screen flex items-center justify-center p-6"
        style={{ background: "var(--bg)" }}
      >
        <div
          className="max-w-md w-full rounded-2xl p-8 text-center"
          style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
        >
          {/* Lock icon */}
          <div
            className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-5"
            style={{ background: "var(--accent-red-bg)", border: "1px solid var(--accent-red-bdr)" }}
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--accent-red)" }}>
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>

          <h1 className="text-[18px] font-bold mb-2" style={{ color: "var(--heading)" }}>
            Access restricted
          </h1>
          <p className="text-[13px] mb-5" style={{ color: "var(--muted)" }}>
            Your current role does not have permission to access this page.
          </p>

          {/* Current role badge */}
          <div className="flex items-center justify-center gap-2 mb-6">
            <span className="text-[12px]" style={{ color: "var(--muted)" }}>Signed in as:</span>
            <span
              className="text-[11px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wide"
              style={{ background: colors.bg, color: colors.text, border: `1px solid ${colors.border}` }}
            >
              {ROLE_LABELS[user.role]}
            </span>
          </div>

          <button
            onClick={() => router.back()}
            className="px-5 py-2 rounded-lg text-[13px] font-semibold transition-opacity hover:opacity-80"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
          >
            Go back
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
