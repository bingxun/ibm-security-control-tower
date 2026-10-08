"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import ThemeSwitcher from "./ThemeSwitcher";
import CommandPalette from "./CommandPalette";
import { useAuth } from "@/lib/auth";
import { ROLE_LABELS, ROLE_COLORS } from "@/lib/types";

interface Props {
  agentStatus?: "running" | "awaiting" | "done" | "error";
  projectId?: string;
  imageRef?: string;
}

export default function TopNav({ agentStatus, projectId, imageRef }: Props) {
  const path       = usePathname();
  const router     = useRouter();
  const { user, permissions, logout } = useAuth();

  const isReview    = path?.startsWith("/review");
  const isNewScan   = path?.startsWith("/new-scan");
  const isDashboard = path?.startsWith("/dashboard");
  const isSettings  = path?.startsWith("/settings");

  const handleLogout = () => {
    logout();
    router.replace("/login");
  };

  const roles = user?.roles ?? [];

  return (
    <nav
      className="h-14 flex items-center px-6 gap-4 flex-shrink-0"
      style={{
        background: "var(--bg-nav)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)" }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="white">
            <path d="M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm2 14H10v-1h4v1zm0-3H10v-1h4v1zm.5-5.07V10h-5V7.93C8.16 7.43 7 8.17 7 9c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.83-1.16-1.57-2.5-1.07z"/>
          </svg>
        </div>
        <div>
          <div className="text-[13px] font-bold leading-none" style={{ color: "var(--heading)" }}>
            Control Tower
          </div>
          <div className="text-[11px] leading-none mt-0.5" style={{ color: "var(--muted)" }}>
            Security Review
          </div>
        </div>
      </div>

      <div className="w-px h-6 mx-1" style={{ background: "var(--border)" }} />

      {/* Breadcrumb */}
      {isDashboard && (
        <span className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>Dashboard</span>
      )}
      {isNewScan && (
        <div className="flex items-center gap-2">
          <Link href="/dashboard" className="flex items-center gap-1.5 text-[12px] transition-opacity hover:opacity-70" style={{ color: "var(--muted)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="15 18 9 12 15 6"/></svg>
            Dashboard
          </Link>
          <span style={{ color: "var(--dim)" }}>/</span>
          <span className="text-[12px] font-semibold" style={{ color: "var(--heading)" }}>New Scan</span>
        </div>
      )}
      {isReview && (
        <div className="flex items-center gap-2 min-w-0">
          <Link href="/dashboard" className="flex items-center gap-1.5 text-[12px] transition-opacity hover:opacity-70 flex-shrink-0" style={{ color: "var(--muted)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="15 18 9 12 15 6"/></svg>
            Dashboard
          </Link>
          <span style={{ color: "var(--dim)" }}>/</span>
          <span className="text-[11px] font-mono px-2 py-1 rounded flex-shrink-0" style={{ background: "var(--surface2)", color: "var(--accent-blue)", border: "1px solid var(--border)" }}>
            {projectId || "—"}
          </span>
          {imageRef && (
            <>
              <span style={{ color: "var(--dim)" }}>/</span>
              <span className="text-[11px] font-mono truncate max-w-[180px]" style={{ color: "var(--muted)" }} title={imageRef}>
                {imageRef}
              </span>
            </>
          )}
          <span className="text-[12px] flex-shrink-0" style={{ color: "var(--muted)" }}>Review</span>
        </div>
      )}
      {isSettings && (
        <div className="flex items-center gap-2">
          <Link href="/dashboard" className="flex items-center gap-1.5 text-[12px] transition-opacity hover:opacity-70" style={{ color: "var(--muted)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="15 18 9 12 15 6"/></svg>
            Dashboard
          </Link>
          <span style={{ color: "var(--dim)" }}>/</span>
          <span className="text-[12px] font-semibold" style={{ color: "var(--heading)" }}>Settings</span>
        </div>
      )}

      <div className="flex-1" />

      {/* New scan CTA — only for users who can scan */}
      {(isReview || isDashboard) && permissions?.canScan && (
        <Link
          href="/new-scan"
          className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-80"
          style={{
            background: "var(--surface2)",
            border: "1px solid var(--border)",
            color: "var(--faint)",
          }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          New scan
        </Link>
      )}

      {/* Settings gear — only for users who can view settings */}
      {!isSettings && permissions?.canViewSettings && (
        <Link
          href="/settings"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-80"
          style={{
            background: "var(--surface2)",
            border: "1px solid var(--border)",
            color: "var(--faint)",
          }}
          title="Settings"
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
          </svg>
          Settings
        </Link>
      )}

      {/* Command palette (⌘K) — the floating assistant lives in the root layout
          so it persists across page navigation. */}
      <CommandPalette />

      {/* Theme switcher */}
      <ThemeSwitcher />

      {/* Agent status — only while a run actually reports one */}
      {agentStatus && (() => {
        const cfg = {
          running:  { bg: "var(--accent-purple-bg)", bdr: "var(--accent-purple-bdr)", color: "var(--accent-purple)",  dot: "var(--accent-purple)",  label: "Agent running",  pulse: true  },
          awaiting: { bg: "var(--accent-yellow-bg, rgba(210,153,34,0.08))", bdr: "rgba(210,153,34,0.2)", color: "var(--accent-yellow)", dot: "var(--accent-yellow)", label: "Awaiting review", pulse: false },
          done:     { bg: "var(--accent-green-bg)",  bdr: "var(--accent-green-bdr)",  color: "var(--accent-green)",   dot: "var(--accent-green)",   label: "Run complete",   pulse: false },
          error:    { bg: "var(--accent-red-bg)",    bdr: "var(--accent-red-bdr)",    color: "var(--accent-red)",     dot: "var(--accent-red)",     label: "Agent error",    pulse: false },
        }[agentStatus];
        return (
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[12px] font-medium"
            style={{ background: cfg.bg, border: `1px solid ${cfg.bdr}`, color: cfg.color }}
          >
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0${cfg.pulse ? " animate-pulse" : ""}`}
              style={{ background: cfg.dot, boxShadow: `0 0 6px ${cfg.dot}` }}
            />
            {cfg.label}
          </div>
        );
      })()}

      {/* User chip + logout */}
      {user && (
        <div className="flex items-center gap-2">
          {/* Role badges — one per role the user holds */}
          <span className="hidden sm:flex items-center gap-1">
            {roles.map((role) => {
              const c = ROLE_COLORS[role];
              return (
                <span
                  key={role}
                  className="text-[10px] font-bold px-2 py-1 rounded-full uppercase tracking-wide"
                  style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}` }}
                >
                  {ROLE_LABELS[role]}
                </span>
              );
            })}
          </span>

          {/* Name + avatar */}
          <div className="flex items-center gap-2">
            <div className="text-right hidden md:block">
              <div className="text-[12px] font-medium leading-none" style={{ color: "var(--body)" }}>{user.name}</div>
              <div className="text-[11px] leading-none mt-0.5" style={{ color: "var(--muted)" }}>{user.email}</div>
            </div>
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold text-white flex-shrink-0"
              style={{ background: "linear-gradient(135deg, #4493f8, #7c5cd8)" }}
            >
              {user.avatarInitials}
            </div>
          </div>

          {/* Logout */}
          <button
            onClick={handleLogout}
            title="Sign out"
            className="flex items-center justify-center w-8 h-8 rounded-lg transition-opacity hover:opacity-70"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--muted)" }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
          </button>
        </div>
      )}
    </nav>
  );
}
