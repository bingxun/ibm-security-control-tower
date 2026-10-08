"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth, MOCK_USERS } from "@/lib/auth";
import { ROLE_LABELS, ROLE_COLORS, type UserRole } from "@/lib/types";

// ── Role hint cards shown below the form ──────────────────────────────────

const ROLE_HINTS: Array<{
  role: UserRole;
  email: string;
  password: string;
  description: string;
  can: string[];
  cannot: string[];
}> = [
  {
    role:        "DEVOPS_ENGINEER",
    email:       "bob@example.com",
    password:    "devops123",
    description: "Initiates container image scans and monitors pipeline progress.",
    can:         ["Start new scans", "View CVE findings", "Monitor pipeline"],
    cannot:      ["Approve / reject CVEs", "Access settings"],
  },
  {
    role:        "CYBER_MANAGER",
    email:       "carol@example.com",
    password:    "cyber123",
    description: "Reviews AI-generated rationales and makes approval decisions.",
    can:         ["Approve / reject CVEs", "Edit rationales", "View settings"],
    cannot:      ["Start new scans"],
  },
  {
    role:        "ADMIN",
    email:       "alice@example.com",
    password:    "admin123",
    description: "Full access — manages users, scans, and approvals.",
    can:         ["All scan actions", "All approval actions", "Settings & user management"],
    cannot:      [],
  },
];

// ── Sub-components ────────────────────────────────────────────────────────

function RoleCard({
  hint,
  onSelect,
}: {
  hint: (typeof ROLE_HINTS)[number];
  onSelect: (email: string, password: string) => void;
}) {
  const colors = ROLE_COLORS[hint.role];
  return (
    <button
      type="button"
      onClick={() => onSelect(hint.email, hint.password)}
      className="text-left w-full rounded-xl p-4 transition-all hover:scale-[1.01] active:scale-[0.99]"
      style={{
        background:   "var(--surface)",
        border:       `1px solid var(--border)`,
        cursor:       "pointer",
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <span
          className="text-[11px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wide"
          style={{ background: colors.bg, color: colors.text, border: `1px solid ${colors.border}` }}
        >
          {ROLE_LABELS[hint.role]}
        </span>
        <span className="text-[11px]" style={{ color: "var(--muted)" }}>
          {hint.email}
        </span>
      </div>
      <p className="text-[12px] mb-3" style={{ color: "var(--body)" }}>
        {hint.description}
      </p>
      <div className="flex gap-4">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wide mb-1" style={{ color: "var(--accent-green)" }}>
            Can do
          </div>
          <ul className="space-y-0.5">
            {hint.can.map((item) => (
              <li key={item} className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--subtle)" }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                {item}
              </li>
            ))}
          </ul>
        </div>
        {hint.cannot.length > 0 && (
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-wide mb-1" style={{ color: "var(--accent-red)" }}>
              Cannot
            </div>
            <ul className="space-y-0.5">
              {hint.cannot.map((item) => (
                <li key={item} className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--subtle)" }}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </button>
  );
}

// ── Login page ────────────────────────────────────────────────────────────

export default function LoginPage() {
  const router              = useRouter();
  const { login, user, isLoading } = useAuth();

  const [email, setEmail]     = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]     = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Already logged in → redirect
  useEffect(() => {
    if (!isLoading && user) {
      router.replace("/dashboard");
    }
  }, [user, isLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      router.replace("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  };

  const prefill = (em: string, pw: string) => {
    setEmail(em);
    setPassword(pw);
    setError(null);
  };

  if (isLoading) return null;

  return (
    <div
      className="min-h-screen flex items-center justify-center p-6"
      style={{ background: "var(--bg)" }}
    >
      <div className="w-full max-w-4xl flex gap-8 items-start">

        {/* ── Left: Login form ── */}
        <div
          className="flex-shrink-0 w-80 rounded-2xl p-8"
          style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
        >
          {/* Brand */}
          <div className="flex items-center gap-3 mb-8">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)" }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="white">
                <path d="M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm2 14H10v-1h4v1zm0-3H10v-1h4v1zm.5-5.07V10h-5V7.93C8.16 7.43 7 8.17 7 9c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.83-1.16-1.57-2.5-1.07z" />
              </svg>
            </div>
            <div>
              <div className="text-[15px] font-bold leading-none" style={{ color: "var(--heading)" }}>
                Control Tower
              </div>
              <div className="text-[12px] leading-none mt-1" style={{ color: "var(--muted)" }}>
                Security Review Platform
              </div>
            </div>
          </div>

          <h1 className="text-[20px] font-bold mb-1" style={{ color: "var(--heading)" }}>
            Sign in
          </h1>
          <p className="text-[13px] mb-6" style={{ color: "var(--muted)" }}>
            Use your role credentials to access the platform.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>
                Email
              </label>
              <input
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-3 py-2 rounded-lg text-[13px] outline-none transition-all"
                style={{
                  background: "var(--bg)",
                  border:     "1px solid var(--border)",
                  color:      "var(--body)",
                }}
                onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
                onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-3 py-2 pr-10 rounded-lg text-[13px] outline-none transition-all"
                  style={{
                    background: "var(--bg)",
                    border:     "1px solid var(--border)",
                    color:      "var(--body)",
                  }}
                  onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
                  onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                  tabIndex={-1}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-[12px]"
                style={{ background: "var(--accent-red-bg)", border: "1px solid var(--accent-red-bdr)", color: "var(--accent-red)" }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 rounded-lg text-[13px] font-semibold transition-opacity disabled:opacity-60"
              style={{
                background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)",
                color:      "white",
                cursor:     submitting ? "not-allowed" : "pointer",
              }}
            >
              {submitting ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                  </svg>
                  Signing in…
                </span>
              ) : "Sign in"}
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-3 my-5">
            <div className="flex-1 h-px" style={{ background: "var(--border)" }} />
            <span className="text-[11px]" style={{ color: "var(--dim)" }}>or quick-select a role</span>
            <div className="flex-1 h-px" style={{ background: "var(--border)" }} />
          </div>

          {/* Quick-select buttons */}
          <div className="space-y-2">
            {ROLE_HINTS.map((hint) => {
              const colors = ROLE_COLORS[hint.role];
              return (
                <button
                  key={hint.role}
                  type="button"
                  onClick={() => prefill(hint.email, hint.password)}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-[12px] transition-opacity hover:opacity-80 text-left"
                  style={{ background: colors.bg, border: `1px solid ${colors.border}`, color: colors.text }}
                >
                  <span className="font-bold">{ROLE_LABELS[hint.role]}</span>
                  <span className="font-mono opacity-70 flex-1">{hint.email}</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <polyline points="9 18 15 12 9 6"/>
                  </svg>
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Right: Role information cards ── */}
        <div className="flex-1 space-y-4">
          <div>
            <h2 className="text-[16px] font-bold mb-1" style={{ color: "var(--heading)" }}>
              Role-based access
            </h2>
            <p className="text-[13px]" style={{ color: "var(--muted)" }}>
              Each role has specific permissions. Click a card to pre-fill credentials.
            </p>
          </div>
          {ROLE_HINTS.map((hint) => (
            <RoleCard key={hint.role} hint={hint} onSelect={prefill} />
          ))}
        </div>
      </div>
    </div>
  );
}
