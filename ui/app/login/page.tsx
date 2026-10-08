"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import styles from "./page.module.css";

// Pause decorative updates when requested, when hidden, or for reduced motion.
function startAnimation(tick: () => void, delay: number, paused: boolean) {
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let timer: ReturnType<typeof setInterval> | undefined;
  const sync = () => {
    clearInterval(timer);
    if (!paused && !motion.matches && !document.hidden) timer = setInterval(tick, delay);
  };
  sync();
  motion.addEventListener("change", sync);
  document.addEventListener("visibilitychange", sync);
  return () => {
    clearInterval(timer);
    motion.removeEventListener("change", sync);
    document.removeEventListener("visibilitychange", sync);
  };
}

// ── Animated pipeline ────────────────────────────────────────────────────────

const PIPELINE_STAGES = [
  {
    label: "Image Scan",
    sublabel: "Multi-scanner",
    icon: (color: string) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round">
        <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
        <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
        <rect x="7" y="7" width="10" height="10" rx="1.5"/>
      </svg>
    ),
    accentVar: "--accent-blue",
  },
  {
    label: "AI Synthesis",
    sublabel: "Claude Sonnet",
    icon: (color: string) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round">
        <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3.14Z"/>
        <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3.14Z"/>
      </svg>
    ),
    accentVar: "--accent-purple",
  },
  {
    label: "Human Gate",
    sublabel: "Approval queue",
    icon: (color: string) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
    ),
    accentVar: "--accent-orange",
  },
  {
    label: "RAG Memory",
    sublabel: "Decision store",
    icon: (color: string) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"/>
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
      </svg>
    ),
    accentVar: "--accent-green",
  },
];

function PipelineViz({ paused }: { paused: boolean }) {
  const [activeIdx, setActiveIdx] = useState(0);

  useEffect(() => {
    return startAnimation(() => setActiveIdx((i) => (i + 1) % PIPELINE_STAGES.length), 1600, paused);
  }, [paused]);

  return (
    <div className="grid grid-cols-4 gap-3">
      {PIPELINE_STAGES.map((s, i) => {
        const isActive  = i === activeIdx;
        const isDone    = i < activeIdx;
        const color     = `var(${s.accentVar})`;
        return (
          <div
            key={s.label}
            className="flex flex-col items-center gap-2 p-3 rounded-xl transition-all duration-500"
            style={{
              background: isActive ? `color-mix(in srgb, ${color} 10%, transparent)` : "var(--surface3, var(--bg))",
              border:     `1px solid ${isActive ? color : isDone ? "var(--accent-green-bdr)" : "var(--border)"}`,
              opacity:    isDone ? 0.7 : 1,
            }}
          >
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center"
              style={{ background: `color-mix(in srgb, ${color} 12%, transparent)` }}
            >
              {isDone
                ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" strokeWidth="2.5" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
                : s.icon(color)
              }
            </div>
            <div className="text-center">
              <div className="text-[10px] font-bold leading-none" style={{ color: isActive ? color : "var(--body)" }}>{s.label}</div>
              <div className="text-[9px] mt-0.5" style={{ color: "var(--faint)" }}>{s.sublabel}</div>
            </div>
            <div aria-hidden="true" className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: color, visibility: isActive ? "visible" : "hidden" }} />
          </div>
        );
      })}
    </div>
  );
}

// ── CVE ticker ───────────────────────────────────────────────────────────────

const SAMPLE_CVES = [
  { id: "CVE-2023-38545", sev: "CRITICAL", pkg: "curl 7.74.0",      cvss: 9.8 },
  { id: "CVE-2022-37434", sev: "CRITICAL", pkg: "zlib 1.2.12-r0",   cvss: 9.8 },
  { id: "CVE-2023-29491", sev: "HIGH",     pkg: "ncurses 6.2",       cvss: 7.8 },
  { id: "CVE-2022-1304",  sev: "HIGH",     pkg: "e2fsprogs 1.46.2",  cvss: 7.8 },
  { id: "CVE-2023-4911",  sev: "HIGH",     pkg: "glibc 2.31",        cvss: 7.8 },
  { id: "CVE-2023-0286",  sev: "HIGH",     pkg: "openssl 1.1.1n",    cvss: 7.4 },
];

const SEV_STYLE: Record<string, { bg: string; color: string; border: string }> = {
  CRITICAL: { bg: "var(--accent-red-bg)",                  color: "var(--accent-red)",    border: "var(--accent-red-bdr)" },
  HIGH:     { bg: "rgba(240,136,62,0.1)",                  color: "var(--accent-orange)", border: "rgba(240,136,62,0.3)" },
};

function CveTicker({ paused }: { paused: boolean }) {
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    return startAnimation(() => setIdx((i) => (i + 1) % SAMPLE_CVES.length), 2000, paused);
  }, [paused]);

  const rows = [
    SAMPLE_CVES[(idx + SAMPLE_CVES.length - 1) % SAMPLE_CVES.length],
    SAMPLE_CVES[idx],
    SAMPLE_CVES[(idx + 1) % SAMPLE_CVES.length],
  ];

  return (
    <div className="space-y-1.5">
      {rows.map((cve, i) => {
        const sty = SEV_STYLE[cve.sev];
        const isFocus = i === 1;
        return (
          <div
            key={cve.id + i}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg"
            style={{
              background: isFocus ? "var(--surface2)" : "transparent",
              border:     `1px solid ${isFocus ? "var(--border)" : "transparent"}`,
              opacity:    i === 0 ? 0.4 : i === 2 ? 0.6 : 1,
              transition: "opacity 0.5s ease",
            }}
          >
            <span
              className="text-[9px] font-black px-1.5 py-0.5 rounded-md uppercase tracking-wide flex-shrink-0 w-14 text-center"
              style={{ background: sty.bg, color: sty.color, border: `1px solid ${sty.border}` }}
            >
              {cve.sev}
            </span>
            <span className="text-[11px] font-mono flex-1 truncate" style={{ color: "var(--heading)" }}>
              {cve.id}
            </span>
            <span className="text-[10px] font-mono hidden xl:block" style={{ color: "var(--faint)" }}>
              {cve.pkg}
            </span>
            <span
              className="text-[11px] font-black flex-shrink-0 tabular-nums"
              style={{ color: sty.color }}
            >
              {cve.cvss}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Login page ────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const router                     = useRouter();
  const { login, user, isLoading } = useAuth();

  const [email, setEmail]               = useState("");
  const [password, setPassword]         = useState("");
  const [error, setError]               = useState<string | null>(null);
  const [submitting, setSubmitting]     = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const [paused, setPaused] = useState(false);
  const errorRef = useRef<HTMLDivElement>(null);
  const pendingRef = useRef(false);

  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  useEffect(() => {
    if (!isLoading && user) router.replace("/dashboard");
  }, [user, isLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (pendingRef.current) return;
    pendingRef.current = true;
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      router.replace("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
      pendingRef.current = false;
      setSubmitting(false);
    }
  };

  if (isLoading || user) return <main className={styles.loading} role="status">{user ? "Opening your workspace…" : "Checking your session…"}</main>;

  return (
    <main className={styles.page} data-paused={paused}>
    <div className="min-h-full flex">

      {/* ═══════════════════════════════════════
          LEFT — Product showcase
      ═══════════════════════════════════════ */}
      <div
        className="hidden lg:flex flex-col items-center justify-between gap-8 flex-1 min-w-0 p-8 xl:p-10 relative overflow-hidden"
        style={{ background: "var(--surface)", borderRight: "1px solid var(--border)" }}
      >
        {/* Background grid */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ opacity: 0.03 }}>
          <defs>
            <pattern id="login-grid" width="48" height="48" patternUnits="userSpaceOnUse">
              <path d="M 48 0 L 0 0 0 48" fill="none" stroke="var(--accent-blue)" strokeWidth="0.5"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#login-grid)" />
        </svg>
        {/* Glow blobs */}
        <div className="absolute -top-24 -left-24 w-96 h-96 rounded-full pointer-events-none"
          style={{ background: "radial-gradient(circle, var(--accent-blue-bg) 0%, transparent 65%)" }} />
        <div className="absolute -bottom-24 -right-24 w-96 h-96 rounded-full pointer-events-none"
          style={{ background: "radial-gradient(circle, var(--accent-purple-bg) 0%, transparent 65%)" }} />

        {/* ── Brand ── */}
        <div className="relative z-10 flex items-center gap-3 w-full max-w-lg">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)" }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="white">
              <path d="M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm2 14H10v-1h4v1zm0-3H10v-1h4v1zm.5-5.07V10h-5V7.93C8.16 7.43 7 8.17 7 9c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.83-1.16-1.57-2.5-1.07z"/>
            </svg>
          </div>
          <div>
            <div className="text-[15px] font-bold leading-none" style={{ color: "var(--heading)" }}>Control Tower</div>
            <div className="text-[11px] leading-none mt-0.5" style={{ color: "var(--faint)" }}>Agentic Cloud Security</div>
          </div>
        </div>

        {/* ── Hero ── */}
        <div className="relative z-10 space-y-6 max-w-lg">
          {/* Badge */}
          <div>
            <div
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[11px] font-semibold mb-5"
              style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)", color: "var(--accent-purple)" }}
            >
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-purple)" }} />
              Powered by IBM RAD · Claude Sonnet 4.6
            </div>

            {/* Headline */}
            <h1 className="text-[38px] font-black leading-[1.1] tracking-tight" style={{ color: "var(--heading)" }}>
              Container security,<br />
              <span style={{
                background: "linear-gradient(90deg, #f97316 0%, var(--accent-purple) 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}>
                AI-powered.
              </span>
            </h1>

            <p className="text-[14px] mt-4 leading-relaxed" style={{ color: "var(--faint)" }}>
              Scan any container image, get AI-synthesised CVE rationales,
              and route every finding through your team&apos;s approval gate — in minutes.
            </p>
          </div>

          {/* Pipeline card */}
          <div
            className="rounded-2xl p-5"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: "var(--faint)" }}>
                Agent pipeline
              </span>
              <div className="flex items-center gap-2">
                <button type="button" className={styles.motionToggle} aria-pressed={paused} onClick={() => setPaused((value) => !value)}>
                  {paused ? "Resume animation" : "Pause animation"}
                </button>
              <span
                className="flex items-center gap-1.5 text-[10px] font-semibold px-2 py-1 rounded-full"
                style={{ background: "var(--accent-green-bg)", color: "var(--accent-green)", border: "1px solid var(--accent-green-bdr)" }}
              >
                <span className="w-1 h-1 rounded-full animate-pulse" style={{ background: "var(--accent-green)" }} />
                Demo
              </span>
              </div>
            </div>
            <PipelineViz paused={paused} />
          </div>

          {/* CVE feed card */}
          <div
            className="rounded-2xl p-5"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: "var(--faint)" }}>
                Recent findings
              </span>
              <span className="text-[10px] font-mono" style={{ color: "var(--faint)" }}>nginx:1.21.6</span>
            </div>
            <CveTicker paused={paused} />

            {/* Stats row */}
            <div
              className="flex gap-0 mt-4 rounded-xl overflow-hidden"
              style={{ border: "1px solid var(--border)" }}
            >
              {[
                { value: "874",   label: "CVEs found",      color: "var(--accent-blue)"   },
                { value: "~2.5m", label: "Time to triage",  color: "var(--accent-purple)" },
                { value: "94%",   label: "AI accuracy",     color: "var(--accent-green)"  },
              ].map((s, i) => (
                <div
                  key={s.label}
                  className="flex-1 flex flex-col items-center py-3"
                  style={{
                    background: "var(--surface3, var(--bg))",
                    borderRight: i < 2 ? "1px solid var(--border)" : "none",
                  }}
                >
                  <span className="text-[16px] font-black tabular-nums" style={{ color: s.color }}>{s.value}</span>
                  <span className="text-[9px] uppercase tracking-wide mt-0.5" style={{ color: "var(--faint)" }}>{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Footer ── */}
        <div className="relative z-10 flex items-center gap-3 w-full max-w-lg">
          <span className="text-[11px]" style={{ color: "var(--faint)" }}>IBM Hackathon · Team Fire</span>
          <span style={{ color: "var(--border)" }}>·</span>
          <span className="text-[11px]" style={{ color: "var(--faint)" }}>Enterprise-grade agentic security</span>
        </div>
      </div>

      {/* ═══════════════════════════════════════
          RIGHT — Login form
      ═══════════════════════════════════════ */}
      <div
        className="flex flex-col justify-center w-full lg:w-[44%] lg:max-w-[600px] lg:flex-shrink-0 p-6 sm:p-8 lg:p-12"
        style={{ background: "var(--bg)" }}
      >
        {/* Mobile brand */}
        <div className="flex items-center gap-3 mb-10 lg:hidden w-full max-w-sm mx-auto">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{ background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)" }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="white">
              <path d="M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm2 14H10v-1h4v1zm0-3H10v-1h4v1zm.5-5.07V10h-5V7.93C8.16 7.43 7 8.17 7 9c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.83-1.16-1.57-2.5-1.07z"/>
            </svg>
          </div>
          <div className="text-[15px] font-bold" style={{ color: "var(--heading)" }}>Control Tower</div>
        </div>

        <div className="w-full max-w-sm mx-auto">

          {/* Heading */}
          <div className="mb-8">
            <h2 className="text-[28px] font-black tracking-tight" style={{ color: "var(--heading)" }}>
              Welcome back
            </h2>
            <p className="text-[13px] mt-1.5" style={{ color: "var(--faint)" }}>
              Sign in to your security workspace.
            </p>
          </div>

          <form onSubmit={handleSubmit} className={`${styles.form} space-y-5`} aria-busy={submitting}>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-[13px] font-semibold mb-2" style={{ color: "var(--body)" }}>
                Email
              </label>
              <input
                id="email"
                name="email"
                autoCapitalize="none"
                spellCheck={false}
                readOnly={submitting}
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-4 py-3 rounded-xl text-[16px] outline-none"
                style={{
                  background: "var(--surface)",
                  border:     "1px solid var(--border)",
                  color:      "var(--body)",
                  transition: "border-color 0.15s, box-shadow 0.15s",
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = "var(--accent-blue)";
                  e.target.style.boxShadow   = "0 0 0 3px var(--accent-blue-bg)";
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = "var(--border)";
                  e.target.style.boxShadow   = "none";
                }}
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-[13px] font-semibold mb-2" style={{ color: "var(--body)" }}>
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  readOnly={submitting}
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-4 py-3 pr-11 rounded-xl text-[16px] outline-none"
                  style={{
                    background: "var(--surface)",
                    border:     "1px solid var(--border)",
                    color:      "var(--body)",
                    transition: "border-color 0.15s, box-shadow 0.15s",
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = "var(--accent-blue)";
                    e.target.style.boxShadow   = "0 0 0 3px var(--accent-blue-bg)";
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = "var(--border)";
                    e.target.style.boxShadow   = "none";
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className={styles.reveal}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-controls="password"
                >
                  {showPassword ? (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--body)" }}>
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                      <line x1="1" y1="1" x2="23" y2="23"/>
                    </svg>
                  ) : (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--body)" }}>
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div
                ref={errorRef}
                role="alert"
                tabIndex={-1}
                className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-[13px] break-words"
                style={{ background: "var(--accent-red-bg)", border: "1px solid var(--accent-red-bdr)", color: "var(--accent-red)" }}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                {error}
              </div>
            )}

            {/* Submit */}
            <div className="pt-1">
              <button
                type="submit"
                disabled={submitting}
                className={`${styles.submit} w-full py-3.5 rounded-xl text-[14px] font-bold disabled:opacity-60`}
                style={{
                  background: "linear-gradient(135deg, #c2410c 0%, #b91c1c 100%)",
                  color:      "white",
                  cursor:     submitting ? "not-allowed" : "pointer",
                  boxShadow:  submitting ? "none" : "0 4px 24px rgba(249,115,22,0.3)",
                  transition: "box-shadow 0.2s, opacity 0.15s",
                }}
              >
                {submitting ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
                      <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                    </svg>
                    Authenticating…
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    Sign in
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round">
                      <line x1="5" y1="12" x2="19" y2="12"/>
                      <polyline points="12 5 19 12 12 19"/>
                    </svg>
                  </span>
                )}
              </button>
            </div>
            <span className="sr-only" role="status">{submitting ? "Signing in. Please wait." : ""}</span>
          </form>

          {/* Trust signals */}
          <div className="mt-8 pt-6" style={{ borderTop: "1px solid var(--border)" }}>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <div className="flex items-center gap-1.5">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--faint)" }}>
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <span className="text-[11px]" style={{ color: "var(--faint)" }}>Encrypted</span>
              </div>
              <div className="w-px h-3" style={{ background: "var(--border)" }} />
              <div className="flex items-center gap-1.5">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--faint)" }}>
                  <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                </svg>
                <span className="text-[11px]" style={{ color: "var(--faint)" }}>24h session</span>
              </div>
              <div className="w-px h-3" style={{ background: "var(--border)" }} />
              <div className="flex items-center gap-1.5">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--faint)" }}>
                  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
                  <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
                <span className="text-[11px]" style={{ color: "var(--faint)" }}>Role-based</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </main>
  );
}
