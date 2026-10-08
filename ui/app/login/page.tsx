"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";

// ── Pipeline diagram ────────────────────────────────────────────────────────

function PipelineViz() {
  const stages = [
    { label: "Image Scan",   icon: "scan",   color: "var(--accent-blue)"   },
    { label: "AI Synthesis", icon: "brain",  color: "var(--accent-purple)" },
    { label: "Human Review", icon: "shield", color: "#f97316"              },
    { label: "Persist",      icon: "db",     color: "var(--accent-green)"  },
  ];

  return (
    <div className="flex items-center w-full max-w-sm mx-auto">
      {stages.map((s, i) => (
        <div key={s.label} className="flex items-center flex-1 min-w-0">
          <div className="flex flex-col items-center gap-1.5 flex-shrink-0">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center"
              style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
            >
              {s.icon === "scan" && (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.8" strokeLinecap="round">
                  <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
                  <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
                  <rect x="7" y="7" width="10" height="10" rx="1"/>
                </svg>
              )}
              {s.icon === "brain" && (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.8" strokeLinecap="round">
                  <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3.14Z"/>
                  <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3.14Z"/>
                </svg>
              )}
              {s.icon === "shield" && (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.8" strokeLinecap="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <polyline points="9 12 11 14 15 10"/>
                </svg>
              )}
              {s.icon === "db" && (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.8" strokeLinecap="round">
                  <ellipse cx="12" cy="5" rx="9" ry="3"/>
                  <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                  <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                </svg>
              )}
            </div>
            <span className="text-[9px] font-semibold text-center leading-tight" style={{ color: s.color, maxWidth: 52 }}>
              {s.label}
            </span>
          </div>
          {i < stages.length - 1 && (
            <div className="flex-1 flex items-center px-1 pb-4">
              <div className="w-full h-px" style={{ background: "var(--border)" }} />
              <svg width="5" height="5" viewBox="0 0 6 6" className="flex-shrink-0 -ml-0.5" style={{ color: "var(--muted)" }}>
                <polyline points="1,1 5,3 1,5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── CVE ticker ──────────────────────────────────────────────────────────────

const SAMPLE_CVES = [
  { id: "CVE-2023-38545", sev: "CRITICAL", pkg: "curl 7.74.0",      cvss: "9.8", color: "var(--accent-red)"    },
  { id: "CVE-2022-37434", sev: "CRITICAL", pkg: "zlib 1.2.12-r0",   cvss: "9.8", color: "var(--accent-red)"    },
  { id: "CVE-2023-29491", sev: "HIGH",     pkg: "ncurses 6.2",       cvss: "7.8", color: "var(--accent-orange)" },
  { id: "CVE-2022-1304",  sev: "HIGH",     pkg: "e2fsprogs 1.46.2",  cvss: "7.8", color: "var(--accent-orange)" },
  { id: "CVE-2023-4911",  sev: "HIGH",     pkg: "glibc 2.31",        cvss: "7.8", color: "var(--accent-orange)" },
  { id: "CVE-2023-0286",  sev: "HIGH",     pkg: "openssl 1.1.1n",    cvss: "7.4", color: "var(--accent-orange)" },
];

function CveTicker() {
  const [visible, setVisible] = useState([0, 1, 2]);

  useEffect(() => {
    const id = setInterval(() => {
      setVisible((prev) => {
        const next = prev[prev.length - 1] + 1;
        return [...prev.slice(1), next % SAMPLE_CVES.length];
      });
    }, 1800);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="w-full space-y-1.5 overflow-hidden" style={{ height: 92 }}>
      {visible.map((idx, i) => {
        const cve = SAMPLE_CVES[idx % SAMPLE_CVES.length];
        return (
          <div
            key={`${idx}-${i}`}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg"
            style={{
              background: "var(--surface2)",
              border:     "1px solid var(--border)",
              opacity:    i === 0 ? 0.45 : i === 1 ? 0.75 : 1,
              transition: "opacity 0.6s ease",
            }}
          >
            <span
              className="text-[9px] font-black px-1.5 py-0.5 rounded uppercase tracking-wide flex-shrink-0"
              style={{ background: "var(--accent-red-bg)", color: cve.color, border: "1px solid var(--accent-red-bdr)" }}
            >
              {cve.sev}
            </span>
            <span className="text-[11px] font-mono flex-1 truncate" style={{ color: "var(--heading)" }}>
              {cve.id}
            </span>
            <span className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
              {cve.pkg}
            </span>
            <span className="text-[10px] font-bold flex-shrink-0" style={{ color: cve.color }}>
              {cve.cvss}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Stats strip ─────────────────────────────────────────────────────────────

function StatStrip() {
  const stats = [
    { value: "874",   label: "CVEs scanned",  color: "var(--accent-blue)"   },
    { value: "~2.5m", label: "Synthesis time", color: "var(--accent-purple)" },
    { value: "94%",   label: "AI accuracy",   color: "var(--accent-green)"  },
  ];
  return (
    <div className="flex gap-4">
      {stats.map((s) => (
        <div key={s.label} className="flex-1 text-center">
          <div className="text-[18px] font-black" style={{ color: s.color }}>{s.value}</div>
          <div className="text-[10px] uppercase tracking-wide mt-0.5" style={{ color: "var(--muted)" }}>{s.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Login page ───────────────────────────────────────────────────────────────

export default function LoginPage() {
  const router                     = useRouter();
  const { login, user, isLoading } = useAuth();

  const [email, setEmail]               = useState("");
  const [password, setPassword]         = useState("");
  const [error, setError]               = useState<string | null>(null);
  const [submitting, setSubmitting]     = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    if (!isLoading && user) router.replace("/dashboard");
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

  if (isLoading) return null;

  return (
    <div className="min-h-screen flex" style={{ background: "var(--bg)", overflow: "hidden" }}>

      {/* ══════════════ LEFT — Product showcase ══════════════ */}
      <div
        className="hidden lg:flex flex-col justify-between flex-1 p-10 relative overflow-hidden"
        style={{ background: "var(--surface)", borderRight: "1px solid var(--border)" }}
      >
        {/* Subtle grid */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ opacity: 0.025 }}>
          <defs>
            <pattern id="login-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--accent-blue)" strokeWidth="0.5"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#login-grid)" />
        </svg>

        {/* Glow blobs — respect theme via opacity */}
        <div className="absolute top-16 left-8 w-72 h-72 rounded-full pointer-events-none"
          style={{ background: "radial-gradient(circle, var(--accent-blue-bg) 0%, transparent 70%)" }} />
        <div className="absolute bottom-16 right-8 w-80 h-80 rounded-full pointer-events-none"
          style={{ background: "radial-gradient(circle, var(--accent-purple-bg) 0%, transparent 70%)" }} />

        {/* Brand */}
        <div className="relative z-10 flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)" }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="white">
              <path d="M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm2 14H10v-1h4v1zm0-3H10v-1h4v1zm.5-5.07V10h-5V7.93C8.16 7.43 7 8.17 7 9c0 2.76 2.24 5 5 5s5-2.24 5-5c0-.83-1.16-1.57-2.5-1.07z"/>
            </svg>
          </div>
          <div>
            <div className="text-[14px] font-bold leading-none" style={{ color: "var(--heading)" }}>Control Tower</div>
            <div className="text-[11px] leading-none mt-0.5" style={{ color: "var(--muted)" }}>Agentic Cloud Security</div>
          </div>
        </div>

        {/* Hero + widgets */}
        <div className="relative z-10 space-y-7">
          {/* AI pill */}
          <div>
            <div
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[11px] font-semibold mb-4"
              style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)", color: "var(--accent-purple)" }}
            >
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-purple)" }} />
              Powered by IBM RAD · Claude Sonnet 4.6
            </div>
            <h1 className="text-[30px] font-black leading-[1.15] tracking-tight" style={{ color: "var(--heading)" }}>
              Container security<br />
              <span style={{ background: "linear-gradient(90deg, #f97316, var(--accent-purple))", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                at the speed of AI
              </span>
            </h1>
            <p className="text-[13px] mt-3 leading-relaxed max-w-sm" style={{ color: "var(--subtle)" }}>
              Scan container images, synthesise CVE rationales with a large language model, and route findings through a human approval gate — all in one pipeline.
            </p>
          </div>

          {/* Pipeline */}
          <div
            className="rounded-2xl p-4"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
          >
            <div className="text-[10px] font-semibold uppercase tracking-widest mb-4" style={{ color: "var(--muted)" }}>
              Agent pipeline
            </div>
            <PipelineViz />
          </div>

          {/* Live CVE feed */}
          <div
            className="rounded-2xl p-4"
            style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: "var(--muted)" }}>
                Live findings
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--accent-green)" }} />
                <span className="text-[10px]" style={{ color: "var(--accent-green)" }}>nginx:1.21.6</span>
              </div>
            </div>
            <CveTicker />
          </div>

          <StatStrip />
        </div>

        {/* Footer */}
        <div className="relative z-10">
          <span className="text-[11px]" style={{ color: "var(--dim)" }}>Built for IBM Hackathon · Team Fire</span>
        </div>
      </div>

      {/* ══════════════ RIGHT — Login form ══════════════ */}
      <div
        className="flex flex-col justify-center w-full lg:w-[420px] lg:flex-shrink-0 p-8 lg:p-12"
        style={{ background: "var(--bg)" }}
      >
        {/* Mobile brand */}
        <div className="flex items-center gap-3 mb-10 lg:hidden">
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

        <div className="max-w-sm w-full mx-auto">
          <h2 className="text-[24px] font-black mb-1" style={{ color: "var(--heading)" }}>
            Welcome back
          </h2>
          <p className="text-[13px] mb-8" style={{ color: "var(--muted)" }}>
            Sign in to your security workspace.
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label
                className="block text-[11px] font-semibold uppercase tracking-widest mb-2"
                style={{ color: "var(--muted)" }}
              >
                Email
              </label>
              <input
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-4 py-3 rounded-xl text-[13px] outline-none"
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
              <label
                className="block text-[11px] font-semibold uppercase tracking-widest mb-2"
                style={{ color: "var(--muted)" }}
              >
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
                  className="w-full px-4 py-3 pr-11 rounded-xl text-[13px] outline-none"
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
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 opacity-40 hover:opacity-80 transition-opacity"
                  tabIndex={-1}
                  aria-label={showPassword ? "Hide password" : "Show password"}
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
                className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-[12px]"
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
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-3 rounded-xl text-[14px] font-bold disabled:opacity-50"
              style={{
                background: "linear-gradient(135deg, #f97316 0%, #dc2626 100%)",
                color:      "white",
                cursor:     submitting ? "not-allowed" : "pointer",
                boxShadow:  submitting ? "none" : "0 0 20px rgba(249,115,22,0.25)",
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
          </form>

          {/* Footer */}
          <div className="mt-8 flex items-center justify-center gap-2">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ color: "var(--dim)" }}>
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span className="text-[11px]" style={{ color: "var(--dim)" }}>
              Secured · Session expires in 24h
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
