"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import { startScan } from "@/lib/api";

// ── Form shape ─────────────────────────────────────────────────────────────
interface ScanForm {
  imageRef: string;
  registry: string;
  tag: string;

  projectId: string;
  cloudProvider: string;

  cisProfile: string;

  severityThreshold: "critical" | "high" | "medium" | "low";
  scanner: "trivy" | "grype";
  autoApproveBelow: "none" | "medium" | "low";
}

const REGISTRIES = ["docker.io", "ghcr.io", "icr.io", "quay.io", "custom"];
const CLOUD_PROVIDERS = ["IBM Cloud", "AWS", "Azure", "GCP", "On-prem"];
const CIS_PROFILES = [
  "CIS Docker Benchmark v1.6",
  "CIS Kubernetes Benchmark v1.8",
  "CIS IBM Cloud Foundations v1.0",
  "NIST SP 800-190",
  "Custom / Upload",
];
const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

// ── Micro-components ───────────────────────────────────────────────────────

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label
      className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5"
      style={{ color: "var(--muted)" }}
    >
      {children}
    </label>
  );
}

function Input({
  placeholder,
  value,
  onChange,
  mono = false,
  disabled = false,
}: {
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
  mono?: boolean;
  disabled?: boolean;
}) {
  return (
    <input
      type="text"
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      className="w-full px-3 py-2.5 rounded-xl text-[13px] outline-none transition-colors"
      style={{
        background: "var(--surface2)",
        border: "1px solid var(--border)",
        color: "var(--body)",
        fontFamily: mono ? "monospace" : "inherit",
        opacity: disabled ? 0.5 : 1,
      }}
      onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
      onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
    />
  );
}

function Select({
  value,
  onChange,
  options,
  disabled = false,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      className="w-full px-3 py-2.5 rounded-xl text-[13px] outline-none transition-colors appearance-none"
      style={{
        background: "var(--surface2)",
        border: "1px solid var(--border)",
        color: "var(--body)",
        opacity: disabled ? 0.5 : 1,
        backgroundImage:
          "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236e7681' stroke-width='2.5' stroke-linecap='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E\")",
        backgroundRepeat: "no-repeat",
        backgroundPosition: "right 12px center",
        paddingRight: "32px",
      }}
    >
      {options.map((o) => (
        <option key={o} value={o}>{o}</option>
      ))}
    </select>
  );
}

function SectionCard({
  icon,
  title,
  subtitle,
  children,
  badge,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  children: React.ReactNode;
  badge?: React.ReactNode;
}) {
  return (
    <div
      className="rounded-2xl overflow-hidden"
      style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
    >
      <div
        className="flex items-center gap-3 px-6 py-4"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: "var(--surface2)" }}
        >
          {icon}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-bold" style={{ color: "var(--heading)" }}>
              {title}
            </span>
            {badge}
          </div>
          <span className="text-[11px]" style={{ color: "var(--muted)" }}>
            {subtitle}
          </span>
        </div>
      </div>
      <div className="px-6 py-5">{children}</div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

function NewScanPageInner() {
  const router = useRouter();
  const [form, setForm] = useState<ScanForm>({
    imageRef: "",
    registry: "docker.io",
    tag: "latest",
    projectId: "",
    cloudProvider: "IBM Cloud",
    cisProfile: "CIS Docker Benchmark v1.6",
    severityThreshold: "high",
    scanner: "trivy",
    autoApproveBelow: "none",
  });

  const [launching, setLaunching] = useState(false);
  const [error, setError]         = useState<string | null>(null);

  const set = <K extends keyof ScanForm>(k: K, v: ScanForm[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  // ── Image ref validation ──────────────────────────────────────────────────
  // Rules:
  //   • No spaces
  //   • No double colons (e.g. ubuntu:20.04:latest)
  //   • No double slashes
  //   • Only valid chars: a-z A-Z 0-9 . - _ / : @
  const imageRefError = (() => {
    const raw = form.imageRef.trim();
    if (!raw) return null; // empty — handled by canLaunch
    if (/\s/.test(raw))           return "Image name must not contain spaces.";
    if ((raw.match(/:/g) || []).length > 1)
                                  return "Invalid format — too many \":\" separators (e.g. name:tag:extra).";
    if (raw.includes("//"))       return "Invalid format — double slash \"//\" is not allowed.";
    if (raw.startsWith("/") || raw.endsWith("/"))
                                  return "Image name must not start or end with \"/\".";
    if (raw.startsWith(":") || raw.endsWith(":"))
                                  return "Image name must not start or end with \":\".";
    if (/[^a-zA-Z0-9.\-_/:@]/.test(raw))
                                  return "Image name contains invalid characters. Use a-z, 0-9, . - _ / : @.";
    return null;
  })();

  // Build the final image ref sent to the backend.
  // If the user typed a full ref (contains ":" for a tag, or multiple "/" for a path
  // that already includes the registry), use it as-is.
  // Otherwise assemble registry + name + tag from the separate fields.
  const resolvedRef = (() => {
    const raw = form.imageRef.trim();
    if (imageRefError) return ""; // invalid — don't resolve
    // Already has a tag (contains ":") or is a full multi-part ref — use verbatim
    if (raw.includes(":") || raw.split("/").length > 2) return raw;
    // Bare name — prepend registry and append tag
    return `${form.registry}/${raw}:${form.tag || "latest"}`;
  })();

  const canLaunch =
    form.imageRef.trim().length > 0 &&
    !imageRefError &&
    form.projectId.trim().length > 0 &&
    !launching;

  const handleLaunch = async () => {
    if (!canLaunch) return;
    setLaunching(true);
    setError(null);
    try {
      // POST immediately — backend registers the run and starts Trivy in the background
      const { run_id } = await startScan({
        imageRef: resolvedRef,
        projectId: form.projectId,
        cisProfile: form.cisProfile,
        severityThreshold: form.severityThreshold,
        scanner: form.scanner,
        autoApproveBelow: form.autoApproveBelow,
        // no trivyJson — backend runs Trivy itself
      });
      router.push(`/review?run=${run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLaunching(false);
    }
  };

  return (
    <div
      className="flex flex-col h-screen overflow-hidden"
      style={{ background: "var(--bg)", color: "var(--heading)" }}
    >
      <TopNav />

      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-6 py-8 flex flex-col gap-5">

          {/* Page title */}
          <div>
            <h1 className="text-[22px] font-black tracking-tight" style={{ color: "var(--heading)" }}>
              New Security Scan
            </h1>
            <p className="text-[13px] mt-1" style={{ color: "var(--subtle)" }}>
              Configure the container target, project context, and policies. The agent will ingest, synthesise, and prepare rationale for your review.
            </p>
          </div>

          {/* Error banner */}
          {error && (
            <div
              className="flex items-center gap-3 px-4 py-3 rounded-xl text-[13px]"
              style={{
                background: "var(--accent-red-bg)",
                border: "1px solid var(--accent-red-bdr)",
                color: "var(--accent-red)",
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              {error}
              <button className="ml-auto text-[11px]" onClick={() => setError(null)}>✕</button>
            </div>
          )}

          {/* ── 1. Container Target ── */}
          <SectionCard
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2">
                <rect x="2" y="7" width="20" height="14" rx="2" />
                <path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" />
                <line x1="12" y1="12" x2="12" y2="16" />
                <line x1="10" y1="14" x2="14" y2="14" />
              </svg>
            }
            title="Container Target"
            subtitle="The image to scan for vulnerabilities"
          >
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <Label>Registry</Label>
                  <Select
                    value={form.registry}
                    onChange={(v) => set("registry", v)}
                    options={REGISTRIES}
                    disabled={launching}
                  />
                </div>
                <div className="col-span-2">
                  <Label>Image name <span style={{ color: "var(--accent-red)" }}>*</span></Label>
                  <Input
                    placeholder="e.g. nginx:1.21.6 or my-org/api-gateway"
                    value={form.imageRef}
                    onChange={(v) => set("imageRef", v)}
                    mono
                    disabled={launching}
                  />
                  {imageRefError && (
                    <p className="mt-1.5 text-[11px] flex items-center gap-1.5" style={{ color: "var(--accent-red)" }}>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                      </svg>
                      {imageRefError}
                    </p>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <Label>Tag / Digest</Label>
                  <Input
                    placeholder="latest"
                    value={form.tag}
                    onChange={(v) => set("tag", v)}
                    mono
                    disabled={launching}
                  />
                </div>
                <div className="col-span-2">
                  <Label>Resolved reference</Label>
                  <div
                    className="px-3 py-2.5 rounded-xl text-[12px] font-mono truncate"
                    style={{
                      background: "var(--surface3)",
                      border: "1px solid var(--border)",
                      color: form.imageRef ? "var(--accent-blue)" : "var(--dim)",
                    }}
                  >
                    {form.imageRef
                      ? resolvedRef
                      : "—"}
                  </div>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* ── 2. Project Context ── */}
          <SectionCard
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-purple)" strokeWidth="2">
                <polygon points="12 2 2 7 12 12 22 7 12 2" />
                <polyline points="2 17 12 22 22 17" />
                <polyline points="2 12 12 17 22 12" />
              </svg>
            }
            title="Project Context"
            subtitle="Helps the agent ground its rationale in your actual environment"
          >
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Project ID <span style={{ color: "var(--accent-red)" }}>*</span></Label>
                  <Input
                    placeholder="e.g. CLOUD-247"
                    value={form.projectId}
                    onChange={(v) => set("projectId", v)}
                    mono
                    disabled={launching}
                  />
                </div>
                <div>
                  <Label>Cloud Provider</Label>
                  <Select
                    value={form.cloudProvider}
                    onChange={(v) => set("cloudProvider", v)}
                    options={CLOUD_PROVIDERS}
                    disabled={launching}
                  />
                </div>
              </div>

            </div>
          </SectionCard>

          {/* ── 3. Policy ── */}
          <SectionCard
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-yellow)" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            }
            title="Compliance Policy"
            subtitle="CIS benchmark applied to validate controls"
          >
            <div className="flex flex-col gap-4">
              <div>
                <Label>CIS Profile</Label>
                <Select
                  value={form.cisProfile}
                  onChange={(v) => set("cisProfile", v)}
                  options={CIS_PROFILES}
                  disabled={launching}
                />
              </div>

            </div>
          </SectionCard>

          {/* ── 4. Scan Options ── */}
          <SectionCard
            icon={
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--faint)" strokeWidth="2">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14" />
              </svg>
            }
            title="Scan Options"
            subtitle="Control what the scanner looks for and how the agent handles results"
          >
            <div className="grid grid-cols-3 gap-5">
              {/* Scanner */}
              <div>
                <Label>Scanner</Label>
                <div className="flex flex-col gap-2">
                  {(["trivy", "grype"] as const).map((s) => (
                    <label
                      key={s}
                      className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer transition-colors"
                      style={{
                        background: form.scanner === s ? "var(--accent-blue-bg)" : "var(--surface2)",
                        border: `1px solid ${form.scanner === s ? "var(--accent-blue)" : "var(--border)"}`,
                        opacity: launching ? 0.5 : 1,
                      }}
                    >
                      <input
                        type="radio"
                        name="scanner"
                        value={s}
                        checked={form.scanner === s}
                        onChange={() => set("scanner", s)}
                        className="hidden"
                        disabled={launching}
                      />
                      <div
                        className="w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0"
                        style={{ borderColor: form.scanner === s ? "var(--accent-blue)" : "var(--border2)" }}
                      >
                        {form.scanner === s && (
                          <div className="w-2 h-2 rounded-full" style={{ background: "var(--accent-blue)" }} />
                        )}
                      </div>
                      <div>
                        <div className="text-[12px] font-semibold capitalize" style={{ color: "var(--heading)" }}>{s}</div>
                        <div className="text-[10px]" style={{ color: "var(--muted)" }}>
                          {s === "trivy" ? "Aqua Security" : "Anchore"}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Minimum severity */}
              <div>
                <Label>Minimum severity</Label>
                <div className="flex flex-col gap-2">
                  {SEVERITY_LEVELS.map((sev) => {
                    const color =
                      sev === "critical" ? "var(--accent-red)" :
                      sev === "high"     ? "var(--accent-orange)" :
                      sev === "medium"   ? "var(--accent-yellow)" :
                                           "var(--accent-green)";
                    const isSelected = form.severityThreshold === sev;
                    return (
                      <label
                        key={sev}
                        className="flex items-center gap-3 px-3 py-2 rounded-xl cursor-pointer"
                        style={{
                          background: isSelected ? `rgba(${sev === "critical" ? "248,81,73" : sev === "high" ? "240,136,62" : sev === "medium" ? "210,153,34" : "63,185,80"},0.08)` : "var(--surface2)",
                          border: `1px solid ${isSelected ? color : "var(--border)"}`,
                          opacity: launching ? 0.5 : 1,
                        }}
                      >
                        <input
                          type="radio"
                          name="severity"
                          value={sev}
                          checked={isSelected}
                          onChange={() => set("severityThreshold", sev as ScanForm["severityThreshold"])}
                          className="hidden"
                          disabled={launching}
                        />
                        <div
                          className="w-3.5 h-3.5 rounded-full flex-shrink-0"
                          style={{ background: isSelected ? color : "var(--border2)" }}
                        />
                        <span
                          className="text-[12px] font-semibold capitalize"
                          style={{ color: isSelected ? color : "var(--subtle)" }}
                        >
                          {sev}+
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Auto-approve */}
              <div>
                <Label>Auto-approve below</Label>
                <div className="flex flex-col gap-2 mb-3">
                  {(["none", "low", "medium"] as const).map((opt) => {
                    const isSelected = form.autoApproveBelow === opt;
                    return (
                      <label
                        key={opt}
                        className="flex items-center gap-3 px-3 py-2 rounded-xl cursor-pointer"
                        style={{
                          background: isSelected ? "var(--accent-green-bg)" : "var(--surface2)",
                          border: `1px solid ${isSelected ? "var(--accent-green-bdr)" : "var(--border)"}`,
                          opacity: launching ? 0.5 : 1,
                        }}
                      >
                        <input
                          type="radio"
                          name="auto"
                          value={opt}
                          checked={isSelected}
                          onChange={() => set("autoApproveBelow", opt)}
                          className="hidden"
                          disabled={launching}
                        />
                        <div
                          className="w-3.5 h-3.5 rounded-full flex-shrink-0"
                          style={{ background: isSelected ? "var(--accent-green)" : "var(--border2)" }}
                        />
                        <div>
                          <div
                            className="text-[12px] font-semibold capitalize"
                            style={{ color: isSelected ? "var(--accent-green)" : "var(--subtle)" }}
                          >
                            {opt === "none" ? "Off" : `${opt} severity`}
                          </div>
                        </div>
                      </label>
                    );
                  })}
                </div>
                {form.autoApproveBelow !== "none" && (
                  <div
                    className="flex items-start gap-2 p-2.5 rounded-lg text-[11px]"
                    style={{
                      background: "var(--accent-yellow-bg, rgba(210,153,34,0.08))",
                      border: "1px solid rgba(210,153,34,0.2)",
                      color: "var(--accent-yellow)",
                    }}
                  >
                    ⚠ Findings below this threshold will be auto-approved without human review.
                  </div>
                )}
              </div>
            </div>
          </SectionCard>

          {/* ── Launch bar ── */}
          <div
            className="rounded-2xl flex items-center gap-4 px-6 py-4 sticky bottom-4"
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
            }}
          >
            <div className="flex-1">
              {launching ? (
                <div className="flex items-center gap-2.5">
                  <span
                    className="w-2 h-2 rounded-full animate-pulse flex-shrink-0"
                    style={{ background: "var(--accent-blue)" }}
                  />
                  <p className="text-[13px]" style={{ color: "var(--subtle)" }}>
                    Starting agent pipeline…
                  </p>
                </div>
              ) : canLaunch ? (
                <p className="text-[13px]" style={{ color: "var(--subtle)" }}>
                  Ready to scan{" "}
                  <span className="font-mono font-semibold" style={{ color: "var(--accent-blue)" }}>
                    {resolvedRef}
                  </span>
                  {" "}for{" "}
                  <span style={{ color: "var(--heading)" }}>{form.severityThreshold}+</span> severity CVEs
                </p>
              ) : (
                <p className="text-[13px]" style={{ color: "var(--muted)" }}>
                  Fill in <span style={{ color: "var(--heading)" }}>Image name</span> and{" "}
                  <span style={{ color: "var(--heading)" }}>Project ID</span> to launch
                </p>
              )}
            </div>

            <button
              onClick={handleLaunch}
              disabled={!canLaunch}
              className="flex items-center gap-2.5 px-8 py-3 rounded-xl text-[14px] font-bold transition-all"
              style={{
                background: canLaunch ? "var(--btn-accept-bg)" : "var(--surface2)",
                color: canLaunch ? "var(--btn-accept-text)" : "var(--dim)",
                border: canLaunch ? "none" : "1px solid var(--border)",
                boxShadow: canLaunch ? "0 0 24px var(--btn-accept-glow)" : "none",
                cursor: canLaunch ? "pointer" : "not-allowed",
              }}
            >
              {launching ? (
                <>
                  <svg
                    width="15" height="15" viewBox="0 0 24 24" fill="none"
                    stroke="currentColor" strokeWidth="2.5"
                    className="animate-spin"
                  >
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Launching…
                </>
              ) : (
                <>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  Launch Scan
                </>
              )}
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}

export default function NewScanPage() {
  return (
    <RequireAuth permission="canScan">
      <NewScanPageInner />
    </RequireAuth>
  );
}
