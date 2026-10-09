"use client";

import { useState, useEffect } from "react";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import ProjectsSettings from "@/components/ProjectsSettings";
import UsersSettings from "@/components/UsersSettings";
import { usePermission } from "@/lib/auth";
import { getLlmConfig, testLlmConfig, saveLlmConfig } from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────────────────

type Section = "projects" | "claude" | "rag" | "users" | "scanner" | "notifications" | "danger";

// ── Shared micro-components ────────────────────────────────────────────────

function SectionCard({
  title,
  subtitle,
  icon,
  children,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  children: React.ReactNode;
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
        <div>
          <p className="text-[13px] font-bold" style={{ color: "var(--heading)" }}>{title}</p>
          <p className="text-[11px]" style={{ color: "var(--muted)" }}>{subtitle}</p>
        </div>
      </div>
      <div className="px-6 py-5 flex flex-col gap-5">{children}</div>
    </div>
  );
}

function FieldRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 sm:gap-8">
      <div className="flex-shrink-0 w-48 pt-0.5">
        <p className="text-[12px] font-semibold" style={{ color: "var(--faint)" }}>{label}</p>
        {hint && <p className="text-[11px] mt-0.5 leading-snug" style={{ color: "var(--muted)" }}>{hint}</p>}
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
  mono = false,
  type = "text",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  type?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full px-3 py-2.5 rounded-xl text-[13px] outline-none"
      style={{
        background: "var(--surface2)",
        border: "1px solid var(--border)",
        color: "var(--body)",
        fontFamily: mono ? "monospace" : "inherit",
      }}
      onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
      onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
    />
  );
}

function SecretInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <input
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? "••••••••••••••••••••••••••"}
        className="w-full px-3 py-2.5 pr-10 rounded-xl text-[13px] outline-none font-mono"
        style={{
          background: "var(--surface2)",
          border: "1px solid var(--border)",
          color: "var(--body)",
        }}
        onFocus={(e) => (e.target.style.borderColor = "var(--accent-blue)")}
        onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
      />
      <button
        type="button"
        onClick={() => setShow((v) => !v)}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px]"
        style={{ color: "var(--muted)" }}
      >
        {show ? "hide" : "show"}
      </button>
    </div>
  );
}

function SelectInput({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full px-3 py-2.5 rounded-xl text-[13px] outline-none appearance-none"
      style={{
        background: "var(--surface2)",
        border: "1px solid var(--border)",
        color: "var(--body)",
        backgroundImage:
          "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236e7681' stroke-width='2.5' stroke-linecap='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E\")",
        backgroundRepeat: "no-repeat",
        backgroundPosition: "right 12px center",
        paddingRight: "32px",
      }}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

function Toggle({ enabled, onChange, label }: { enabled: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <div className="flex items-center gap-3">
      <button
        onClick={() => onChange(!enabled)}
        className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
        style={{ background: enabled ? "var(--accent-green)" : "var(--border2)" }}
      >
        <span
          className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
          style={{
            background: "#fff",
            left: enabled ? "calc(100% - 18px)" : "2px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
          }}
        />
      </button>
      {label && (
        <span className="text-[12px]" style={{ color: enabled ? "var(--body)" : "var(--muted)" }}>
          {label}
        </span>
      )}
    </div>
  );
}

function SaveButton({ onClick, saved }: { onClick: () => void; saved: boolean }) {
  return (
    <div className="flex justify-end pt-2" style={{ borderTop: "1px solid var(--border)" }}>
      <button
        onClick={onClick}
        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-bold transition-all"
        style={{
          background: saved ? "var(--accent-green-bg)" : "var(--btn-accept-bg)",
          color: saved ? "var(--accent-green)" : "var(--btn-accept-text)",
          border: saved ? "1px solid var(--accent-green-bdr)" : "none",
          boxShadow: saved ? "none" : "0 0 16px var(--btn-accept-glow)",
        }}
      >
        {saved ? (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
            Saved
          </>
        ) : (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            Save changes
          </>
        )}
      </button>
    </div>
  );
}

// ── Nav sidebar ────────────────────────────────────────────────────────────

const NAV_ITEMS: { id: Section; label: string; icon: React.ReactNode }[] = [
  { id: "projects", label: "Projects", icon: <span aria-hidden="true">▦</span> },
  {
    id: "claude",
    label: "Claude Gateway",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4" />
        <circle cx="12" cy="12" r="3.5" />
      </svg>
    ),
  },
  {
    id: "rag",
    label: "RAG / Memory",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      </svg>
    ),
  },
  {
    id: "users",
    label: "Users & Roles",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
  },
  {
    id: "scanner",
    label: "Scanner",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
  },
  {
    id: "notifications",
    label: "Notifications",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
      </svg>
    ),
  },
  {
    id: "danger",
    label: "Danger Zone",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
  },
];

// ── Section renderers ──────────────────────────────────────────────────────

function ClaudeSection() {
  const [cfg, setCfg] = useState({ base_url: "", model: "", token: "" });
  const [hint, setHint] = useState("");
  const [tokenSet, setTokenSet] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadErr, setLoadErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<null | { ok: boolean; detail: string }>(null);

  useEffect(() => {
    let cancelled = false;
    getLlmConfig()
      .then((c) => { if (!cancelled) { setCfg({ base_url: c.base_url, model: c.model, token: "" }); setHint(c.token_hint); setTokenSet(c.token_set); } })
      .catch((e) => { if (!cancelled) setLoadErr(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const set = (k: keyof typeof cfg) => (v: string) => { setCfg((p) => ({ ...p, [k]: v })); setSaved(false); setTestResult(null); };
  const body = () => ({ base_url: cfg.base_url, model: cfg.model, ...(cfg.token.trim() ? { token: cfg.token.trim() } : {}) });

  const handleTest = async () => {
    setTesting(true); setTestResult(null);
    try { setTestResult(await testLlmConfig(body())); }
    catch (e) { setTestResult({ ok: false, detail: e instanceof Error ? e.message : "Test failed" }); }
    finally { setTesting(false); }
  };
  const handleSave = async () => {
    try { const c = await saveLlmConfig(body()); setHint(c.token_hint); setTokenSet(c.token_set); setCfg((p) => ({ ...p, token: "" })); setSaved(true); }
    catch (e) { setLoadErr(e instanceof Error ? e.message : "Save failed"); }
  };

  return (
    <SectionCard
      title="Claude Gateway"
      subtitle="Anthropic-compatible LLM gateway (IBM RAD) powering synthesis, Review AI, and the assistant"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--brand-2)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4" /><circle cx="12" cy="12" r="3.5" />
        </svg>
      }
    >
      {loadErr && (
        <div className="px-4 py-2.5 rounded-xl text-[12px]" style={{ background: "var(--accent-red-bg)", border: "1px solid var(--accent-red-bdr)", color: "var(--accent-red)" }}>{loadErr}</div>
      )}

      <FieldRow label="Base URL" hint="Anthropic-compatible endpoint (e.g. https://llm.ibm-rad.com)">
        <TextInput value={cfg.base_url} onChange={set("base_url")} placeholder={loading ? "Loading…" : "https://llm.ibm-rad.com"} mono />
      </FieldRow>

      <FieldRow label="Model" hint="Served model id (e.g. global.anthropic.claude-sonnet-4-6)">
        <TextInput value={cfg.model} onChange={set("model")} placeholder={loading ? "Loading…" : "global.anthropic.claude-sonnet-4-6"} mono />
      </FieldRow>

      <FieldRow label="API token" hint={tokenSet ? "A token is configured — enter a new one to replace it, or leave blank to keep it" : "Gateway API token (sk-…)"}>
        <SecretInput value={cfg.token} onChange={set("token")} placeholder={tokenSet ? `Configured · ${hint} — leave blank to keep` : "Enter gateway token…"} />
      </FieldRow>

      {/* Live connection test */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl flex-wrap" style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}>
        <button
          onClick={handleTest}
          disabled={testing || loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-80"
          style={{ background: "var(--accent-blue-bg)", color: "var(--accent-blue)", border: "1px solid var(--accent-blue-bdr)", opacity: testing ? 0.6 : 1 }}
        >
          {testing ? (
            <><svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56" /></svg>Testing…</>
          ) : "Test connection"}
        </button>
        {testResult && (
          <span className="text-[12px] flex items-center gap-1.5 min-w-0" style={{ color: testResult.ok ? "var(--accent-green)" : "var(--accent-red)" }}>
            {testResult.ok
              ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
              : <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>}
            <span className="truncate">{testResult.detail}</span>
          </span>
        )}
      </div>

      <SaveButton onClick={handleSave} saved={saved} />
    </SectionCard>
  );
}

function RagSection() {
  const [cfg, setCfg] = useState({
    dbPath: "./data/rag_memory.db",
    similarityThreshold: "70",
    topK: "5",
    autoRetain: true,
    retainRejected: false,
  });
  const [saved, setSaved] = useState(false);
  const set = (k: keyof typeof cfg) => (v: string | boolean) => { setCfg((p) => ({ ...p, [k]: v })); setSaved(false); };

  return (
    <SectionCard
      title="RAG / Memory Store"
      subtitle="Milvus Lite vector database and retrieval settings"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-purple)" strokeWidth="2">
          <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
        </svg>
      }
    >
      <FieldRow label="Database path" hint="Local .db file path for pymilvus-lite">
        <TextInput value={cfg.dbPath} onChange={set("dbPath")} mono />
      </FieldRow>

      <FieldRow label="Similarity threshold" hint="Minimum cosine score (%) to surface a RAG match">
        <div className="flex items-center gap-3">
          <input
            type="range"
            min={50} max={95} step={5}
            value={cfg.similarityThreshold}
            onChange={(e) => set("similarityThreshold")(e.target.value)}
            className="flex-1"
          />
          <span
            className="text-[13px] font-bold font-mono w-10 text-right flex-shrink-0"
            style={{ color: "var(--accent-purple)" }}
          >
            {cfg.similarityThreshold}%
          </span>
        </div>
      </FieldRow>

      <FieldRow label="Top-K results" hint="Max prior decisions retrieved per CVE">
        <SelectInput
          value={cfg.topK}
          onChange={set("topK")}
          options={[1, 3, 5, 8, 10].map((n) => ({ value: String(n), label: String(n) }))}
        />
      </FieldRow>

      <div
        className="h-px w-full"
        style={{ background: "var(--border)" }}
      />

      <FieldRow label="Auto-retain approved" hint="Automatically persist every accepted decision to memory">
        <Toggle enabled={cfg.autoRetain} onChange={(v) => set("autoRetain")(v)} label={cfg.autoRetain ? "Enabled" : "Disabled"} />
      </FieldRow>

      <FieldRow label="Retain rejected" hint="Also persist rejected CVE rationales (helps avoid re-analysis)">
        <Toggle enabled={cfg.retainRejected} onChange={(v) => set("retainRejected")(v)} label={cfg.retainRejected ? "Enabled" : "Disabled"} />
      </FieldRow>

      {/* Stats strip */}
      <div
        className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-4 rounded-xl"
        style={{ background: "var(--accent-purple-bg)", border: "1px solid var(--accent-purple-bdr)" }}
      >
        {[
          { label: "Decisions stored", value: "312" },
          { label: "Avg. match score", value: "87%" },
          { label: "DB size", value: "4.2 MB" },
        ].map((s) => (
          <div key={s.label} className="text-center">
            <div className="text-[18px] font-black" style={{ color: "var(--accent-purple)" }}>{s.value}</div>
            <div className="text-[10px] mt-0.5" style={{ color: "var(--muted)" }}>{s.label}</div>
          </div>
        ))}
      </div>

      <SaveButton onClick={() => setSaved(true)} saved={saved} />
    </SectionCard>
  );
}

function ScannerSection() {
  const [cfg, setCfg] = useState({
    defaultScanner: "trivy",
    trivyVersion: "0.50.1",
    severityDefault: "high",
    autoApproveDefault: "none",
    maxConcurrent: "3",
    cacheTtlHours: "24",
    failOnCvss: "9.0",
  });
  const [saved, setSaved] = useState(false);
  const set = (k: keyof typeof cfg) => (v: string) => { setCfg((p) => ({ ...p, [k]: v })); setSaved(false); };

  return (
    <SectionCard
      title="Scanner Defaults"
      subtitle="Default scanner behaviour applied to every new scan"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-yellow)" strokeWidth="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
      }
    >
      <FieldRow label="Default scanner">
        <SelectInput
          value={cfg.defaultScanner}
          onChange={set("defaultScanner")}
          options={[
            { value: "trivy", label: "Trivy (Aqua Security)" },
            { value: "grype", label: "Grype (Anchore)" },
          ]}
        />
      </FieldRow>

      <FieldRow label="Trivy version" hint="Pinned version for reproducible scans">
        <TextInput value={cfg.trivyVersion} onChange={set("trivyVersion")} mono />
      </FieldRow>

      <FieldRow label="Default severity" hint="Minimum severity to surface in new scans">
        <SelectInput
          value={cfg.severityDefault}
          onChange={set("severityDefault")}
          options={["critical", "high", "medium", "low"].map((v) => ({ value: v, label: v.charAt(0).toUpperCase() + v.slice(1) + "+" }))}
        />
      </FieldRow>

      <FieldRow label="Auto-approve below" hint="Org-wide default auto-approval threshold">
        <SelectInput
          value={cfg.autoApproveDefault}
          onChange={set("autoApproveDefault")}
          options={[
            { value: "none", label: "Off — all CVEs require review" },
            { value: "low",  label: "Low severity and below" },
            { value: "medium", label: "Medium severity and below" },
          ]}
        />
      </FieldRow>

      <div
        className="h-px w-full"
        style={{ background: "var(--border)" }}
      />

      <FieldRow label="Max concurrent scans">
        <SelectInput
          value={cfg.maxConcurrent}
          onChange={set("maxConcurrent")}
          options={[1, 2, 3, 5, 10].map((n) => ({ value: String(n), label: String(n) }))}
        />
      </FieldRow>

      <FieldRow label="Cache TTL" hint="Hours to cache Trivy DB before re-pulling">
        <TextInput value={cfg.cacheTtlHours} onChange={set("cacheTtlHours")} />
      </FieldRow>

      <FieldRow label="Fail-hard CVSS" hint="CVEs at or above this score block auto-approve regardless of threshold">
        <TextInput value={cfg.failOnCvss} onChange={set("failOnCvss")} />
      </FieldRow>

      <SaveButton onClick={() => setSaved(true)} saved={saved} />
    </SectionCard>
  );
}

function NotificationsSection() {
  const [cfg, setCfg] = useState({
    emailEnabled: true,
    emailAddr: "security-team@ibm.com",
    slackEnabled: false,
    slackWebhook: "",
    notifyOnCritical: true,
    notifyOnApproval: false,
    notifyOnComplete: true,
    digestDaily: false,
  });
  const [saved, setSaved] = useState(false);
  const set = (k: keyof typeof cfg) => (v: string | boolean) => { setCfg((p) => ({ ...p, [k]: v })); setSaved(false); };

  return (
    <SectionCard
      title="Notifications"
      subtitle="Alert channels for scan events and approvals"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-orange)" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
      }
    >
      {/* Email */}
      <FieldRow label="Email alerts">
        <div className="flex flex-col gap-2">
          <Toggle enabled={cfg.emailEnabled} onChange={(v) => set("emailEnabled")(v)} label="Send email notifications" />
          {cfg.emailEnabled && (
            <TextInput value={cfg.emailAddr} onChange={set("emailAddr")} placeholder="email@ibm.com" type="email" />
          )}
        </div>
      </FieldRow>

      {/* Slack */}
      <FieldRow label="Slack webhook">
        <div className="flex flex-col gap-2">
          <Toggle enabled={cfg.slackEnabled} onChange={(v) => set("slackEnabled")(v)} label="Post to Slack channel" />
          {cfg.slackEnabled && (
            <SecretInput value={cfg.slackWebhook} onChange={set("slackWebhook")} placeholder="https://hooks.slack.com/services/…" />
          )}
        </div>
      </FieldRow>

      <div className="h-px w-full" style={{ background: "var(--border)" }} />

      <FieldRow label="Notify on">
        <div className="flex flex-col gap-2">
          {[
            { key: "notifyOnCritical", label: "Critical CVE found" },
            { key: "notifyOnApproval", label: "Decision made (accept/reject)" },
            { key: "notifyOnComplete", label: "Scan run completed" },
            { key: "digestDaily",      label: "Daily digest summary" },
          ].map(({ key, label }) => (
            <Toggle
              key={key}
              enabled={cfg[key as keyof typeof cfg] as boolean}
              onChange={(v) => set(key as keyof typeof cfg)(v)}
              label={label}
            />
          ))}
        </div>
      </FieldRow>

      <SaveButton onClick={() => setSaved(true)} saved={saved} />
    </SectionCard>
  );
}

function DangerRow({ id, title, desc, btnLabel, confirm, done, setConfirm, execute }: {
  id: "rag" | "scans";
  title: string;
  desc: string;
  btnLabel: string;
  confirm: "rag" | "scans" | null;
  done: "rag" | "scans" | null;
  setConfirm: (value: "rag" | "scans" | null) => void;
  execute: (value: "rag" | "scans") => void;
}) {
  return (
    <div
      className="flex items-center justify-between gap-6 px-5 py-4 rounded-xl"
      style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
    >
      <div>
        <p className="text-[13px] font-semibold" style={{ color: "var(--heading)" }}>{title}</p>
        <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>{desc}</p>
      </div>
      {done === id ? (
        <span className="text-[12px] flex items-center gap-1.5 flex-shrink-0" style={{ color: "var(--accent-green)" }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
          Done
        </span>
      ) : confirm === id ? (
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[11px]" style={{ color: "var(--muted)" }}>Confirm?</span>
          <button
            onClick={() => execute(id)}
            className="px-3 py-1.5 rounded-lg text-[12px] font-bold"
            style={{ background: "var(--accent-red-bg)", color: "var(--accent-red)", border: "1px solid var(--accent-red-bdr)" }}
          >
            Yes, delete
          </button>
          <button
            onClick={() => setConfirm(null)}
            className="px-3 py-1.5 rounded-lg text-[12px]"
            style={{ background: "var(--surface2)", color: "var(--muted)", border: "1px solid var(--border)" }}
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setConfirm(id)}
          className="flex-shrink-0 px-4 py-2 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-80"
          style={{ background: "var(--accent-red-bg)", color: "var(--accent-red)", border: "1px solid var(--accent-red-bdr)" }}
        >
          {btnLabel}
        </button>
      )}
    </div>
  );
}

function DangerSection() {
  const [confirm, setConfirm] = useState<"rag" | "scans" | null>(null);
  const [done, setDone] = useState<"rag" | "scans" | null>(null);

  const execute = (which: "rag" | "scans") => {
    setConfirm(null);
    setDone(which);
    setTimeout(() => setDone(null), 3000);
  };



  return (
    <SectionCard
      title="Danger Zone"
      subtitle="Irreversible actions — proceed with caution"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      }
    >
      <div
        className="flex items-start gap-3 px-4 py-3 rounded-xl text-[12px]"
        style={{ background: "var(--accent-red-bg)", border: "1px solid var(--accent-red-bdr)", color: "var(--accent-red)" }}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" className="flex-shrink-0 mt-0.5">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
        Actions in this section are permanent and cannot be undone. Admin role required.
      </div>

      <DangerRow
        confirm={confirm}
        done={done}
        setConfirm={setConfirm}
        execute={execute}
        id="rag"
        title="Purge RAG memory"
        desc="Delete all 312 persisted decisions from the Milvus vector store. Future scans will lose all institutional knowledge."
        btnLabel="Purge memory"
      />
      <DangerRow
        confirm={confirm}
        done={done}
        setConfirm={setConfirm}
        execute={execute}
        id="scans"
        title="Delete all scan history"
        desc="Remove all scan run records and associated CVE triage data from the system. Dashboard will reset to zero."
        btnLabel="Delete history"
      />
    </SectionCard>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

const SECTION_COMPONENTS: Record<Section, React.ComponentType> = {
  projects: ProjectsSettings,
  claude: ClaudeSection,
  rag: RagSection,
  users: UsersSettings,
  scanner: ScannerSection,
  notifications: NotificationsSection,
  danger: DangerSection,
};

function SettingsPageInner() {
  const [active, setActive] = useState<Section>("projects");
  const canManageUsers = usePermission("canManageUsers");
  const ActiveSection = SECTION_COMPONENTS[active];

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: "var(--bg)", color: "var(--heading)" }}>
      <TopNav />

      <div className="flex flex-col lg:flex-row flex-1 overflow-hidden">
        {/* Sidebar — horizontal tab strip on phones, vertical rail on lg+ */}
        <aside
          className="w-full lg:w-52 flex-shrink-0 flex flex-row lg:flex-col gap-1 lg:gap-0.5 py-2 lg:py-4 overflow-x-auto lg:overflow-y-auto border-solid border-[color:var(--border)] border-b lg:border-b-0 lg:border-r"
          style={{ background: "var(--bg-nav)" }}
        >
          <p
            className="hidden lg:block px-5 pb-2 text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: "var(--muted)" }}
          >
            Settings
          </p>
          {NAV_ITEMS.filter((item) => (item.id !== "users" && item.id !== "claude") || canManageUsers).map((item) => {
            const isActive = active === item.id;
            const isDanger = item.id === "danger";
            return (
              <button
                key={item.id}
                onClick={() => setActive(item.id)}
                className="mx-1 lg:mx-2 flex-shrink-0 whitespace-nowrap flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium text-left transition-colors"
                style={{
                  background: isActive ? (isDanger ? "var(--accent-red-bg)" : "var(--surface2)") : "transparent",
                  color: isActive
                    ? isDanger ? "var(--accent-red)" : "var(--heading)"
                    : isDanger ? "var(--accent-red)" : "var(--subtle)",
                  border: isActive ? `1px solid ${isDanger ? "var(--accent-red-bdr)" : "var(--border)"}` : "1px solid transparent",
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = "var(--surface2)"; }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ color: isActive ? (isDanger ? "var(--accent-red)" : "var(--accent-blue)") : "var(--dim)" }}>
                  {item.icon}
                </span>
                {item.label}
              </button>
            );
          })}
        </aside>

        {/* Content */}
        <main className="flex-1 overflow-y-auto px-4 sm:px-8 py-5 sm:py-7">
          <div className="max-w-4xl mx-auto">
            <ActiveSection />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <RequireAuth permission="canViewSettings">
      <SettingsPageInner />
    </RequireAuth>
  );
}
