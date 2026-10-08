"use client";

import { useState } from "react";
import TopNav from "@/components/TopNav";
import RequireAuth from "@/components/RequireAuth";
import ProjectsSettings from "@/components/ProjectsSettings";
import UsersSettings from "@/components/UsersSettings";
import { usePermission } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────

type Section = "projects" | "watsonx" | "rag" | "users" | "scanner" | "notifications" | "danger";

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
    id: "watsonx",
    label: "watsonx.ai",
    icon: (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z" />
        <path d="M12 8v4l3 3" />
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

function WatsonxSection() {
  const [cfg, setCfg] = useState({
    apiKey: "",
    projectId: "58098c39-0bb6-4ac6-abaa-2cdb451c33cd",
    url: "https://jp-tok.ml.cloud.ibm.com",
    model: "ibm/granite-13b-instruct-v2",
    embedModel: "ibm/slate-125m-english-rtrvr",
    maxTokens: "256",
    temperature: "0.3",
  });
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<null | "ok" | "fail">(null);
  const set = (k: keyof typeof cfg) => (v: string) => {
    setCfg((p) => ({ ...p, [k]: v }));
    setSaved(false);
    setTestResult(null);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    await new Promise((r) => setTimeout(r, 1400));
    setTesting(false);
    setTestResult(cfg.apiKey.length > 10 ? "ok" : "fail");
  };

  return (
    <SectionCard
      title="watsonx.ai"
      subtitle="IBM Granite LLM and slate embedding model credentials"
      icon={
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2">
          <path d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z" /><path d="M12 8v4l3 3" />
        </svg>
      }
    >
      <FieldRow label="API Key" hint="IBM Cloud API key with WML Editor role">
        <SecretInput value={cfg.apiKey} onChange={set("apiKey")} placeholder="Enter IBM Cloud API key…" />
      </FieldRow>

      <FieldRow label="Project ID" hint="watsonx.ai project GUID">
        <TextInput value={cfg.projectId} onChange={set("projectId")} mono />
      </FieldRow>

      <FieldRow label="Regional URL" hint="watsonx.ai endpoint">
        <SelectInput
          value={cfg.url}
          onChange={set("url")}
          options={[
            { value: "https://jp-tok.ml.cloud.ibm.com", label: "Asia Pacific — Tokyo (jp-tok)" },
            { value: "https://us-south.ml.cloud.ibm.com", label: "US South — Dallas (us-south)" },
            { value: "https://eu-de.ml.cloud.ibm.com", label: "EU — Frankfurt (eu-de)" },
            { value: "https://au-syd.ml.cloud.ibm.com", label: "Asia Pacific — Sydney (au-syd)" },
          ]}
        />
      </FieldRow>

      <div
        className="h-px w-full"
        style={{ background: "var(--border)" }}
      />

      <FieldRow label="Generation model" hint="Granite model for rationale synthesis">
        <SelectInput
          value={cfg.model}
          onChange={set("model")}
          options={[
            { value: "ibm/granite-13b-instruct-v2", label: "Granite 13B Instruct v2" },
            { value: "ibm/granite-3-8b-instruct", label: "Granite 3 8B Instruct" },
            { value: "ibm/granite-20b-multilingual", label: "Granite 20B Multilingual" },
          ]}
        />
      </FieldRow>

      <FieldRow label="Embedding model" hint="Slate model for RAG vector encoding">
        <SelectInput
          value={cfg.embedModel}
          onChange={set("embedModel")}
          options={[
            { value: "ibm/slate-125m-english-rtrvr", label: "Slate 125M English" },
            { value: "ibm/slate-30m-english-rtrvr", label: "Slate 30M English (faster)" },
          ]}
        />
      </FieldRow>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <FieldRow label="Max tokens" hint="Per-CVE generation cap">
          <TextInput value={cfg.maxTokens} onChange={set("maxTokens")} />
        </FieldRow>
        <FieldRow label="Temperature">
          <TextInput value={cfg.temperature} onChange={set("temperature")} />
        </FieldRow>
      </div>

      {/* Connection test */}
      <div
        className="flex items-center gap-3 px-4 py-3 rounded-xl"
        style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}
      >
        <button
          onClick={handleTest}
          disabled={testing}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-80"
          style={{
            background: "var(--accent-blue-bg)",
            color: "var(--accent-blue)",
            border: "1px solid rgba(68,147,248,0.25)",
            opacity: testing ? 0.6 : 1,
          }}
        >
          {testing ? (
            <>
              <svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M21 12a9 9 0 1 1-6.219-8.56" />
              </svg>
              Testing…
            </>
          ) : "Test connection"}
        </button>
        {testResult === "ok" && (
          <span className="text-[12px] flex items-center gap-1.5" style={{ color: "var(--accent-green)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
            Connection successful
          </span>
        )}
        {testResult === "fail" && (
          <span className="text-[12px] flex items-center gap-1.5" style={{ color: "var(--accent-red)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            Failed — check API key and project association
          </span>
        )}
      </div>

      <SaveButton onClick={() => setSaved(true)} saved={saved} />
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
  watsonx: WatsonxSection,
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

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside
          className="w-52 flex-shrink-0 flex flex-col py-4 gap-0.5 overflow-y-auto"
          style={{ background: "var(--bg-nav)", borderRight: "1px solid var(--border)" }}
        >
          <p
            className="px-5 pb-2 text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: "var(--muted)" }}
          >
            Settings
          </p>
          {NAV_ITEMS.filter((item) => item.id !== "users" || canManageUsers).map((item) => {
            const isActive = active === item.id;
            const isDanger = item.id === "danger";
            return (
              <button
                key={item.id}
                onClick={() => setActive(item.id)}
                className="mx-2 flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium text-left transition-colors"
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
        <main className="flex-1 overflow-y-auto px-8 py-7">
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
