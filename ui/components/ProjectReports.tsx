"use client";
import { useRef, useState } from "react";
import { downloadProjectReport, importProjectReport } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import styles from "./Management.module.css";

export default function ProjectReports({ projectId, onImported }: { projectId: string; onImported: () => void }) {
  const { permissions } = useAuth();
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  async function download(template = false) {
    setBusy(true); setError(""); setMessage("");
    try { await downloadProjectReport(projectId, template); }
    catch (e) { setError(e instanceof Error ? e.message : "Download failed."); }
    finally { setBusy(false); }
  }
  return <section className="rounded-2xl p-5" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div><h2 className="text-[14px] font-bold">Project review file</h2><p className="text-[12px] mt-1" style={{ color: "var(--subtle)" }}>All image scans, CVEs, justifications and remediations in one CSV.</p></div>
      <div className="flex flex-wrap gap-2">
        <button className={styles.button} disabled={busy} onClick={() => void download()}>Download project CSV</button>
        <button className={styles.button} disabled={busy} onClick={() => input.current?.click()}>Upload completed CSV</button>
        <button className={styles.button} disabled={busy} onClick={() => void download(true)}>CSV template</button>
      </div>
    </div>
    <p className="text-[12px] mt-3" style={{ color: "var(--muted)" }}>Download the project file, set Status to {permissions?.canApproveSubmitted ? "approved or rejected" : permissions?.canSubmitForApproval ? "submitted" : "approved"} for the findings you are deciding, and complete Justification and Remediation. Keep Run ID, Image, CVE ID and Package unchanged. Upload saves all valid changes together, and each row is checked against what your role may do; publishing a shared baseline is a separate action on each approved CVE.</p>
    <input ref={input} className="hidden" type="file" accept=".csv,text/csv" aria-label="Completed Cyber Manager CSV" disabled={busy} onChange={async e => {
      const file = e.target.files?.[0]; e.target.value = "";
      if (!file) return;
      setBusy(true); setError(""); setMessage("");
      try {
        if (!file.name.toLowerCase().endsWith(".csv") || file.size > 5_000_000) throw new Error("Choose a CSV file no larger than 5 MB.");
        const content = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
        const result = await importProjectReport(projectId, content);
        setMessage(`${result.updated} decisions saved; ${result.unchanged} findings unchanged.`); onImported();
      } catch (err) { setError(err instanceof Error ? err.message : "Upload failed."); }
      finally { setBusy(false); }
    }} />
    {busy && <p role="status" className="text-[12px] mt-3">Processing file…</p>}
    {message && <p role="status" className="text-[12px] mt-3" style={{ color: "var(--accent-green)" }}>{message}</p>}
    {error && <p role="alert" className="text-[12px] mt-3" style={{ color: "var(--accent-red)" }}>{error}</p>}
  </section>;
}
