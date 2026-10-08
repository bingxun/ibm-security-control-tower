"use client";
import { useEffect, useState } from "react";
import { listBaselines, publishBaseline, revokeBaseline, type SharedBaseline } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { CveRecord } from "@/lib/types";
import styles from "./Management.module.css";

export default function BaselinePublisher({ runId, cve }: { runId: string; cve: CveRecord }) {
  const { permissions } = useAuth();
  const [open, setOpen] = useState(false);
  const [justification, setJustification] = useState("");
  const [remediation, setRemediation] = useState("");
  const [baselines, setBaselines] = useState<SharedBaseline[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    listBaselines().then(rows => { if (!cancelled) setBaselines(rows.filter(r => r.cve_id === cve.id && r.pkg === cve.pkg)); })
      .catch(() => { if (!cancelled) setError("Unable to load shared references."); });
    return () => { cancelled = true; };
  }, [cve.id, cve.pkg]);
  async function publish() {
    setBusy(true); setError(""); setMessage("");
    try {
      await publishBaseline(runId, cve.id, cve.pkg, justification, remediation);
      setBaselines((await listBaselines()).filter(r => r.cve_id === cve.id && r.pkg === cve.pkg));
      setMessage("Published for reference in future scans across all projects."); setOpen(false);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to publish."); }
    finally { setBusy(false); }
  }
  return <section className="rounded-xl p-4 my-3" style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}>
    <h3 className="text-[12px] font-bold">Shared Cyber Manager baseline</h3>
    {baselines.map(b => <div key={b.id} className="text-[12px] mt-3 space-y-1">
      <p style={{ color: "var(--subtle)" }}>{b.approver} · {new Date(b.published_at).toLocaleDateString()} · Reference only</p>
      <p className="whitespace-pre-wrap">{b.rationale}</p><p className="whitespace-pre-wrap">Remediation: {b.remediation}</p>
      {permissions?.canApproveSubmitted && <button disabled={busy} className={styles.button} onClick={async () => {
        setBusy(true); setError(""); setMessage("");
        try { await revokeBaseline(b.id); setBaselines(rows => rows.filter(r => r.id !== b.id)); setMessage("Withdrawn from future scans. Existing scan references remain historical evidence."); }
        catch (e) { setError(e instanceof Error ? e.message : "Unable to withdraw."); }
        finally { setBusy(false); }
      }}>Withdraw baseline</button>}
    </div>)}
    {!baselines.length && <p className="text-[12px] mt-2" style={{ color: "var(--muted)" }}>No published reference for this CVE and package.</p>}
    {permissions?.canApproveSubmitted && cve.status === "approved" && <button disabled={busy} className={`${styles.button} mt-3`} onClick={() => setOpen(!open)}>{open ? "Cancel" : "Publish a shared reference"}</button>}
    {open && <div className="mt-3 flex flex-col gap-3 text-[12px]">
      <p>This text will be visible across all projects. Write a reusable assessment without project names, infrastructure secrets or private details. It will not automatically approve new findings.</p>
      <label>Shared justification<textarea className="w-full rounded-lg p-3 mt-1" style={{ background: "var(--surface)" }} value={justification} onChange={e => setJustification(e.target.value)} maxLength={20000} rows={4} /></label>
      <label>Shared remediation<textarea className="w-full rounded-lg p-3 mt-1" style={{ background: "var(--surface)" }} value={remediation} onChange={e => setRemediation(e.target.value)} maxLength={20000} rows={3} /></label>
      <button className={styles.button} disabled={busy || !justification.trim() || !remediation.trim()} onClick={() => void publish()}>{busy ? "Publishing…" : "Publish to all projects"}</button>
    </div>}
    {message && <p role="status" className="text-[12px] mt-2">{message}</p>}
    {error && <p role="alert" className="text-[12px] mt-2" style={{ color: "var(--accent-red)" }}>{error}</p>}
  </section>;
}
