"use client";

import { useEffect, useState, useRef, type FormEvent } from "react";
import styles from "./Management.module.css";
import ProjectIcon from "./ProjectIcon";
import { useAuth } from "@/lib/auth";
import { ROLE_LABELS } from "@/lib/types";
import { listProjects, createProject, getProjectMembers, saveProjectMembers, listUsers, type Project, type PlatformUser } from "@/lib/api";

const control = styles.button;

function MembershipEditor({ project }: { project: Project }) {
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [retry, setRetry] = useState(0);
  const pending = useRef(false);
  useEffect(() => {
    let cancelled = false;
    Promise.all([listUsers(), getProjectMembers(project.id)]).then(([accounts, members]) => {
      if (!cancelled) { setUsers(accounts.filter(u => !u.roles.includes("SUPER_ADMIN"))); setSelected(members.user_ids); }
    }).catch(e => { if (!cancelled) setError(e.message); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [project.id, retry]);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (pending.current) return;
    pending.current = true; setBusy(true); setError(""); setSaved(false);
    try { const result = await saveProjectMembers(project.id, selected); setSelected(result.user_ids); setSaved(true); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to save assignments"); }
    finally { pending.current = false; setBusy(false); }
  }
  return <form onSubmit={save} className="space-y-3 border-t border-[var(--border)] pt-4" aria-label={`Members of ${project.name}`}>
    <h3 className="font-semibold">Project assignments</h3>
    <p className="text-xs text-[var(--faint)]">Select the admins and team members who can access this project. Super admins always have access.</p>
    {loading ? <p role="status">Loading members…</p> : <>
      {error && <p role="alert" className="text-[var(--accent-red)]">{error}</p>}
      {error && <button type="button" className={control} disabled={busy} onClick={() => { setError(""); setLoading(true); setRetry(n => n + 1); }}>Reload members</button>}
      {!error && <>
        <fieldset disabled={busy} className="max-h-72 overflow-y-auto space-y-2">
          {users.map(u => <label key={u.id} className="flex items-center gap-3 rounded-lg bg-[var(--surface2)] p-3">
            <input type="checkbox" className="h-4 w-4 accent-[var(--accent-blue)]" checked={selected.includes(u.id)} onChange={e => { setSaved(false); setSelected(ids => e.target.checked ? [...ids, u.id] : ids.filter(id => id !== u.id)); }} />
            <span className="min-w-0"><span className="block text-sm">{u.name} · {u.roles.map(r => ROLE_LABELS[r]).join(", ")}{!u.is_active && " (inactive)"}</span><span className="block break-all text-xs text-[var(--faint)]">{u.email}</span></span>
          </label>)}
          {users.length === 0 && <p className="text-sm">Create an account in Users &amp; Roles first.</p>}
        </fieldset>
        <button className={styles.primary} disabled={busy || users.length === 0}>{busy ? "Saving…" : "Save assignments"}</button>
      </>}
      <p role="status" className="text-sm text-[var(--accent-green)]">{saved ? "Project assignments saved." : ""}</p>
    </>}
  </form>;
}

export default function ProjectsSettings() {
  const { permissions } = useAuth();
  const manage = permissions?.canManageProjects === true;
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState("");
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const pending = useRef(false);
  useEffect(() => {
    let cancelled = false;
    listProjects().then(p => { if (!cancelled) setProjects(p); }).catch(e => { if (!cancelled) setError(e.message); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [retry]);
  async function create(event: FormEvent) {
    event.preventDefault(); if (!name.trim() || pending.current) return;
    pending.current = true; setBusy(true); setError(""); setMessage("");
    try { const project = await createProject(name.trim(), description.trim()); setProjects(p => [...p, project]); setName(""); setDescription(""); setEditing(project.id); setShowCreate(false); setSearch(""); setMessage("Project created. Assign team members below."); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to create project"); }
    finally { pending.current = false; setBusy(false); }
  }
  return <section className="space-y-5 rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 text-[var(--body)]">
    <div className="flex justify-between items-center gap-3"><div><h1 className="text-lg font-bold text-[var(--heading)]">Projects</h1><p className="text-sm text-[var(--faint)]">{manage ? "Create projects and assign access for your team." : "Only projects assigned to you are shown."}</p></div><button className={control} disabled={loading || busy} onClick={() => { setError(""); setLoading(true); setRetry(n => n + 1); }}>Refresh</button></div>
    {error && <p role="alert" className="text-[var(--accent-red)]">{error}</p>}
    <p role="status" className={message ? "text-sm text-[var(--accent-green)]" : "sr-only"}>{message}</p>
    <div className={styles.toolbar}>
      <div className="flex items-center gap-3"><span className={styles.projectIcon}><ProjectIcon /></span><span className={styles.count}>{projects.length} projects</span></div>
      {manage && <button type="button" className={showCreate ? styles.button : styles.primary} disabled={busy} aria-expanded={showCreate} aria-controls="new-project-form" onClick={() => setShowCreate(value => !value)}>{showCreate ? "Cancel" : "+ New project"}</button>}
    </div>
    {manage && showCreate && <form id="new-project-form" onSubmit={create} className="space-y-4 rounded-xl border border-[var(--border)] bg-[var(--surface3)] p-5">
      <h2 className="font-semibold">Create project</h2>
      <label className="block text-sm">Project name<input className={`${styles.field} mt-2 w-full`} required maxLength={120} value={name} onChange={e => setName(e.target.value)} disabled={busy} /></label>
      <label className="block text-sm">Description (optional)<textarea className={`${styles.field} mt-2 w-full`} maxLength={1000} value={description} onChange={e => setDescription(e.target.value)} disabled={busy} /></label>
      <button className={styles.primary} disabled={busy || loading || !name.trim()}>{busy ? "Creating…" : "Create project"}</button>
    </form>}
    {projects.length > 0 && <label className="block"><span className="sr-only">Search projects</span><input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search projects…" className={`${styles.field} ${styles.search}`} /></label>}
    {loading ? <p role="status">Loading projects…</p> : projects.length === 0 ? <p className="text-sm">{manage ? "No projects yet. Select New project to get started." : "No projects assigned. Contact your super admin for access."}</p> : <div className="space-y-4">{projects.filter(project => `${project.name} ${project.description}`.toLowerCase().includes(search.toLowerCase())).map(project => <article key={project.id} className="space-y-3 rounded-xl border border-[var(--border)] p-4">
      <div className={styles.projectRow}><span className={styles.projectIcon}><ProjectIcon /></span><div className="min-w-0"><h2 className={styles.projectTitle}>{project.name}</h2><p className={styles.projectDescription}>{project.description || "Container security workspace"}</p></div>{manage && <button className={`${control} shrink-0`} aria-expanded={editing === project.id} onClick={() => setEditing(editing === project.id ? null : project.id)}>{editing === project.id ? "Close" : "Assign users"}</button>}</div>
      {manage && editing === project.id && <MembershipEditor key={project.id} project={project} />}
    </article>)}</div>}
    {!loading && projects.length > 0 && !projects.some(project => `${project.name} ${project.description}`.toLowerCase().includes(search.toLowerCase())) && <p role="status" className="py-6 text-center text-sm text-[var(--faint)]">No projects match your search.</p>}
  </section>;
}
