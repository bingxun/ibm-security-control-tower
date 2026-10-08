"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import styles from "./Management.module.css";
import { useAuth } from "@/lib/auth";
import { ROLE_LABELS, ROLE_COLORS, type UserRole } from "@/lib/types";
import { listUsers, createPlatformUser, updatePlatformUser, type PlatformUser, type UpdateUserPayload } from "@/lib/api";

const roles = Object.keys(ROLE_LABELS) as UserRole[];
const descriptions: Record<UserRole, string> = {
  SUPER_ADMIN: "Manage all projects, memberships, and users.",
  ADMIN: "Scan and review within assigned projects.",
  DEVOPS_ENGINEER: "Start scans and view findings.",
  CYBER_MANAGER: "Review findings and access settings.",
  DSO_MANAGER: "Submit decisions on findings and access settings (cannot reject).",
};
const control = styles.field;
const button = styles.button;
const emptyDraft = { name: "", email: "", password: "", roles: ["DEVOPS_ENGINEER"] as UserRole[] };

/** A compact toggle-chip group for selecting one or more roles. Always keeps ≥1 selected. */
function RolePicker({ value, onChange, disabled, idPrefix }: { value: UserRole[]; onChange: (roles: UserRole[]) => void; disabled?: boolean; idPrefix: string }) {
  const toggle = (role: UserRole) => {
    const has = value.includes(role);
    if (has && value.length === 1) return; // keep at least one role
    onChange(has ? value.filter((r) => r !== role) : [...value, role]);
  };
  return (
    <div role="group" aria-label="Roles" className="flex flex-wrap gap-1.5">
      {roles.map((role) => {
        const c = ROLE_COLORS[role];
        const on = value.includes(role);
        return (
          <button
            key={role}
            type="button"
            id={`${idPrefix}-${role}`}
            aria-pressed={on}
            disabled={disabled}
            onClick={() => toggle(role)}
            className="text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-opacity disabled:cursor-not-allowed disabled:opacity-60"
            style={on
              ? { background: c.bg, color: c.text, borderColor: c.border }
              : { background: "transparent", color: "var(--muted)", borderColor: "var(--border2)" }}
          >
            {ROLE_LABELS[role]}
          </button>
        );
      })}
    </div>
  );
}

export default function UsersSettings() {
  const { user, permissions } = useAuth();
  const allowed = permissions?.canManageUsers === true;
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState("");
  const [reload, setReload] = useState(0);
  const [draft, setDraft] = useState(emptyDraft);
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const pending = useRef(false);
  const errorRef = useRef<HTMLDivElement>(null);
  const createButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!allowed) return;
    const controller = new AbortController();
    listUsers(controller.signal).then((items) => {
      if (!controller.signal.aborted) setUsers(items);
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) setLoadError(cause instanceof Error ? cause.message : "Unable to load users.");
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [allowed, reload]);

  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  function refresh() {
    setLoading(true); setLoadError(null); setError(null); setSuccess("");
    setReload((value) => value + 1);
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!allowed || pending.current) return;
    if (!draft.name.trim()) { setError("Enter a name for the user."); return; }
    pending.current = true;
    setBusy("create"); setError(null); setSuccess("");
    try {
      const created = await createPlatformUser({ ...draft, name: draft.name.trim(), email: draft.email.trim() });
      setUsers((items) => [created, ...items]);
      setDraft(emptyDraft); setShowCreate(false);
      setSuccess(`Created ${created.name}. The account is ready to sign in.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create user.");
    } finally { pending.current = false; setBusy(null); }
  }

  async function update(account: PlatformUser, payload: UpdateUserPayload) {
    if (!allowed || pending.current || account.id === user?.id) return;
    pending.current = true;
    setBusy(account.id); setError(null); setSuccess("");
    try {
      const updated = await updatePlatformUser(account.id, payload);
      setUsers((items) => items.map((item) => item.id === updated.id ? updated : item));
      setSuccess(payload.roles ? `${updated.name} is now ${updated.roles.map(r => ROLE_LABELS[r]).join(", ")}.`
        : `${updated.name} ${updated.is_active ? "activated" : "deactivated"}.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update user.");
    } finally { pending.current = false; setBusy(null); }
  }

  useEffect(() => {
    if (success.startsWith("Created ")) createButtonRef.current?.focus();
  }, [success]);

  if (!allowed) return <p role="status" className="text-sm text-[var(--body)]">Only super admins can manage users.</p>;

  return <section aria-labelledby="users-heading" className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] text-[var(--body)]">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] px-6 py-4">
      <div><h1 id="users-heading" className="text-base font-bold text-[var(--heading)]">Users &amp; Roles</h1><p className="mt-1 text-xs text-[var(--faint)]">Manage workspace accounts and access.</p></div>
      <button type="button" className={button} onClick={refresh} disabled={loading || busy !== null}>Refresh</button>
    </header>
    <div className="space-y-5 p-6">
      {loading && <p role="status" className="text-sm">Loading users…</p>}
      {loadError && <div role="alert" className="space-y-3 rounded-xl border border-[var(--accent-red)] bg-[var(--accent-red-bg)] p-4 text-sm"><p>{loadError}</p><button className={button} onClick={refresh}>Try again</button></div>}
      {error && <div ref={errorRef} tabIndex={-1} role="alert" className="rounded-xl border border-[var(--accent-red)] bg-[var(--accent-red-bg)] p-4 text-sm focus-visible:outline-2 focus-visible:outline-[var(--accent-blue)]">{error}</div>}
      <p role="status" className={success ? "rounded-xl bg-[var(--accent-green-bg)] p-3 text-sm" : "sr-only"}>{success}</p>
      {!loading && !loadError && <>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-[var(--faint)]">{users.length} {users.length === 1 ? "user" : "users"}</p>
          <button ref={createButtonRef} className={showCreate ? button : styles.primary} onClick={() => { setShowCreate(!showCreate); setDraft(emptyDraft); setError(null); setSuccess(""); }} disabled={busy !== null} aria-expanded={showCreate} aria-controls="create-user-form">{showCreate ? "Cancel" : "Create user"}</button>
        </div>
        {showCreate && <form id="create-user-form" onSubmit={create} aria-busy={busy === "create"} className="space-y-4 rounded-xl border border-[var(--border)] p-4">
          <h2 className="text-sm font-semibold">Create user</h2>
          <p className="text-xs text-[var(--faint)]">Creates an account immediately. Share the password securely; no invitation email is sent.</p>
          <fieldset disabled={busy !== null} className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-1 text-sm">Name<input className={control} name="name" autoComplete="off" required value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
            <label className="space-y-1 text-sm">Email<input className={control} name="email" type="email" autoComplete="off" autoCapitalize="none" spellCheck={false} required value={draft.email} onChange={(e) => setDraft({ ...draft, email: e.target.value })} /></label>
            <label className="space-y-1 text-sm"><span id="new-user-password-label">Password</span><input aria-labelledby="new-user-password-label" className={control} name="password" type="password" autoComplete="new-password" required minLength={8} aria-describedby="new-password-help" value={draft.password} onChange={(e) => setDraft({ ...draft, password: e.target.value })} /><span id="new-password-help" className="text-xs text-[var(--faint)]">At least 8 characters.</span></label>
            <div className="space-y-1.5 text-sm sm:col-span-2"><span>Roles <span className="text-[var(--faint)]">(one or more)</span></span><RolePicker idPrefix="new-user-role" value={draft.roles} onChange={(roles) => setDraft({ ...draft, roles })} disabled={busy !== null} /></div>
          </fieldset>
          <button type="submit" disabled={busy !== null} className={`${button} bg-[var(--btn-accept-bg)] text-[var(--btn-accept-text)] hover:opacity-90`}>{busy === "create" ? "Creating…" : "Create account"}</button>
        </form>}
        <details className="rounded-xl border border-[var(--border)]"><summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-[var(--faint)]">Role permissions</summary><div className={styles.roleLegend}>{roles.map((role) => <div key={role}><strong className="flex items-center gap-2 text-[var(--body)]"><span aria-hidden="true" className="inline-block h-2 w-2 rounded-full" style={{ background: ROLE_COLORS[role].text }} />{ROLE_LABELS[role]}</strong><p className="mt-1">{descriptions[role]}</p></div>)}</div></details>
        <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
          <table className={`${styles.table} w-full min-w-[600px] text-left text-sm`}>
            <caption className="sr-only">Workspace users and role and account status controls</caption>
            <thead className="bg-[var(--surface2)] text-xs text-[var(--faint)]"><tr><th scope="col" className="p-3">User</th><th scope="col" className="p-3">Role</th><th scope="col" className="p-3">Status</th></tr></thead>
            <tbody>{users.map((account) => {
              const self = account.id === user?.id;
              return <tr key={account.id} aria-busy={busy === account.id} className="border-t border-[var(--border)]">
                <th scope="row" className="p-3 font-normal"><div className="flex items-center gap-3"><span className={styles.avatar} aria-hidden="true">{account.name.split(" ").map(part => part[0]).slice(0, 2).join("").toUpperCase()}</span><div><div className="font-semibold text-[var(--heading)]">{account.name}{self && <span className="ml-2 text-xs font-normal text-[var(--faint)]">(you)</span>}</div><div className="mt-1 break-all text-xs text-[var(--faint)]">{account.email}</div></div></div></th>
                <td className="p-3"><RolePicker idPrefix={`role-${account.id}`} value={account.roles} onChange={(roles) => update(account, { roles })} disabled={self || busy !== null} /></td>
                <td className="p-3"><button type="button" className={styles.status} role="switch" aria-checked={Boolean(account.is_active)} aria-label={`Account active for ${account.email}`} aria-describedby={self ? "self-account-help" : undefined} disabled={self || busy !== null} onClick={() => update(account, { is_active: !account.is_active })}>{account.is_active ? "Active" : "Inactive"}</button></td>
              </tr>;
            })}</tbody>
          </table>
          {users.length === 0 && <p className="p-4 text-sm">No users found.</p>}
        </div>
        <p id="self-account-help" className="text-xs text-[var(--faint)]">Your own super admin role and active status cannot be changed here.</p>
        <p role="status" className="text-sm">{busy && busy !== "create" ? "Saving changes…" : ""}</p>
      </>}
    </div>
  </section>;
}
