"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "@/lib/auth";
import { ROLE_LABELS, type UserRole } from "@/lib/types";
import { listUsers, createPlatformUser, updatePlatformUser, type PlatformUser, type UpdateUserPayload } from "@/lib/api";

const roles = Object.keys(ROLE_LABELS) as UserRole[];
const descriptions: Record<UserRole, string> = {
  ADMIN: "Scan, review findings, and manage users.",
  DEVOPS_ENGINEER: "Start scans and view findings.",
  CYBER_MANAGER: "Review findings and access settings.",
};
const control = "w-full min-h-11 rounded-lg border border-[var(--border2)] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--body)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent-blue)] disabled:opacity-60";
const button = "min-h-11 rounded-lg border border-[var(--border2)] px-3 py-2 text-sm font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent-blue)] disabled:opacity-60 disabled:cursor-not-allowed";
const emptyDraft = { name: "", email: "", password: "", role: "DEVOPS_ENGINEER" as UserRole };

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
      setSuccess(payload.role ? `${updated.name} is now a ${ROLE_LABELS[updated.role]}.`
        : `${updated.name} ${updated.is_active ? "activated" : "deactivated"}.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update user.");
    } finally { pending.current = false; setBusy(null); }
  }

  useEffect(() => {
    if (success.startsWith("Created ")) createButtonRef.current?.focus();
  }, [success]);

  if (!allowed) return <p role="status" className="text-sm text-[var(--body)]">Only administrators can manage users.</p>;

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
          <button ref={createButtonRef} className={button} onClick={() => { setShowCreate(!showCreate); setDraft(emptyDraft); setError(null); setSuccess(""); }} disabled={busy !== null} aria-expanded={showCreate} aria-controls="create-user-form">{showCreate ? "Cancel" : "Create user"}</button>
        </div>
        {showCreate && <form id="create-user-form" onSubmit={create} aria-busy={busy === "create"} className="space-y-4 rounded-xl border border-[var(--border)] p-4">
          <h2 className="text-sm font-semibold">Create user</h2>
          <p className="text-xs text-[var(--faint)]">Creates an account immediately. Share the password securely; no invitation email is sent.</p>
          <fieldset disabled={busy !== null} className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-1 text-sm">Name<input className={control} name="name" autoComplete="off" required value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
            <label className="space-y-1 text-sm">Email<input className={control} name="email" type="email" autoComplete="off" autoCapitalize="none" spellCheck={false} required value={draft.email} onChange={(e) => setDraft({ ...draft, email: e.target.value })} /></label>
            <label className="space-y-1 text-sm"><span id="new-user-password-label">Password</span><input aria-labelledby="new-user-password-label" className={control} name="password" type="password" autoComplete="new-password" required minLength={8} aria-describedby="new-password-help" value={draft.password} onChange={(e) => setDraft({ ...draft, password: e.target.value })} /><span id="new-password-help" className="text-xs text-[var(--faint)]">At least 8 characters.</span></label>
            <label className="space-y-1 text-sm"><span id="new-user-role-label">Role</span><select aria-labelledby="new-user-role-label" className={control} value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value as UserRole })}>{roles.map((role) => <option key={role} value={role}>{ROLE_LABELS[role]}</option>)}</select></label>
          </fieldset>
          <button type="submit" disabled={busy !== null} className={`${button} bg-[var(--btn-accept-bg)] text-[var(--btn-accept-text)] hover:opacity-90`}>{busy === "create" ? "Creating…" : "Create account"}</button>
        </form>}
        <div className="flex flex-wrap gap-x-5 gap-y-3 text-xs text-[var(--faint)]">{roles.map((role) => <div key={role}><strong className="text-[var(--body)]">{ROLE_LABELS[role]}</strong><p className="mt-1">{descriptions[role]}</p></div>)}</div>
        <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
          <table className="w-full min-w-[520px] text-left text-sm">
            <caption className="sr-only">Workspace users and role and account status controls</caption>
            <thead className="bg-[var(--surface2)] text-xs text-[var(--faint)]"><tr><th scope="col" className="p-3">User</th><th scope="col" className="p-3">Role</th><th scope="col" className="p-3">Status</th></tr></thead>
            <tbody>{users.map((account) => {
              const self = account.id === user?.id;
              return <tr key={account.id} aria-busy={busy === account.id} className="border-t border-[var(--border)]">
                <th scope="row" className="p-3 font-normal"><div className="font-semibold text-[var(--heading)]">{account.name}{self && <span className="ml-2 text-xs font-normal text-[var(--faint)]">(you)</span>}</div><div className="mt-1 break-all text-xs text-[var(--faint)]">{account.email}</div></th>
                <td className="p-3"><select aria-label={`Role for ${account.email}`} aria-describedby={self ? "self-account-help" : undefined} className={control} value={account.role} disabled={self || busy !== null} onChange={(e) => update(account, { role: e.target.value as UserRole })}>{roles.map((role) => <option key={role} value={role}>{ROLE_LABELS[role]}</option>)}</select></td>
                <td className="p-3"><button type="button" className={button} role="switch" aria-checked={Boolean(account.is_active)} aria-label={`Account active for ${account.email}`} aria-describedby={self ? "self-account-help" : undefined} disabled={self || busy !== null} onClick={() => update(account, { is_active: !account.is_active })}>{account.is_active ? "Active" : "Inactive"}</button></td>
              </tr>;
            })}</tbody>
          </table>
          {users.length === 0 && <p className="p-4 text-sm">No users found.</p>}
        </div>
        <p id="self-account-help" className="text-xs text-[var(--faint)]">Your own admin role and active status cannot be changed here.</p>
        <p role="status" className="text-sm">{busy && busy !== "create" ? "Saving changes…" : ""}</p>
      </>}
    </div>
  </section>;
}
