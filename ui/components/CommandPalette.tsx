"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { listScans, listProjects, type Project, type ScanSummary } from "@/lib/api";

interface Cmd {
  id: string;
  group: string;
  label: string;
  sub?: string;
  keywords?: string;
  icon: React.ReactNode;
  run: () => void;
}

const I = {
  dash: <path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />,
  scan: <><rect x="3" y="3" width="18" height="18" rx="2" /><line x1="3" y1="9" x2="21" y2="9" /></>,
  plus: <><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></>,
  gear: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>,
  folder: <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />,
  review: <><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></>,
};
function Icon({ p }: { p: React.ReactNode }) {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{p}</svg>;
}

export default function CommandPalette() {
  const router = useRouter();
  const { user, permissions } = useAuth();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const loadedRef = useRef(false);
  const openRef = useRef(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const go = useCallback((href: string) => { setOpen(false); router.push(href); }, [router]);
  const openPalette = useCallback(() => { setQuery(""); setSel(0); setOpen(true); }, []);

  useEffect(() => { openRef.current = open; }, [open]);

  // ⌘K / Ctrl+K toggles; Esc closes.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        if (openRef.current) setOpen(false); else openPalette();
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openPalette]);

  // Lazily load navigable data the first time it opens.
  useEffect(() => {
    if (!open || loadedRef.current) return;
    loadedRef.current = true;
    Promise.all([listProjects().catch(() => []), listScans().catch(() => [])])
      .then(([p, s]) => { setProjects(p); setScans(s); });
  }, [open]);

  // Focus the field when the palette opens (DOM side-effect only).
  useEffect(() => {
    if (open) { const t = setTimeout(() => inputRef.current?.focus(), 20); return () => clearTimeout(t); }
  }, [open]);

  const commands = useMemo<Cmd[]>(() => {
    const p = permissions;
    const nav: Cmd[] = [
      { id: "nav-dash", group: "Navigate", label: "Dashboard", keywords: "home", icon: <Icon p={I.dash} />, run: () => go("/dashboard") },
      { id: "nav-scans", group: "Navigate", label: "All scans", keywords: "images runs", icon: <Icon p={I.scan} />, run: () => go("/scans") },
    ];
    if (p?.canScan) nav.push({ id: "act-newscan", group: "Actions", label: "New scan", sub: "Scan a container image", keywords: "create run", icon: <Icon p={I.plus} />, run: () => go("/new-scan") });
    if (p?.canApprove) {
      const firstAwaiting = scans.find((s) => s.status === "awaiting_approval");
      nav.push({ id: "act-review", group: "Actions", label: "Open review queue", sub: firstAwaiting ? `Next: ${firstAwaiting.image}` : "Nothing awaiting", keywords: "approve findings", icon: <Icon p={I.review} />, run: () => go(firstAwaiting ? `/review?run=${firstAwaiting.id}` : "/scans") });
    }
    if (p?.canViewSettings) nav.push({ id: "nav-settings", group: "Navigate", label: "Settings", keywords: "projects users roles preferences", icon: <Icon p={I.gear} />, run: () => go("/settings") });

    const projCmds: Cmd[] = projects.map((pr) => ({
      id: `proj-${pr.id}`, group: "Projects", label: pr.name, sub: pr.description || "Open project scans",
      keywords: "project workspace", icon: <Icon p={I.folder} />, run: () => go(`/scans?project=${pr.id}`),
    }));
    const scanCmds: Cmd[] = scans.slice(0, 40).map((s) => ({
      id: `scan-${s.id}`, group: "Scans", label: s.image, sub: `#${s.seq} · ${projects.find((p) => p.id === s.project)?.name ?? s.project} · ${s.totalCves} findings`,
      keywords: `${s.project} ${s.status} review`, icon: <Icon p={I.scan} />, run: () => go(`/review?run=${s.id}`),
    }));
    return [...nav, ...projCmds, ...scanCmds];
  }, [permissions, projects, scans, go]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => `${c.label} ${c.sub ?? ""} ${c.keywords ?? ""}`.toLowerCase().includes(q));
  }, [commands, query]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${sel}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); filtered[sel]?.run(); }
  };

  if (!user) return null;

  // Group the filtered results, preserving first-seen group order.
  const groups: { name: string; items: { cmd: Cmd; idx: number }[] }[] = [];
  filtered.forEach((cmd, idx) => {
    let g = groups.find((x) => x.name === cmd.group);
    if (!g) { g = { name: cmd.group, items: [] }; groups.push(g); }
    g.items.push({ cmd, idx });
  });

  return (
    <>
      {/* Trigger affordance in the nav */}
      <button
        onClick={openPalette}
        className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg text-[12px] transition-colors"
        style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--muted)" }}
        title="Command palette (⌘K)"
      >
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
        Search
        <kbd className="ml-1 text-[10px] font-sans font-semibold px-1.5 py-0.5 rounded" style={{ background: "var(--surface3)", border: "1px solid var(--border)", color: "var(--faint)" }}>⌘K</kbd>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[100] flex items-start justify-center ct-fade-in"
          style={{ background: "rgba(0,0,0,0.55)", backdropFilter: "blur(4px)", paddingTop: "12vh" }}
          onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
        >
          <div className="w-full max-w-xl mx-4 rounded-2xl overflow-hidden ct-fade-up" style={{ background: "var(--surface)", border: "1px solid var(--border2)", boxShadow: "var(--shadow-pop)" }}>
            {/* Search field */}
            <div className="flex items-center gap-3 px-4" style={{ borderBottom: "1px solid var(--border)" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="2" strokeLinecap="round" className="flex-shrink-0"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => { setQuery(e.target.value); setSel(0); }}
                onKeyDown={onInputKey}
                placeholder="Jump to a scan, project, or action…"
                className="flex-1 bg-transparent outline-none py-3.5 text-[14px]"
                style={{ color: "var(--heading)" }}
              />
              <kbd className="text-[10px] font-semibold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: "var(--surface3)", border: "1px solid var(--border)", color: "var(--faint)" }}>ESC</kbd>
            </div>

            {/* Results */}
            <div ref={listRef} className="max-h-[52vh] overflow-y-auto py-2">
              {filtered.length === 0 && (
                <div className="px-4 py-8 text-center text-[13px]" style={{ color: "var(--muted)" }}>No matches for “{query}”.</div>
              )}
              {groups.map((g) => (
                <div key={g.name} className="px-2">
                  <div className="px-3 pt-2 pb-1 text-[10px] font-bold uppercase tracking-wider" style={{ color: "var(--dim)" }}>{g.name}</div>
                  {g.items.map(({ cmd, idx }) => {
                    const active = idx === sel;
                    return (
                      <button
                        key={cmd.id}
                        data-idx={idx}
                        onMouseEnter={() => setSel(idx)}
                        onClick={() => cmd.run()}
                        className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors"
                        style={{ background: active ? "var(--surface2)" : "transparent" }}
                      >
                        <span className="grid place-items-center w-7 h-7 rounded-lg flex-shrink-0" style={{ background: active ? "var(--accent-blue-bg)" : "var(--surface3)", color: active ? "var(--accent-blue)" : "var(--muted)", border: "1px solid var(--border)" }}>
                          {cmd.icon}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block text-[13px] font-semibold truncate" style={{ color: "var(--heading)" }}>{cmd.label}</span>
                          {cmd.sub && <span className="block text-[11px] truncate" style={{ color: "var(--muted)" }}>{cmd.sub}</span>}
                        </span>
                        {active && <span className="text-[11px] flex-shrink-0" style={{ color: "var(--dim)" }}>↵</span>}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
