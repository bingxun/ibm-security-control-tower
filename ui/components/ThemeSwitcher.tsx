"use client";

import { useState, useRef, useEffect } from "react";
import { THEMES } from "@/lib/themes";
import { useTheme } from "./ThemeProvider";

export default function ThemeSwitcher() {
  const { theme, setTheme, isAuto } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const current = THEMES.find((t) => t.id === theme)!;

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const resetToAuto = () => {
    localStorage.removeItem("ct-theme");
    localStorage.setItem("ct-theme-auto", "true");
    // Re-apply time-of-day immediately
    const hour = new Date().getHours();
    setTheme(hour >= 6 && hour < 18 ? "light" : "dark");
    // Override isAuto back — hack: clear the pinned flag then reload logic
    localStorage.removeItem("ct-theme-auto");
    setOpen(false);
    window.location.reload(); // simplest way to re-trigger the mount effect cleanly
  };

  return (
    <div className="relative" ref={ref}>
      {/* Trigger */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-opacity hover:opacity-80"
        style={{
          background: "var(--surface2)",
          border:     "1px solid var(--border)",
          color:      "var(--faint)",
        }}
      >
        <span>{current.icon}</span>
        <span>{current.label}</span>
        {isAuto && (
          <span
            className="text-[9px] font-bold px-1 py-0.5 rounded uppercase tracking-wide"
            style={{ background: "var(--accent-blue-bg)", color: "var(--accent-blue)", border: "1px solid rgba(68,147,248,0.2)" }}
          >
            Auto
          </span>
        )}
        <svg
          width="10" height="10" viewBox="0 0 10 10" fill="none"
          style={{
            transform:  open ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.15s",
            color:      "var(--muted)",
          }}
        >
          <path d="M2 3.5L5 6.5L8 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>

      {/* Dropdown */}
      {open && (
        <div
          className="absolute right-0 top-full mt-1.5 rounded-xl overflow-hidden z-50"
          style={{
            background: "var(--surface)",
            border:     "1px solid var(--border)",
            boxShadow:  "0 8px 24px rgba(0,0,0,0.3)",
            minWidth:   "180px",
          }}
        >
          <div
            className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: "var(--muted)", borderBottom: "1px solid var(--border)" }}
          >
            Appearance
          </div>

          {/* Auto option */}
          <button
            onClick={resetToAuto}
            className="w-full flex items-center gap-3 px-3 py-2.5 text-left text-[13px] transition-colors"
            style={{
              background: isAuto ? "var(--surface2)" : "transparent",
              color:      isAuto ? "var(--heading)" : "var(--subtle)",
            }}
            onMouseEnter={(e) => { if (!isAuto) e.currentTarget.style.background = "var(--surface2)"; }}
            onMouseLeave={(e) => { if (!isAuto) e.currentTarget.style.background = "transparent"; }}
          >
            <span className="text-[14px] w-5 text-center">🕐</span>
            <div className="flex-1">
              <div className="font-medium">Auto</div>
              <div className="text-[10px]" style={{ color: "var(--muted)" }}>Light 6am–6pm · Dark 6pm–6am</div>
            </div>
            {isAuto && (
              <svg className="ml-auto" width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M2 6L5 9L10 3" stroke="var(--accent-green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            )}
          </button>

          {/* Manual overrides */}
          {THEMES.map((t) => {
            const isActive = !isAuto && t.id === theme;
            return (
              <button
                key={t.id}
                onClick={() => { setTheme(t.id); setOpen(false); }}
                className="w-full flex items-center gap-3 px-3 py-2.5 text-left text-[13px] transition-colors"
                style={{
                  background: isActive ? "var(--surface2)" : "transparent",
                  color:      isActive ? "var(--heading)" : "var(--subtle)",
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = "var(--surface2)"; }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
              >
                <span className="text-[14px] w-5 text-center">{t.icon}</span>
                <span className="font-medium">{t.label}</span>
                {isActive && (
                  <svg className="ml-auto" width="12" height="12" viewBox="0 0 12 12" fill="none">
                    <path d="M2 6L5 9L10 3" stroke="var(--accent-green)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                )}
              </button>
            );
          })}

          {/* Preview swatches */}
          <div className="px-3 py-2.5 flex gap-2" style={{ borderTop: "1px solid var(--border)" }}>
            {THEMES.map((t) => (
              <button
                key={t.id}
                onClick={() => { setTheme(t.id); setOpen(false); }}
                title={t.label}
                className="flex-1 h-6 rounded-md transition-transform hover:scale-105"
                style={{
                  background:
                    t.id === "dark"  ? "linear-gradient(135deg, #080b10 50%, #238636 100%)" :
                    t.id === "light" ? "linear-gradient(135deg, #f0f2f5 50%, #1a7f37 100%)" :
                                       "linear-gradient(135deg, #000 50%, #00ff41 100%)",
                  border: (!isAuto && t.id === theme)
                    ? "2px solid var(--accent-purple)"
                    : "1px solid var(--border)",
                }}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
