"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { Theme } from "@/lib/themes";

interface ThemeCtx {
  theme: Theme;
  setTheme: (t: Theme) => void;
  isAuto: boolean;  // true when following the time-of-day rule
}

const Ctx = createContext<ThemeCtx>({ theme: "dark", setTheme: () => {}, isAuto: true });

/** 06:00–18:00 local time → light, otherwise → dark */
function timeOfDayTheme(): Theme {
  const hour = new Date().getHours();
  return hour >= 6 && hour < 18 ? "light" : "dark";
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState]   = useState<Theme>("dark");
  const [isAuto, setIsAuto]      = useState(true);

  // Apply theme to <html> element
  const applyTheme = (t: Theme) => {
    document.documentElement.setAttribute("data-theme", t);
    setThemeState(t);
  };

  // Manual override — saves to localStorage and disables auto
  const setTheme = (t: Theme) => {
    applyTheme(t);
    setIsAuto(false);
    localStorage.setItem("ct-theme", t);
    localStorage.setItem("ct-theme-auto", "false");
  };

  // On mount: restore saved preference or default to time-of-day
  useEffect(() => {
    const saved     = localStorage.getItem("ct-theme") as Theme | null;
    const autoFlag  = localStorage.getItem("ct-theme-auto");
    const userPinned = autoFlag === "false" && saved;

    const resolved = userPinned ? saved! : timeOfDayTheme();
    applyTheme(resolved);
    setIsAuto(!userPinned);
  }, []);

  // Re-check time-of-day every minute when in auto mode
  useEffect(() => {
    if (!isAuto) return;
    const tick = () => {
      const tod = timeOfDayTheme();
      if (tod !== theme) applyTheme(tod);
    };
    const id = setInterval(tick, 60_000);
    return () => clearInterval(id);
  }, [isAuto, theme]);

  return <Ctx.Provider value={{ theme, setTheme, isAuto }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
