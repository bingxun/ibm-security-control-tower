"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { Theme } from "@/lib/themes";

interface ThemeCtx {
  theme: Theme;
  setTheme: (t: Theme) => void;
}

const Ctx = createContext<ThemeCtx>({ theme: "dark", setTheme: () => {} });

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");

  // Persist to localStorage and apply to <html>
  const setTheme = (t: Theme) => {
    setThemeState(t);
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem("ct-theme", t);
  };

  // Hydrate from localStorage on mount, falling back to time-of-day default
  useEffect(() => {
    const saved = localStorage.getItem("ct-theme") as Theme | null;
    const resolved = saved ?? "light";
    setThemeState(resolved);
    document.documentElement.setAttribute("data-theme", resolved);
  }, []);

  return <Ctx.Provider value={{ theme, setTheme }}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
