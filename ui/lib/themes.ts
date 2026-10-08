export type Theme = "dark" | "light" | "hc";

export const THEMES: { id: Theme; label: string; icon: string }[] = [
  { id: "dark",  label: "Dark",           icon: "🌙" },
  { id: "light", label: "Light",          icon: "☀️" },
  { id: "hc",    label: "High Contrast",  icon: "◑"  },
];
