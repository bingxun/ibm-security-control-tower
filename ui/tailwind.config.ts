import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg:       "#0a0c10",
        surface:  "#111318",
        surface2: "#181c23",
        border:   "#22272e",
        border2:  "#2d333b",
        dim:      "#3d444d",
        muted:    "#6e7681",
        subtle:   "#8b949e",
        text:     "#e6edf3",
        body:     "#c9d1d9",
        green:    "#3fb950",
        red:      "#f85149",
        yellow:   "#d29922",
        blue:     "#4493f8",
        purple:   "#a371f7",
      },
      fontFamily: {
        mono: ['"SF Mono"', '"Fira Code"', '"Consolas"', "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
