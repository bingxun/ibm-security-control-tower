import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable standalone output for Docker builds.
  // Vercel sets VERCEL=1 automatically, so standalone is skipped there.
  ...(process.env.VERCEL ? {} : { output: "standalone" }),
};

export default nextConfig;
