"use client";

import RequireAuth from "@/components/RequireAuth";
import Home from "@/components/home/Home";

export default function DashboardPage() {
  return (
    <RequireAuth>
      <Home />
    </RequireAuth>
  );
}
