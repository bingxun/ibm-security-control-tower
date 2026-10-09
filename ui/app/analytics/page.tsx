"use client";

import { useEffect, useMemo, useState } from "react";
import RequireAuth from "@/components/RequireAuth";
import { HomeShell, StatCard, StatGrid } from "@/components/home/HomeKit";
import { HBarChart, AreaChart, ChartCard } from "@/components/analytics/charts";
import { listScans, getDashboardStats, type ScanSummary, type DashboardStats } from "@/lib/api";

const EMPTY: DashboardStats = { totalScans: 0, cvesTriaged: 0, avgApprovalRate: 0, ragDecisions: 0, ragFirstPassRate: 0, autoApproved: 0 };

const fmtDate = (iso: string) => {
  const d = new Date(`${iso}T00:00:00`);
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

function AnalyticsInner() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<DashboardStats>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listScans(), getDashboardStats()])
      .then(([s, d]) => { if (!cancelled) { setScans(s); setStats(d); } })
      .catch((e) => { if (!cancelled) setError(e?.message ?? "Failed to load analytics"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const severity = useMemo(() => {
    let c = 0, h = 0, m = 0, l = 0;
    for (const s of scans) { c += s.critical; h += s.high; m += s.medium; l += Math.max(0, s.totalCves - s.critical - s.high - s.medium); }
    return [
      { label: "Critical", value: c, color: "var(--accent-red)" },
      { label: "High", value: h, color: "var(--accent-orange)" },
      { label: "Medium", value: m, color: "var(--accent-yellow)" },
      { label: "Low", value: l, color: "var(--accent-green)" },
    ];
  }, [scans]);

  const funnel = useMemo(() => {
    let a = 0, r = 0, total = 0;
    for (const s of scans) { a += s.approved; r += s.rejected; total += s.totalCves; }
    const open = Math.max(0, total - a - r);
    return [
      { label: "Approved", value: a, color: "var(--accent-green)" },
      { label: "Rejected", value: r, color: "var(--accent-red)" },
      { label: "Open", value: open, color: "var(--accent-blue)" },
    ];
  }, [scans]);

  const activity = useMemo(() => {
    const byDate = new Map<string, number>();
    for (const s of scans) byDate.set(s.date, (byDate.get(s.date) ?? 0) + 1);
    return [...byDate.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([date, count]) => ({ label: fmtDate(date), value: count }));
  }, [scans]);

  const byProject = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of scans) map.set(s.project, (map.get(s.project) ?? 0) + s.totalCves);
    const sorted = [...map.entries()].sort(([, a], [, b]) => b - a);
    const top = sorted.slice(0, 8);
    const rest = sorted.slice(8).reduce((n, [, v]) => n + v, 0);
    const rows = top.map(([label, value]) => ({ label, value, color: "var(--accent-blue)" }));
    if (rest > 0) rows.push({ label: "Other", value: rest, color: "var(--dim)" });
    return rows;
  }, [scans]);

  const autonomyPct = stats.cvesTriaged > 0 ? Math.round((stats.autoApproved / stats.cvesTriaged) * 100) : 0;

  return (
    <HomeShell>
      <div>
        <h1 className="text-[26px] font-black tracking-tight" style={{ color: "var(--heading)" }}>Analytics</h1>
        <p className="text-[14px] mt-1" style={{ color: "var(--subtle)" }}>Scan volume, finding severity, and review throughput across your assigned projects.</p>
      </div>

      {error ? (
        <div className="rounded-2xl px-6 py-10 text-center text-[13px]" style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--accent-red)" }}>{error}</div>
      ) : (
        <>
          <StatGrid>
            <StatCard value={String(stats.totalScans)} label="Total scans" sub="all time" color="var(--accent-blue)" />
            <StatCard value={stats.cvesTriaged.toLocaleString()} label="CVEs triaged" sub="across scans" color="var(--accent-purple)" />
            <StatCard value={`${stats.avgApprovalRate}%`} label="Approval rate" sub="first-pass" color="var(--accent-green)" />
            <StatCard value={`${autonomyPct}%`} label="Autonomy" sub={`${stats.autoApproved} auto-approved`} color="var(--accent-orange)" />
          </StatGrid>

          <ChartCard title="Scan activity" subtitle={loading ? "Loading…" : `${activity.length} active ${activity.length === 1 ? "day" : "days"}`}>
            {activity.length > 0 ? <AreaChart data={activity} /> : <Empty loading={loading} />}
          </ChartCard>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <ChartCard title="Findings by severity" subtitle="Aggregated across all scans">
              {scans.length > 0 ? <HBarChart data={severity} /> : <Empty loading={loading} />}
            </ChartCard>
            <ChartCard title="Review funnel" subtitle="Human decisions on findings">
              {scans.length > 0 ? <HBarChart data={funnel} /> : <Empty loading={loading} />}
            </ChartCard>
          </div>

          <ChartCard title="Findings by project" subtitle="Where the risk concentrates">
            {byProject.length > 0 ? <HBarChart data={byProject} /> : <Empty loading={loading} />}
          </ChartCard>
        </>
      )}
    </HomeShell>
  );
}

function Empty({ loading }: { loading: boolean }) {
  return <p className="text-[12px] py-6 text-center" style={{ color: "var(--dim)" }}>{loading ? "Loading…" : "No scans yet."}</p>;
}

export default function AnalyticsPage() {
  return (
    <RequireAuth>
      <AnalyticsInner />
    </RequireAuth>
  );
}
