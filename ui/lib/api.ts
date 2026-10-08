/**
 * Thin API client — wraps every backend call in one place.
 * Falls back gracefully when the backend is unreachable.
 */

import type { CveRecord, AgentStep, RunStats } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ScanPayload {
  imageRef: string;
  projectId: string;
  cisProfile: string;
  severityThreshold: string;
  scanner: string;
  autoApproveBelow: string;
  trivyJson?: object;
}

export interface ScanRun {
  run_id: string;
  status: "queued" | "scanning" | "running" | "awaiting_approval" | "completed" | "error";
  image_ref: string;
  project_id: string;
  started_at: string;
  cves: CveRecord[];
  agent_steps: AgentStep[];
  stats: RunStats;
  token_fragment: string;
  trivy_logs: string[];
}

export interface ScanSummary {
  id: string;
  project: string;
  image: string;
  date: string;
  totalCves: number;
  critical: number;
  high: number;
  medium: number;
  approved: number;
  rejected: number;
  status: "completed" | "running" | "error";
  duration: string;
}

export interface DashboardStats {
  totalScans: number;
  cvesTriaged: number;
  avgApprovalRate: number;
  ragDecisions: number;
  ragFirstPassRate: number;
}

export interface DecisionPayload {
  cve_id: string;
  decision: "approved" | "rejected";
  edited_rationale?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function post<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`POST ${path} failed: ${res.status} — ${text}`);
  }
  return res.json();
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`GET ${path} failed: ${res.status} — ${text}`);
  }
  return res.json();
}

// ── API calls ──────────────────────────────────────────────────────────────

/** Run Trivy against a remote image on the backend. Returns the raw trivyJson. */
export async function scanImage(imageRef: string): Promise<{ trivyJson: object; totalVulnerabilities: number }> {
  return post("/scan-image", { imageRef });
}

export type TrivyScanEvent =
  | { type: "log";   line: string }
  | { type: "done";  trivyJson: object; totalVulnerabilities: number }
  | { type: "error"; detail: string };

/**
 * Stream Trivy scan progress via SSE.
 * Calls onEvent for each parsed event, returns a cleanup function.
 */
export function streamScanImage(
  imageRef: string,
  onEvent: (e: TrivyScanEvent) => void,
  onDone: (trivyJson: object, total: number) => void,
  onError: (msg: string) => void,
): () => void {
  const url = `${BASE}/scan-image/stream?imageRef=${encodeURIComponent(imageRef)}`;
  const es = new EventSource(url);

  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data) as TrivyScanEvent;
      onEvent(data);
      if (data.type === "done") {
        es.close();
        onDone(data.trivyJson, data.totalVulnerabilities);
      } else if (data.type === "error") {
        es.close();
        onError(data.detail);
      }
    } catch { /* ignore malformed lines */ }
  };

  es.onerror = () => {
    es.close();
    onError("SSE connection lost");
  };

  return () => es.close();
}

/** Start a new scan run. Returns the run_id. */
export async function startScan(payload: ScanPayload): Promise<{ run_id: string }> {
  return post("/scan", payload);
}

/** Fetch the current state of a run (polling fallback). */
export async function getRun(runId: string): Promise<ScanRun> {
  return get(`/run/${runId}`);
}

/** Submit a human decision for a CVE in the given run. */
export async function submitDecision(
  runId: string,
  payload: DecisionPayload
): Promise<void> {
  await post(`/run/${runId}/decision`, payload);
}

/** Fetch past scan summaries for the dashboard. */
export async function listScans(): Promise<ScanSummary[]> {
  return get("/scans");
}

/** Fetch dashboard aggregate stats. */
export async function getDashboardStats(): Promise<DashboardStats> {
  return get("/stats");
}

/**
 * Open an SSE connection to a run's event stream.
 * Calls onEvent for each parsed SSE data line, onDone when the stream ends.
 * Returns a cleanup function.
 */
export function streamRun(
  runId: string,
  onEvent: (event: Partial<ScanRun>) => void,
  onDone: () => void,
  onError: (err: Error) => void
): () => void {
  const es = new EventSource(`${BASE}/run/${runId}/stream`);

  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data) as Partial<ScanRun>;
      onEvent(data);
      if (data.status === "completed" || data.status === "error") {
        es.close();
        onDone();
      }
    } catch {
      // non-JSON keepalive lines — ignore
    }
  };

  es.onerror = () => {
    es.close();
    onError(new Error("SSE stream disconnected"));
  };

  return () => es.close();
}
