/**
 * Thin API client — wraps every backend call in one place.
 */

import type { CveRecord, AgentStep, RunStats, User, UserRole } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Token storage ──────────────────────────────────────────────────────────
// Stored in sessionStorage; sent as Bearer token on every request.

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem("sct_token");
}

export function setToken(token: string): void {
  sessionStorage.setItem("sct_token", token);
  document.cookie = "sct_authed=1; path=/; SameSite=Strict";
}

export function clearToken(): void {
  sessionStorage.removeItem("sct_token");
  document.cookie = "sct_authed=; path=/; max-age=0; SameSite=Strict";
}

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
  status: "queued" | "scanning" | "running" | "awaiting_approval" | "completed" | "error";
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
  pkg?: string; // disambiguates a cve_id shared by multiple packages
  edited_by_role?: string; // role of the user who added manual notes
}

// ── Helpers ────────────────────────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token
    ? { "Content-Type": "application/json", Authorization: `Bearer ${token}` }
    : { "Content-Type": "application/json" };
}

async function post<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method:  "POST",
    headers: authHeaders(),
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`POST ${path} failed: ${res.status} — ${text}`);
  }
  return res.json();
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
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


// ── Auth API ───────────────────────────────────────────────────────────────

export interface LoginResponse {
  token: string;
  user:  User;
}

export async function apiLogin(email: string, password: string): Promise<LoginResponse> {
  // Don't use post() here — login must NOT send an existing token
  const res = await fetch(`${BASE}/auth/login`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? "Invalid email or password");
  }
  return res.json();
}

export async function apiLogout(): Promise<void> {
  const token = getToken();
  if (!token) return;
  await fetch(`${BASE}/auth/logout`, {
    method:  "POST",
    headers: { Authorization: `Bearer ${token}` },
  }).catch(() => {});
}

export async function apiMe(): Promise<User> {
  return get<User>("/auth/me");
}

// ── User management API (ADMIN only) ──────────────────────────────────────

export interface CreateUserPayload {
  email:    string;
  name:     string;
  password: string;
  role:     UserRole;
}

export interface UpdateUserPayload {
  name?:      string;
  role?:      UserRole;
  is_active?: boolean;
  password?:  string;
}

/** The user-management API returns database fields, not display-only avatars. */
export interface PlatformUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  is_active: boolean | 0 | 1;
  created_at: string;
  updated_at: string;
}

async function userRequest<T>(path: string, method = "GET", body?: object, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method, headers: authHeaders(), cache: "no-store", signal,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw error;
    throw new Error("Cannot reach the server. Please try again.");
  }
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    const fallback = response.status === 401 ? "Your session has expired. Please sign in again."
      : response.status === 403 ? "Only administrators can manage users."
      : "Unable to save or load users. Please try again.";
    throw new Error(typeof data?.detail === "string" ? data.detail : fallback);
  }
  return response.status === 204 ? undefined as T : response.json();
}

export async function listUsers(signal?: AbortSignal): Promise<PlatformUser[]> {
  return userRequest<PlatformUser[]>("/users", "GET", undefined, signal);
}

export async function createPlatformUser(payload: CreateUserPayload): Promise<PlatformUser> {
  return userRequest<PlatformUser>("/users", "POST", payload);
}

export async function updatePlatformUser(userId: string, payload: UpdateUserPayload): Promise<PlatformUser> {
  return userRequest<PlatformUser>(`/users/${encodeURIComponent(userId)}`, "PUT", payload);
}

export async function deletePlatformUser(userId: string): Promise<void> {
  return userRequest<void>(`/users/${encodeURIComponent(userId)}`, "DELETE");
}
