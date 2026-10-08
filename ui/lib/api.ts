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
export async function scanImage(imageRef: string, projectId: string): Promise<{ trivyJson: object; totalVulnerabilities: number }> {
  return post("/scan-image", { imageRef, projectId });
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
  projectId: string,
  onEvent: (e: TrivyScanEvent) => void,
  onDone: (trivyJson: object, total: number) => void,
  onError: (msg: string) => void,
): () => void {
  return authenticatedStream(`/scan-image/stream?imageRef=${encodeURIComponent(imageRef)}&projectId=${encodeURIComponent(projectId)}`, (data) => {
    const event = data as TrivyScanEvent;
    onEvent(event);
    if (event.type === "done") onDone(event.trivyJson, event.totalVulnerabilities);
    if (event.type === "error") onError(event.detail);
  }, () => {}, (error) => onError(error.message));
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
export async function listScans(projectId?: string): Promise<ScanSummary[]> {
  return get(`/scans${projectId === undefined ? "" : `?project_id=${encodeURIComponent(projectId)}`}`);
}

/** Fetch dashboard aggregate stats. */
export async function getDashboardStats(projectId?: string): Promise<DashboardStats> {
  return get(`/stats${projectId === undefined ? "" : `?project_id=${encodeURIComponent(projectId)}`}`);
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
  return authenticatedStream(`/run/${encodeURIComponent(runId)}/stream`, (data) => {
    onEvent(data as Partial<ScanRun>);
  }, onDone, onError);
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

// ── User management API (SUPER_ADMIN only) ──────────────────────────────────────

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
      : response.status === 403 ? "Only super admins can manage users and project assignments."
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


// Fetch-based SSE carries the Bearer token without exposing it in URLs.
function authenticatedStream(path: string, onEvent: (data: unknown) => void, onDone: () => void, onError: (error: Error) => void): () => void {
  const controller = new AbortController();
  void (async () => {
    try {
      const response = await fetch(`${BASE}${path}`, { headers: authHeaders(), signal: controller.signal });
      if (!response.ok || !response.body) throw new Error(`Stream unavailable (${response.status})`);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!controller.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary: RegExpExecArray | null;
        while ((boundary = /\r?\n\r?\n/.exec(buffer))) {
          const frame = buffer.slice(0, boundary.index);
          buffer = buffer.slice(boundary.index + boundary[0].length);
          const data = frame.split(/\r?\n/).filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n");
          if (data && !controller.signal.aborted) onEvent(JSON.parse(data));
        }
      }
      if (!controller.signal.aborted) onDone();
    } catch (error) {
      if (!controller.signal.aborted) onError(error instanceof Error ? error : new Error("Stream failed"));
    }
  })();
  return () => controller.abort();
}

export interface Project { id: string; name: string; description: string; created_at: string; }
export function listProjects(): Promise<Project[]> { return userRequest("/projects"); }
export function createProject(name: string, description: string): Promise<Project> {
  return userRequest("/projects", "POST", { name, description });
}
export function getProjectMembers(projectId: string): Promise<{ user_ids: string[] }> {
  return userRequest(`/projects/${encodeURIComponent(projectId)}/members`);
}
export function saveProjectMembers(projectId: string, user_ids: string[]): Promise<{ user_ids: string[] }> {
  return userRequest(`/projects/${encodeURIComponent(projectId)}/members`, "PUT", { user_ids });
}
