"""
FastAPI backend — Agentic Cloud Security Control Tower
Routes:
  POST   /scan                   — start a new agent run
  GET    /run/{run_id}           — poll current run state
  GET    /run/{run_id}/stream    — SSE stream of run events
  POST   /run/{run_id}/decision  — submit human decision (resume LangGraph)
  GET    /scans                  — list past scan summaries (dashboard)
  GET    /stats                  — dashboard aggregate stats
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

logger = logging.getLogger("control_tower")

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from langgraph.types import Command
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

load_dotenv()

# ── LangGraph graph (single shared instance with MemorySaver) ──────────────
from agent.graph import build_graph, make_initial_state
from rag.store import count_decisions, persist_decision, query_memory
from db.database import (
    init_db, create_run, update_run_status, update_run_stats,
    get_run as db_get_run, list_runs,
    upsert_cves, update_cve_decision, get_cves,
    append_trivy_log, get_trivy_logs,
    upsert_agent_steps, get_agent_steps,
    get_dashboard_stats, get_scan_summaries,
    # auth
    create_user, get_user_by_id, get_user_by_email, list_users,
    update_user, delete_user,
    create_session, get_session_user, delete_session,
    seed_admin, VALID_ROLES, migrate_super_admin,
    list_projects, get_project, has_project_access, create_project,
    project_member_ids, set_project_members,
)

GRAPH = build_graph()

# ── In-memory run registry ─────────────────────────────────────────────────
# Holds LIVE state only: SSE event queue + LangGraph state (not persisted in DB).
# Metadata (status, cves, logs) is written to SQLite on every change.
# run_id → {
#   "status": str,
#   "trivy_logs": [str],    mirrors DB — kept for fast SSE reads
#   "langgraph_state": {},
#   "events": [...]         SSE snapshots (ephemeral)
# }
RUNS: dict[str, dict] = {}

# ── Demo Trivy JSON (used when no file is uploaded) ────────────────────────
DEMO_TRIVY = {
    "Results": [
        {
            "Target": "demo-image:latest",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-3094",
                    "PkgName": "xz-utils",
                    "InstalledVersion": "5.6.0",
                    "FixedVersion": "5.6.1",
                    "Severity": "CRITICAL",
                    "Title": "RCE — backdoor in build system",
                    "Description": "Malicious code was found in xz-utils 5.6.0 and 5.6.1 which, under certain conditions, could allow an attacker to break sshd authentication and gain unauthorized access to the system remotely.",
                    "CVSS": {"nvd": {"V3Score": 10.0, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                },
                {
                    "VulnerabilityID": "CVE-2024-0553",
                    "PkgName": "gnutls",
                    "InstalledVersion": "3.7.9",
                    "FixedVersion": "3.8.3",
                    "Severity": "HIGH",
                    "Title": "Info disclosure via session resumption",
                    "Description": "A vulnerability in GnuTLS allows a server-side timing side-channel attack during RSA-PSK key exchange, allowing a remote attacker to retrieve plaintext.",
                    "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
                },
                {
                    "VulnerabilityID": "CVE-2023-44487",
                    "PkgName": "nghttp2",
                    "InstalledVersion": "1.52.0",
                    "FixedVersion": "1.57.0",
                    "Severity": "HIGH",
                    "Title": "DoS — HTTP/2 RST flood",
                    "Description": "HTTP/2 Rapid Reset Attack. An attacker can send a stream of RST_STREAM frames causing unbounded CPU consumption on the server, leading to denial of service.",
                    "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
                },
                {
                    "VulnerabilityID": "CVE-2024-2961",
                    "PkgName": "glibc",
                    "InstalledVersion": "2.35",
                    "FixedVersion": "2.39",
                    "Severity": "HIGH",
                    "Title": "Heap buffer overflow in iconv",
                    "Description": "A buffer overflow in the iconv() function in glibc can be exploited to achieve code execution on systems that use PHP's iconv filter.",
                    "CVSS": {"nvd": {"V3Score": 8.8, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"}},
                },
                {
                    "VulnerabilityID": "CVE-2023-4911",
                    "PkgName": "glibc",
                    "InstalledVersion": "2.35",
                    "FixedVersion": "2.38",
                    "Severity": "CRITICAL",
                    "Title": "Privilege escalation via ld.so",
                    "Description": "A buffer overflow in the GNU C Library's dynamic loader ld.so when processing the GLIBC_TUNABLES environment variable could allow a local attacker to gain root privileges.",
                    "CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                },
            ],
        }
    ]
}

# ── Pydantic models ────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    imageRef: str
    projectId: str
    cisProfile: str = "CIS Docker Benchmark v1.6"
    severityThreshold: str = "high"
    scanner: str = "trivy"
    autoApproveBelow: str = "none"
    trivyJson: Optional[dict] = None


class ImageScanRequest(BaseModel):
    imageRef: str  # e.g. "nginx:1.21.6"
    projectId: str


class DecisionRequest(BaseModel):
    cve_id: str
    decision: str          # "approved" | "rejected"
    edited_rationale: Optional[str] = None


# ── Run state helpers ──────────────────────────────────────────────────────

def _run_snapshot(run_id: str) -> dict:
    """Return a serialisable snapshot of the run for SSE / polling.

    Prefers live in-memory state (RUNS) for running jobs.
    Falls back to SQLite for completed/error runs not in memory (e.g. after restart).
    """
    run = RUNS.get(run_id)

    if run:
        # ── Live path (run is active in memory) ──────────────────────────
        state = run.get("langgraph_state", {})
        raw_cves = state.get("cves", [])

        def _cve_from_state(c: dict) -> dict:
            return {
                "id":           c.get("id", ""),
                "severity":     c.get("severity", "low"),
                "pkg":          c.get("pkg", ""),
                "version":      c.get("version", ""),
                "fixedIn":      c.get("fixed_in", ""),
                "cvss":         c.get("cvss", 0.0),
                "vector":       c.get("vector", ""),
                "authRequired": c.get("auth_required", ""),
                "impact":       c.get("impact", ""),
                "description":  c.get("description", ""),
                "rationale":    c.get("rationale", ""),
                "ragMatch":     c.get("rag_match"),
                "status":       c.get("status", "queued"),
            }

        cves = [_cve_from_state(c) for c in raw_cves]
        approved = sum(1 for c in cves if c["status"] == "approved")
        rejected = sum(1 for c in cves if c["status"] == "rejected")

        return {
            "run_id":         run_id,
            "status":         run["status"],
            "image_ref":      run.get("image_ref", ""),
            "project_id":     run.get("project_id", ""),
            "started_at":     run.get("started_at", ""),
            "cves":           cves,
            "agent_steps":    state.get("agent_steps", []),
            "token_fragment": state.get("token_fragment", ""),
            "trivy_logs":     run.get("trivy_logs", []),
            "stats": {
                "total":         len(cves),
                "approved":      approved,
                "rejected":      rejected,
                "avgSynthesisS": state.get("avg_synthesis_s", 0),
                "ragHits":       state.get("rag_hits", 0),
                "tokensUsed":    state.get("tokens_used", 0),
            },
        }

    # ── DB fallback path (run completed before / server restarted) ────────
    db_run = db_get_run(run_id)
    if not db_run:
        return {}

    db_cves = get_cves(run_id)
    db_steps = get_agent_steps(run_id)
    db_logs = get_trivy_logs(run_id)

    def _cve_from_db(c: dict) -> dict:
        return {
            "id":           c.get("id", ""),
            "severity":     c.get("severity", "low"),
            "pkg":          c.get("pkg", ""),
            "version":      c.get("version", ""),
            "fixedIn":      c.get("fixed_in", ""),
            "cvss":         c.get("cvss", 0.0),
            "vector":       c.get("vector", ""),
            "authRequired": c.get("auth_required", ""),
            "impact":       c.get("impact", ""),
            "description":  c.get("description", ""),
            "rationale":    c.get("rationale", ""),
            "ragMatch":     c.get("rag_match"),
            "status":       c.get("status", "queued"),
        }

    cves = [_cve_from_db(c) for c in db_cves]
    approved = sum(1 for c in cves if c["status"] == "approved")
    rejected = sum(1 for c in cves if c["status"] == "rejected")

    return {
        "run_id":      run_id,
        "status":      db_run.get("status", ""),
        "image_ref":   db_run.get("image_ref", ""),
        "project_id":  db_run.get("project_id", ""),
        "started_at":  db_run.get("started_at", ""),
        "cves":        cves,
        "agent_steps": db_steps,
        "token_fragment": "",
        "trivy_logs":  db_logs,
        "stats": {
            "total":         len(cves),
            "approved":      approved,
            "rejected":      rejected,
            "avgSynthesisS": db_run.get("avg_synthesis_s", 0),
            "ragHits":       db_run.get("rag_hits", 0),
            "tokensUsed":    db_run.get("tokens_used", 0),
        },
    }


# ── Background agent runner ────────────────────────────────────────────────

async def _trivy_scan(run_id: str, image_ref: str) -> dict:
    """
    Run Trivy against image_ref, streaming stderr log lines into run["trivy_logs"].
    Persists each log line to SQLite. Returns parsed Trivy JSON on success.
    """
    run = RUNS[run_id]
    run["status"] = "scanning"
    update_run_status(run_id, "scanning")
    _push_event(run_id, "scanning")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        limit = 10 * 1024 * 1024  # 10 MB — Trivy progress bars produce very long lines
        proc = await asyncio.create_subprocess_exec(
            "trivy", "image",
            "--format", "json",
            "--output", tmp_path,
            "--scanners", "vuln",
            "--skip-java-db-update",
            "--timeout", "5m",
            image_ref,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=limit,
        )

        assert proc.stderr is not None
        async for raw in proc.stderr:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue
            clean = line.strip()
            if clean and "\r" not in clean and len(clean) < 300:
                run["trivy_logs"].append(clean)
                append_trivy_log(run_id, clean)   # ← persist to DB
                _push_event(run_id, "scanning")

        await proc.wait()

        if proc.returncode != 0:
            raise RuntimeError(f"Trivy exited {proc.returncode}")

        with open(tmp_path) as f:
            return json.load(f)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


async def _run_agent_async(run_id: str, initial_state: dict) -> None:
    """
    Run the LangGraph pipeline in a thread (it's sync) via run_in_executor.
    Persists CVEs and agent steps to SQLite after synthesis completes.
    """
    run = RUNS[run_id]
    config = {"configurable": {"thread_id": run_id}}
    loop = asyncio.get_running_loop()

    def _stream():
        run["status"] = "running"
        update_run_status(run_id, "running")
        _push_event(run_id, "running")
        for event in GRAPH.stream(initial_state, config=config, stream_mode="values"):
            run["langgraph_state"] = event
            # Persist CVEs + steps whenever they change
            if event.get("cves"):
                upsert_cves(run_id, event["cves"])
            if event.get("agent_steps"):
                upsert_agent_steps(run_id, event["agent_steps"])
            _push_event(run_id, "running")

    await loop.run_in_executor(None, _stream)

    # Final state check
    state = GRAPH.get_state(config)
    final_vals = state.values if state else {}

    # Persist final stats
    update_run_stats(
        run_id,
        tokens_used=final_vals.get("tokens_used", 0),
        avg_synthesis_s=final_vals.get("avg_synthesis_s", 0.0),
        rag_hits=final_vals.get("rag_hits", 0),
    )

    if state and state.next:
        run["status"] = "awaiting_approval"
        run["langgraph_state"] = state.values
        update_run_status(run_id, "awaiting_approval")
        _push_event(run_id, "awaiting_approval")
    else:
        run["status"] = "completed"
        update_run_status(run_id, "completed")
        _push_event(run_id, "completed")


async def _run_pipeline(run_id: str, image_ref: str, meta: dict) -> None:
    """
    Full pipeline: optional Trivy scan → LangGraph agent.
    Spawned as an asyncio Task from POST /scan.
    """
    run = RUNS[run_id]
    try:
        trivy_json = run.get("trivy_json")
        if trivy_json is None:
            trivy_json = await _trivy_scan(run_id, image_ref)

        initial_state = make_initial_state(
            trivy_json=trivy_json,
            image_ref=image_ref,
            project_id=meta.get("projectId", ""),
            cis_profile=meta.get("cisProfile", "CIS Docker Benchmark v1.6"),
            severity_threshold=meta.get("severityThreshold", "high"),
            run_id=run_id,
        )
        await _run_agent_async(run_id, initial_state)

    except Exception as e:
        tb = traceback.format_exc()
        logger.error("Pipeline error for run %s: %s\n%s", run_id, e, tb)
        run["status"] = "error"
        run["error"] = str(e)
        update_run_status(run_id, "error", error=str(e))
        _push_event(run_id, "error")


def _run_agent(run_id: str, initial_state: dict) -> None:
    """Sync wrapper kept for the decision/resume path."""
    run = RUNS[run_id]
    config = {"configurable": {"thread_id": run_id}}

    try:
        run["status"] = "running"
        _push_event(run_id, "running")

        for event in GRAPH.stream(initial_state, config=config, stream_mode="values"):
            run["langgraph_state"] = event
            _push_event(run_id, "running")

        state = GRAPH.get_state(config)
        if state.next:
            run["status"] = "awaiting_approval"
            run["langgraph_state"] = state.values
            _push_event(run_id, "awaiting_approval")
        else:
            run["status"] = "completed"
            _push_event(run_id, "completed")

    except Exception as e:
        run["status"] = "error"
        run["error"] = str(e)
        _push_event(run_id, "error")
        raise


def _resume_agent(run_id: str, decision: dict) -> None:
    """Resume the graph after a human decision using Command(resume=...)."""
    run = RUNS[run_id]
    config = {"configurable": {"thread_id": run_id}}

    try:
        run["status"] = "running"
        _push_event(run_id, "running")

        # Resume the interrupted graph with the human decision payload
        for event in GRAPH.stream(
            Command(resume=decision),
            config=config,
            stream_mode="values",
        ):
            run["langgraph_state"] = event
            _push_event(run_id, "running")

        state = GRAPH.get_state(config)
        if state.next:
            # Still more CVEs pending — back at approval gate
            run["status"] = "awaiting_approval"
            run["langgraph_state"] = state.values
            _push_event(run_id, "awaiting_approval")
        else:
            run["status"] = "completed"
            _push_event(run_id, "completed")

    except Exception as e:
        run["status"] = "error"
        run["error"] = str(e)
        _push_event(run_id, "error")
        raise


def _push_event(run_id: str, status: str) -> None:
    """Append a serialised snapshot to the run's event queue for SSE."""
    run = RUNS.get(run_id)
    if not run:
        return
    snapshot = _run_snapshot(run_id)
    snapshot["status"] = status
    run["events"].append(snapshot)


# ── App setup ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs("./data", exist_ok=True)
    init_db()       # create tables if they don't exist
    seed_admin()
    migrate_super_admin()
    yield

app = FastAPI(title="Control Tower API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth dependency ────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def _get_token(
    req: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str | None:
    """Extract bearer token from Authorization header or sct_token cookie."""
    if creds:
        return creds.credentials
    return req.cookies.get("sct_token")


def require_auth(
    req: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Dependency: returns the current user or raises 401."""
    token = _get_token(req, creds)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = get_session_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return user


def require_super_admin(current_user: dict = Depends(require_auth)) -> dict:
    """Dependency: only super admins administer global users and projects."""
    if current_user["role"] != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Super admin access required")
    return current_user


def require_scanner(user: dict = Depends(require_auth)) -> dict:
    if user["role"] not in {"SUPER_ADMIN", "ADMIN", "DEVOPS_ENGINEER"}:
        raise HTTPException(status_code=403, detail="Your role cannot start scans")
    return user


def require_reviewer(user: dict = Depends(require_auth)) -> dict:
    if user["role"] not in {"SUPER_ADMIN", "ADMIN", "CYBER_MANAGER"}:
        raise HTTPException(status_code=403, detail="Your role cannot review findings")
    return user


def accessible_projects(user: dict, project_id: str | None = None) -> list[str] | None:
    if project_id is not None:
        check_project(user, project_id)
        return [project_id]
    return None if user["role"] == "SUPER_ADMIN" else [p["id"] for p in list_projects(user)]


def check_project(user: dict, project_id: str) -> None:
    if not has_project_access(user, project_id):
        raise HTTPException(status_code=404, detail="Project not found or not assigned to you")


def check_run(user: dict, run_id: str) -> dict:
    run = db_get_run(run_id)
    if not run or not has_project_access(user, run["project_id"]):
        raise HTTPException(status_code=404, detail="Run not found or not assigned to you")
    return run


def safe_snapshot(user: dict, run_id: str) -> dict:
    run = check_run(user, run_id)
    snapshot = _run_snapshot(run_id)
    # Older AI text may contain cross-project memory. Keep raw findings available,
    # but expose historical generated content only to the super admin.
    if not run.get("project_scoped") and user["role"] != "SUPER_ADMIN":
        for cve in snapshot.get("cves", []):
            cve["ragMatch"] = None
            cve["rationale"] = "Historical rationale withheld. Run a new scan for project-isolated analysis."
        snapshot["agent_steps"] = []
        snapshot["token_fragment"] = ""
        snapshot["trivy_logs"] = []
        snapshot["stats"]["ragHits"] = 0
    return snapshot


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def start_scan(req: ScanRequest, user: dict = Depends(require_scanner)):
    """
    Register a new scan run immediately and return run_id.
    Persists the run to SQLite straight away so it survives restarts.
    """
    check_project(user, req.projectId)
    if req.autoApproveBelow != "none" and user["role"] == "DEVOPS_ENGINEER":
        raise HTTPException(status_code=403, detail="Your role cannot auto-approve findings")
    run_id = str(uuid.uuid4())
    meta = req.model_dump()

    # Persist to DB immediately
    create_run(
        run_id=run_id,
        image_ref=req.imageRef,
        project_id=req.projectId,
        cis_profile=req.cisProfile,
        scanner=req.scanner,
        severity_threshold=req.severityThreshold,
    )

    # In-memory live state (SSE events + LangGraph)
    RUNS[run_id] = {
        "status": "queued",
        "image_ref": req.imageRef,
        "project_id": req.projectId,
        "trivy_logs": [],
        "trivy_json": req.trivyJson,
        "langgraph_state": {},
        "events": [],
        "meta": meta,
    }

    asyncio.ensure_future(_run_pipeline(run_id, req.imageRef, meta))
    return {"run_id": run_id}


@app.get("/run/{run_id}")
def get_run(run_id: str, user: dict = Depends(require_auth)):
    return safe_snapshot(user, run_id)


@app.get("/run/{run_id}/stream")
async def stream_run(run_id: str, request: Request, user: dict = Depends(require_auth)):
    check_run(user, run_id)
    token = _get_token(request, await _bearer(request))

    async def _generator() -> AsyncGenerator[dict, None]:
        previous = None
        while not await request.is_disconnected():
            current = get_session_user(token) if token else None
            if not current:
                return
            try:
                snapshot = safe_snapshot(current, run_id)
            except HTTPException:
                return
            payload = json.dumps(snapshot)
            if payload != previous:
                yield {"data": payload}
                previous = payload
            if snapshot.get("status") in ("completed", "error"):
                return
            await asyncio.sleep(0.3)
    return EventSourceResponse(_generator())


@app.post("/run/{run_id}/decision")
def submit_decision(run_id: str, req: DecisionRequest, background_tasks: BackgroundTasks, user: dict = Depends(require_reviewer)):
    """Submit a human decision to resume the approval gate."""
    check_run(user, run_id)
    if run_id not in RUNS:
        raise HTTPException(status_code=404, detail="Run not found")

    run = RUNS[run_id]
    if run["status"] not in ("awaiting_approval",):
        raise HTTPException(
            status_code=409,
            detail=f"Run is not awaiting approval (status: {run['status']})"
        )

    # Persist decision to DB immediately (before graph resumes)
    update_cve_decision(
        run_id=run_id,
        cve_id=req.cve_id,
        decision=req.decision,
        rationale=req.edited_rationale,
    )

    decision_payload = {
        "cve_id": req.cve_id,
        "decision": req.decision,
        "edited_rationale": req.edited_rationale,
    }

    background_tasks.add_task(_resume_agent, run_id, decision_payload)
    return {"ok": True, "run_id": run_id}


@app.get("/scans")
def list_scans(project_id: str | None = None, user: dict = Depends(require_auth)):
    """Return past scan summaries for the dashboard table — sourced from SQLite."""
    return get_scan_summaries(project_ids=accessible_projects(user, project_id))


@app.get("/scan-image/stream")
async def scan_image_stream(imageRef: str, projectId: str, user: dict = Depends(require_scanner)):
    """
    SSE stream: runs Trivy against imageRef and emits progress events.

    Event types (JSON payloads):
      {"type": "log",    "line": "<raw trivy stderr line>"}
      {"type": "done",   "trivyJson": {...}, "totalVulnerabilities": N}
      {"type": "error",  "detail": "<message>"}
    """
    check_project(user, projectId)
    async def _generate() -> AsyncGenerator[dict, None]:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                tmp_path = tmp.name

            proc = await asyncio.create_subprocess_exec(
                "trivy", "image",
                "--format", "json",
                "--output", tmp_path,
                "--timeout", "5m",
                imageRef,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Stream stderr (Trivy writes progress/logs there)
            assert proc.stderr is not None
            async for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    yield {"data": json.dumps({"type": "log", "line": line})}

            await proc.wait()

            if proc.returncode != 0:
                yield {"data": json.dumps({
                    "type": "error",
                    "detail": f"Trivy exited with code {proc.returncode}",
                })}
                return

            with open(tmp_path) as f:
                trivy_json = json.load(f)

            vulns = [
                v
                for r in trivy_json.get("Results", [])
                for v in (r.get("Vulnerabilities") or [])
            ]
            yield {"data": json.dumps({
                "type": "done",
                "trivyJson": trivy_json,
                "totalVulnerabilities": len(vulns),
            })}

        except Exception as e:
            yield {"data": json.dumps({"type": "error", "detail": str(e)})}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    return EventSourceResponse(_generate())


@app.post("/scan-image")
def scan_image(req: ImageScanRequest, user: dict = Depends(require_scanner)):
    """
    Blocking version — runs Trivy and returns findings in one shot.
    Used as fallback when SSE is not available.
    """
    check_project(user, req.projectId)
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--output", tmp_path,
                "--scanners", "vuln",
                "--skip-java-db-update",
                "--timeout", "5m",
                "--no-progress",
                req.imageRef,
            ],
            capture_output=True,
            text=True,
            timeout=330,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=422,
                detail=f"Trivy scan failed: {result.stderr[-500:] or result.stdout[-500:]}"
            )

        with open(tmp_path) as f:
            trivy_json = json.load(f)

        os.unlink(tmp_path)

        vulns = [
            v
            for r in trivy_json.get("Results", [])
            for v in (r.get("Vulnerabilities") or [])
        ]
        return {
            "imageRef": req.imageRef,
            "totalVulnerabilities": len(vulns),
            "trivyJson": trivy_json,
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Trivy scan timed out (>5m)")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
def get_stats(project_id: str | None = None, user: dict = Depends(require_auth)):
    """Return aggregate stats for the dashboard header — sourced from SQLite."""
    project_ids = accessible_projects(user, project_id)
    stats = get_dashboard_stats(project_ids)
    stats["ragDecisions"] = count_decisions(project_ids)
    return stats


# ── Helpers ────────────────────────────────────────────────────────────────

def _elapsed(started_at: str) -> str:
    if not started_at:
        return "—"
    try:
        start = datetime.fromisoformat(started_at)
        secs = int((datetime.now(timezone.utc) - start).total_seconds())
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "—"


# ── Auth request/response models ───────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str = "DEVOPS_ENGINEER"


class UpdateUserRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


def _safe_user(u: dict) -> dict:
    """Strip password_hash before returning user to client."""
    result = {k: v for k, v in u.items() if k != "password_hash"}
    result["avatarInitials"] = "".join(part[0] for part in u["name"].split()[:2]).upper()
    return result


# ── Auth routes ────────────────────────────────────────────────────────────

@app.post("/auth/login")
def auth_login(req: LoginRequest):
    """Authenticate and return a session token."""
    user = get_user_by_email(req.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    from db.database import _verify_password
    if not _verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    token = create_session(user["id"])
    return {
        "token": token,
        "user":  _safe_user(user),
    }


@app.post("/auth/logout")
def auth_logout(
    req: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    token = _get_token(req, creds)
    if token:
        delete_session(token)
    return {"ok": True}


@app.get("/auth/me")
def auth_me(current_user: dict = Depends(require_auth)):
    """Return the current authenticated user."""
    return _safe_user(current_user)


# ── User management routes (SUPER_ADMIN only) ────────────────────────────────────

@app.get("/users")
def users_list(_admin: dict = Depends(require_super_admin)):
    return [_safe_user(u) for u in list_users()]


@app.post("/users", status_code=201)
def users_create(req: CreateUserRequest, _admin: dict = Depends(require_super_admin)):
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Valid: {sorted(VALID_ROLES)}")
    try:
        user = create_user(email=req.email, name=req.name, password=req.password, role=req.role)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _safe_user(user)


@app.put("/users/{user_id}")
def users_update(
    user_id: str,
    req: UpdateUserRequest,
    current_admin: dict = Depends(require_super_admin),
):
    # Prevent admin from deactivating themselves
    if user_id == current_admin["id"] and req.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    if user_id == current_admin["id"] and req.role is not None and req.role != "SUPER_ADMIN":
        raise HTTPException(status_code=400, detail="Cannot change your own super admin role")
    if req.role is not None and req.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Valid: {sorted(VALID_ROLES)}")
    updated = update_user(
        user_id,
        name=req.name,
        role=req.role,
        is_active=req.is_active,
        password=req.password,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return _safe_user(updated)


@app.delete("/users/{user_id}", status_code=204)
def users_delete(user_id: str, current_admin: dict = Depends(require_super_admin)):
    if user_id == current_admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if not get_user_by_id(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    delete_user(user_id)


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)


class ProjectMembersRequest(BaseModel):
    user_ids: list[str]


@app.get("/projects")
def projects_list(user: dict = Depends(require_auth)):
    return list_projects(user)


@app.post("/projects", status_code=201)
def projects_create(req: CreateProjectRequest, user: dict = Depends(require_super_admin)):
    if not req.name.strip():
        raise HTTPException(status_code=422, detail="Project name is required")
    return create_project(req.name.strip(), req.description.strip())


@app.get("/projects/{project_id}")
def projects_get(project_id: str, user: dict = Depends(require_auth)):
    check_project(user, project_id)
    return get_project(project_id)


@app.get("/projects/{project_id}/members")
def projects_members(project_id: str, user: dict = Depends(require_super_admin)):
    check_project(user, project_id)
    return {"user_ids": project_member_ids(project_id)}


@app.put("/projects/{project_id}/members")
def projects_members_update(project_id: str, req: ProjectMembersRequest, user: dict = Depends(require_super_admin)):
    check_project(user, project_id)
    try:
        set_project_members(project_id, req.user_ids)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    return {"user_ids": project_member_ids(project_id)}
