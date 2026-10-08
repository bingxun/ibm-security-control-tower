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
import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

# Windows defaults to ProactorEventLoop, which supports subprocesses; something
# in the uvicorn --reload process chain can leave the SelectorEventLoop active
# instead, which raises NotImplementedError on any asyncio subprocess call
# (e.g. the Trivy scan below). Force Proactor explicitly before the loop starts.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logger = logging.getLogger("control_tower")

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fpdf import FPDF
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
    seed_admin, VALID_ROLES, migrate_super_admin, migrate_multi_role,
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
    pkg: Optional[str] = None  # disambiguates a cve_id shared by multiple packages
    edited_by_role: Optional[str] = None  # role of the user who added manual notes


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
                "remediation":  c.get("remediation", ""),
                "manualNotes":  c.get("manual_notes", ""),
                "editedByRole": c.get("edited_by_role", ""),
                "edited":       bool(c.get("edited", False)),
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
            "remediation":  c.get("remediation", ""),
            "manualNotes":  c.get("manual_notes", ""),
            "editedByRole": c.get("edited_by_role", ""),
            "edited":       bool(c.get("edited", False)),
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
            if event.get("cves"):
                upsert_cves(run_id, event["cves"])
            _push_event(run_id, "running")

        state = GRAPH.get_state(config)
        final_vals = state.values if state else {}
        update_run_stats(
            run_id,
            tokens_used=final_vals.get("tokens_used", 0),
            avg_synthesis_s=final_vals.get("avg_synthesis_s", 0.0),
            rag_hits=final_vals.get("rag_hits", 0),
        )

        if state and state.next:
            # Still more CVEs pending — back at approval gate
            run["status"] = "awaiting_approval"
            run["langgraph_state"] = state.values
            update_run_status(run_id, "awaiting_approval")
            _push_event(run_id, "awaiting_approval")
        else:
            run["status"] = "completed"
            update_run_status(run_id, "completed")
            _push_event(run_id, "completed")

    except Exception as e:
        run["status"] = "error"
        run["error"] = str(e)
        update_run_status(run_id, "error", error=str(e))
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
    migrate_multi_role()
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


# Capability → the set of roles that grants it. A user needs ANY one of them.
SCANNER_ROLES         = {"SUPER_ADMIN", "ADMIN", "DEVOPS_ENGINEER", "DSO_MANAGER"}
REVIEWER_ROLES        = {"SUPER_ADMIN", "ADMIN", "CYBER_MANAGER", "DSO_MANAGER"}
REJECTER_ROLES        = {"SUPER_ADMIN", "CYBER_MANAGER"}
# Roles that administer projects (create, see all, assign members) and may read
# the user list to pick assignees. Super admins additionally manage users/roles.
PROJECT_MANAGER_ROLES = {"SUPER_ADMIN", "DSO_MANAGER"}


def _roles(user: dict) -> set[str]:
    return set(user.get("roles") or ([user["role"]] if user.get("role") else []))


def require_super_admin(current_user: dict = Depends(require_auth)) -> dict:
    """Dependency: only super admins administer global users and roles."""
    if "SUPER_ADMIN" not in _roles(current_user):
        raise HTTPException(status_code=403, detail="Super admin access required")
    return current_user


def require_project_manager(current_user: dict = Depends(require_auth)) -> dict:
    """Dependency: super admins and DSO managers administer projects + memberships."""
    if not (_roles(current_user) & PROJECT_MANAGER_ROLES):
        raise HTTPException(status_code=403, detail="Project management access required")
    return current_user


def require_scanner(user: dict = Depends(require_auth)) -> dict:
    if not (_roles(user) & SCANNER_ROLES):
        raise HTTPException(status_code=403, detail="Your role cannot start scans")
    return user


def require_reviewer(user: dict = Depends(require_auth)) -> dict:
    if not (_roles(user) & REVIEWER_ROLES):
        raise HTTPException(status_code=403, detail="Your role cannot review findings")
    return user


def accessible_projects(user: dict, project_id: str | None = None) -> list[str] | None:
    if project_id is not None:
        check_project(user, project_id)
        return [project_id]
    return None if (_roles(user) & PROJECT_MANAGER_ROLES) else [p["id"] for p in list_projects(user)]


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
    if not run.get("project_scoped") and "SUPER_ADMIN" not in _roles(user):
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
    if req.autoApproveBelow != "none" and not (_roles(user) & REVIEWER_ROLES):
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

    # Only reviewers who can REJECT may record a rejection; other approvers
    # (Admin/DevOps/DSO) submit approvals only. Mirrors the UI's canReject gate.
    if req.decision == "rejected" and not (_roles(user) & REJECTER_ROLES):
        raise HTTPException(status_code=403, detail="Your role cannot reject findings")

    # Persist decision to DB immediately (before graph resumes)
    update_cve_decision(
        run_id=run_id,
        cve_id=req.cve_id,
        decision=req.decision,
        manual_notes=req.edited_rationale,
        pkg=req.pkg,
        edited_by_role=req.edited_by_role,
    )

    decision_payload = {
        "cve_id": req.cve_id,
        "decision": req.decision,
        "edited_rationale": req.edited_rationale,
        "pkg": req.pkg,
        "edited_by_role": req.edited_by_role,
    }

    background_tasks.add_task(_resume_agent, run_id, decision_payload)
    return {"ok": True, "run_id": run_id}


@app.get("/scans")
def list_scans(project_id: str | None = None, user: dict = Depends(require_auth)):
    """Return past scan summaries for the dashboard table — sourced from SQLite."""
    return get_scan_summaries(project_ids=accessible_projects(user, project_id))


# ── Reports ────────────────────────────────────────────────────────────────

_REPORT_COLUMNS = [
    "CVE ID", "Severity", "Package", "Version", "Fixed In", "CVSS",
    "Status", "Justification", "Remediation", "Manual Notes",
]


def _report_filename(image_ref: str, run_id: str, ext: str) -> str:
    safe_image = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_ref or "image").strip("_") or "image"
    return f"report_{safe_image}_{run_id[:8]}.{ext}"


def _cve_report_row(c: dict) -> list:
    return [
        c.get("id", ""), c.get("severity", ""), c.get("pkg", ""),
        c.get("version", ""), c.get("fixed_in", ""), c.get("cvss", ""),
        c.get("status", ""), c.get("rationale", "") or "",
        c.get("remediation", "") or "", c.get("manual_notes", "") or "",
    ]


def _pdf_safe(text) -> str:
    """fpdf2's core Helvetica font only supports latin-1 — replace anything else
    rather than let an unexpected character (em dash, curly quote, emoji, …) in
    AI-generated text crash report generation."""
    return str(text if text is not None else "").encode("latin-1", "replace").decode("latin-1")


def _build_csv_report(run: dict, cves: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_REPORT_COLUMNS)
    for c in cves:
        writer.writerow(_cve_report_row(c))
    return buf.getvalue()


def _build_pdf_report(run: dict, cves: list[dict]) -> bytes:
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    def _line(text: str, size: int = 9, bold: bool = False, h: int = 5) -> None:
        pdf.set_font("Helvetica", "B" if bold else "", size)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, h, _pdf_safe(text), new_x="LMARGIN", new_y="NEXT")

    _line(f"Vulnerability Report — {run.get('image_ref', '')}", size=14, bold=True, h=8)
    _line(f"Run ID: {run.get('run_id', '')}")
    approved = sum(1 for c in cves if c.get("status") == "approved")
    rejected = sum(1 for c in cves if c.get("status") == "rejected")
    _line(f"Total CVEs: {len(cves)}  |  Approved: {approved}  |  Rejected: {rejected}")
    pdf.ln(4)

    for c in cves:
        _line(
            f"{c.get('id', '')} — {str(c.get('severity', '')).upper()} "
            f"(CVSS {c.get('cvss', '')}) — {str(c.get('status', '')).upper()}",
            size=10, bold=True, h=6,
        )
        _line(
            f"Package: {c.get('pkg', '')} {c.get('version', '')}    "
            f"Fixed in: {c.get('fixed_in', '') or 'N/A'}"
        )
        if c.get("rationale"):
            _line("Justification:", bold=True)
            _line(c["rationale"])
        if c.get("remediation"):
            _line("Remediation:", bold=True)
            _line(c["remediation"])
        if c.get("manual_notes"):
            _line("Manual Notes:", bold=True)
            _line(c["manual_notes"])
        pdf.ln(2)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(3)

    return bytes(pdf.output())


@app.get("/run/{run_id}/report")
def get_run_report(run_id: str, format: str = "csv", user: dict = Depends(require_auth)):
    """Download a CSV/PDF report of a run's CVEs. Project access is enforced."""
    run = check_run(user, run_id)  # 404 unless the run exists and is assigned to the user
    cves = get_cves(run_id)
    fmt = (format or "csv").lower()

    if fmt == "csv":
        filename = _report_filename(run.get("image_ref", ""), run_id, "csv")
        return Response(
            content=_build_csv_report(run, cves),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if fmt == "pdf":
        filename = _report_filename(run.get("image_ref", ""), run_id, "pdf")
        return Response(
            content=_build_pdf_report(run, cves),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    raise HTTPException(status_code=400, detail="format must be 'csv' or 'pdf'")


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
    roles: list[str] = ["DEVOPS_ENGINEER"]


class UpdateUserRequest(BaseModel):
    name: str | None = None
    roles: list[str] | None = None
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
def users_list(_pm: dict = Depends(require_project_manager)):
    # Project managers (incl. DSO) read the list to assign members; only super
    # admins can create/update/delete users (see routes below).
    return [_safe_user(u) for u in list_users()]


@app.post("/users", status_code=201)
def users_create(req: CreateUserRequest, _admin: dict = Depends(require_super_admin)):
    if not req.roles or any(r not in VALID_ROLES for r in req.roles):
        raise HTTPException(status_code=422, detail=f"Invalid role(s). Valid: {sorted(VALID_ROLES)}")
    try:
        user = create_user(email=req.email, name=req.name, password=req.password, roles=req.roles)
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
    if user_id == current_admin["id"] and req.roles is not None and "SUPER_ADMIN" not in req.roles:
        raise HTTPException(status_code=400, detail="Cannot remove your own super admin role")
    if req.roles is not None and (not req.roles or any(r not in VALID_ROLES for r in req.roles)):
        raise HTTPException(status_code=422, detail=f"Invalid role(s). Valid: {sorted(VALID_ROLES)}")
    updated = update_user(
        user_id,
        name=req.name,
        roles=req.roles,
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
def projects_create(req: CreateProjectRequest, user: dict = Depends(require_project_manager)):
    if not req.name.strip():
        raise HTTPException(status_code=422, detail="Project name is required")
    return create_project(req.name.strip(), req.description.strip())


@app.get("/projects/{project_id}")
def projects_get(project_id: str, user: dict = Depends(require_auth)):
    check_project(user, project_id)
    return get_project(project_id)


@app.get("/projects/{project_id}/members")
def projects_members(project_id: str, user: dict = Depends(require_project_manager)):
    check_project(user, project_id)
    return {"user_ids": project_member_ids(project_id)}


@app.put("/projects/{project_id}/members")
def projects_members_update(project_id: str, req: ProjectMembersRequest, user: dict = Depends(require_project_manager)):
    check_project(user, project_id)
    try:
        set_project_members(project_id, req.user_ids)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    return {"user_ids": project_member_ids(project_id)}
