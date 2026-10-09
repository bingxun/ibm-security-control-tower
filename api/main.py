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
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fpdf import FPDF
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

# Make the project's .env the source of truth for config, even when stale
# values are already exported in the shell (which would otherwise shadow it).
load_dotenv(override=True)

# ── LangGraph graph (single shared instance with MemorySaver) ──────────────
from agent.graph import build_graph, make_initial_state
from agent import progress as synthesis_progress
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

from db import baselines
from db.database import get_conn
from agent import review_assist
from agent import assistant
from agent.nodes import synthesis
from pathlib import Path

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

# ── Pydantic models ────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    imageRef: str
    projectId: str
    cisProfile: str = "CIS Docker Benchmark v1.6"
    severityThreshold: str = "high"
    severities: Optional[list[str]] = None   # explicit picks, e.g. ["critical", "medium"]; overrides severityThreshold
    scanner: str = "trivy"
    autoApproveBelow: str = "none"
    trivyJson: Optional[dict] = None
    environmentMarkdown: str = Field(default="", max_length=100_000)


class ImageScanRequest(BaseModel):
    imageRef: str  # e.g. "nginx:1.21.6"
    projectId: str


class DecisionRequest(BaseModel):
    cve_id: str
    decision: str          # "approved" | "rejected" | "submitted" | "changes_requested"
    edited_rationale: Optional[str] = None  # back-compat alias for manual notes
    pkg: Optional[str] = None  # disambiguates a cve_id shared by multiple packages
    edited_by_role: Optional[str] = None  # role of the user who added manual notes
    # DevOps-editable draft fields (sent on submit/resubmit); when omitted the
    # finding's existing values are preserved.
    justification: Optional[str] = None   # edited rationale text
    remediation: Optional[str] = None     # edited proposed remediation
    notes: Optional[str] = None           # manual notes
    # Cyber review fields.
    review_comment: Optional[str] = None      # approve note OR rejection reason
    requested_changes: Optional[str] = None   # what DevOps must provide (changes_requested)
    ai_suggestions_applied: Optional[list[str]] = None  # labels of applied Review AI suggestions


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

        agent_steps = list(state.get("agent_steps", []))
        token_fragment = state.get("token_fragment", "")
        tokens_used = state.get("tokens_used", 0)
        rag_hits = state.get("rag_hits", 0)

        # Overlay in-flight synthesis progress (workers that have finished while
        # the synthesis node is still running) so the UI advances live instead
        # of sitting idle until the whole batch returns.
        prog = synthesis_progress.get(run_id) if run.get("status") == "running" else None
        if prog and prog["cves"]:
            done = prog["cves"]
            raw_cves = [done.get(f"{c.get('id')}::{c.get('pkg')}", c) for c in raw_cves]
            seen = {s.get("id") for s in agent_steps}
            agent_steps = agent_steps + [s for s in prog["steps"] if s.get("id") not in seen]
            tokens_used = max(tokens_used, prog["tokens"])
            rag_hits = max(rag_hits, prog["rag_hits"])

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
            "agent_steps":    agent_steps,
            "token_fragment": token_fragment,
            "trivy_logs":     run.get("trivy_logs", []),
            "stats": {
                "total":         len(cves),
                "approved":      approved,
                "rejected":      rejected,
                "avgSynthesisS": state.get("avg_synthesis_s", 0),
                "ragHits":       rag_hits,
                "tokensUsed":    tokens_used,
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

    synthesis_progress.clear(run_id)  # synthesis done — stop overlaying progress
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
            scan_json=trivy_json,
            environment_markdown=meta.get("environmentMarkdown", ""),
            image_ref=image_ref,
            project_id=meta.get("projectId", ""),
            cis_profile=meta.get("cisProfile", "CIS Docker Benchmark v1.6"),
            severity_threshold=meta.get("severityThreshold", "high"),
            severities=meta.get("severities"),
            scanner=meta.get("scanner", "trivy"),
            run_id=run_id,
            auto_approve_below=meta.get("autoApproveBelow", "none"),
        )
        await _run_agent_async(run_id, initial_state)

    except Exception as e:
        tb = traceback.format_exc()
        logger.error("Pipeline error for run %s: %s\n%s", run_id, e, tb)
        run["status"] = "error"
        run["error"] = str(e)
        synthesis_progress.clear(run_id)
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
    baselines.init_baselines()
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
    expose_headers=["Content-Disposition"],
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
# DevOps engineers submit pending findings for Cyber approval (no direct decide).
SUBMITTER_ROLES       = {"SUPER_ADMIN", "DEVOPS_ENGINEER"}
# Once a finding is `submitted`, ONLY Cyber (and super admin) may approve/reject it.
CYBER_APPROVER_ROLES  = {"SUPER_ADMIN", "CYBER_MANAGER"}
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
            cve["remediation"] = "Historical content withheld. Rescan for project-isolated analysis."
            cve["manualNotes"] = ""
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
    # Auto-approval only ever reuses findings a Cyber Manager explicitly published
    # as shared baselines, within the chosen severity ceiling — so any scanner may
    # enable it; the human authorization lives in the baseline publish, not here.
    run_id = str(uuid.uuid4())
    if len(req.environmentMarkdown.encode("utf-8")) > 100_000:
        raise HTTPException(status_code=422, detail="Environment Markdown must be at most 100 KB")
    meta = req.model_dump()

    # Persist to DB immediately
    create_run(
        run_id=run_id,
        image_ref=req.imageRef,
        project_id=req.projectId,
        cis_profile=req.cisProfile,
        scanner=req.scanner,
        severity_threshold=",".join(req.severities) if req.severities else req.severityThreshold,
    )

    with get_conn() as conn:
        conn.execute("INSERT INTO scan_context(run_id, markdown) VALUES (?,?)", (run_id, req.environmentMarkdown))

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


# One lock serializes approval transitions and checkpoint synchronization within this process.
# SQLite transactions make the durable review batch all-or-nothing.
import threading
from api import project_reports
REVIEW_LOCK = threading.RLock()


def _validate_transition(user, current, decision):
    roles = _roles(user)
    if decision == "submitted":
        if not roles & SUBMITTER_ROLES:
            raise HTTPException(403, "Your role cannot submit findings for approval")
        # Allow both an initial submit and a resubmit after the Cyber Manager
        # sent the finding back for changes.
        if current not in ("pending", "changes_requested"):
            raise HTTPException(409, "Only pending or changes-requested findings can be submitted")
    elif decision == "changes_requested":
        # "Reject & request changes" — Cyber returns a submitted finding to DevOps.
        if not roles & CYBER_APPROVER_ROLES:
            raise HTTPException(403, "Only Cyber Managers can request changes")
        if current != "submitted":
            raise HTTPException(409, "Only submitted findings can be sent back for changes")
    elif decision in ("approved", "rejected"):
        allowed = CYBER_APPROVER_ROLES if current == "submitted" else REVIEWER_ROLES
        if not roles & allowed or (decision == "rejected" and not roles & REJECTER_ROLES):
            raise HTTPException(403, "Your role cannot make this review decision")
        if current not in ("pending", "submitted"):
            raise HTTPException(409, "This finding has already been decided or is not ready")
    else:
        raise HTTPException(422, "Invalid review decision")


def _synchronize_review(run_id):
    """Reconstruct the approval checkpoint from SQLite, including after a restart.

    Review writes are authoritative; never replay ingestion or synthesis when recovering.
    """
    metadata = db_get_run(run_id)
    cves = get_cves(run_id)
    state = make_initial_state({}, image_ref=metadata['image_ref'], project_id=metadata['project_id'], run_id=run_id)
    state.update(cves=cves, total=len(cves), agent_steps=get_agent_steps(run_id),
                 approved=sum(c['status'] == 'approved' for c in cves),
                 rejected=sum(c['status'] == 'rejected' for c in cves))
    live = RUNS.get(run_id)
    state.update(tokens_used=metadata.get('tokens_used',0), avg_synthesis_s=metadata.get('avg_synthesis_s',0), rag_hits=metadata.get('rag_hits',0))
    state['agent_steps'] = [step for step in state['agent_steps'] if not step['id'].startswith('approval-')]
    _desc = {'submitted': 'Awaiting Cyber Manager', 'changes_requested': 'Changes requested — awaiting DevOps revision'}
    state['agent_steps'].extend({
        'id': f"approval-{index}-{c['id']}", 'title': f"Human review · {c['id']} · {c['pkg']}",
        'desc': _desc.get(c['status'], c['status'].capitalize()),
        'chips': [{'label': c['status'], 'variant': 'done' if c['status'] in ('approved','rejected') else 'stream'}],
        'state': 'done' if c['status'] in ('approved','rejected') else 'waiting'
    } for index,c in enumerate(cves))
    config = {"configurable": {"thread_id": run_id}}
    GRAPH.update_state(config, state, as_node="approval")
    if not live:
        RUNS[run_id] = {"status": "awaiting_approval", "image_ref": metadata['image_ref'],
                        "project_id": metadata['project_id'], "trivy_logs": get_trivy_logs(run_id),
                        "langgraph_state": state, "events": []}
    for event in GRAPH.stream(None, config=config, stream_mode="values"):
        RUNS[run_id]['langgraph_state'] = event
    final = GRAPH.get_state(config)
    RUNS[run_id]['langgraph_state'] = final.values
    status = 'awaiting_approval' if final.next else 'completed'
    RUNS[run_id]['status'] = status
    upsert_agent_steps(run_id, final.values.get('agent_steps', []))
    update_run_status(run_id, status)
    _push_event(run_id, status)


def _write_reviews(changes, user):
    """Apply review decisions durably.

    Each change is (run_id, cve, decision, notes, rationale, remediation, meta?)
    where the optional `meta` dict carries review_comment / requested_changes /
    ai_suggestions_applied. The `cves` row holds current state (overwritten),
    while `review_revisions` preserves every submission and decision as its own
    append-only snapshot.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        for change in changes:
            run_id, cve, decision, notes, rationale, remediation = change[:6]
            conn.execute("""UPDATE cves SET status=?,manual_notes=?,rationale=?,remediation=?,
                edited=1,edited_by_role=? WHERE run_id=? AND id=? AND pkg=?""",
                (decision, notes, rationale, remediation, user['role'], run_id, cve['id'], cve['pkg']))
            conn.execute("""INSERT INTO review_audit(run_id,cve_id,pkg,decision,reviewer,reviewed_at)
                VALUES (?,?,?,?,?,?)""", (run_id,cve['id'],cve['pkg'],decision,user['name'],now))
    for change in changes:
        run_id, cve, decision, notes, rationale, remediation = change[:6]
        meta = change[6] if len(change) > 6 else {}
        baselines.record_revision(
            run_id, cve['id'], cve['pkg'], decision, user['name'], user['role'],
            justification=rationale, remediation=remediation, manual_notes=notes,
            review_comment=meta.get('review_comment', ''),
            requested_changes=meta.get('requested_changes', ''),
            ai_suggestions_applied=meta.get('ai_suggestions_applied'))
    for run_id in dict.fromkeys(change[0] for change in changes):
        _synchronize_review(run_id)


@app.post("/run/{run_id}/decision")
def submit_decision(run_id: str, req: DecisionRequest, user: dict = Depends(require_auth)):
    run = check_run(user, run_id)
    with REVIEW_LOCK:
        candidates = [c for c in get_cves(run_id) if c['id'] == req.cve_id and (req.pkg is None or c['pkg'] == req.pkg)]
        # Check role before existence to keep authorization consistent for denied callers.
        _validate_transition(user, candidates[0]['status'] if candidates else 'pending', req.decision)
        if not candidates:
            raise HTTPException(404, "Finding not found")
        if len(candidates) != 1:
            raise HTTPException(422, "Package is required to identify this finding")
        if run['status'] != 'awaiting_approval':
            raise HTTPException(409, "Run is not awaiting approval")
        cve = candidates[0]
        if req.decision == 'changes_requested' and not (
                (req.review_comment or '').strip() and (req.requested_changes or '').strip()):
            raise HTTPException(422, "Requesting changes needs a reason and the evidence DevOps must provide")
        # DevOps may edit the justification/remediation/notes when (re)submitting;
        # a Cyber decision leaves the finding's text as-is. `edited_rationale` is
        # the legacy alias for notes.
        notes = req.notes if req.notes is not None else (
            req.edited_rationale if req.edited_rationale is not None else cve.get('manual_notes', ''))
        rationale = req.justification if req.justification is not None else cve.get('rationale', '')
        remediation = req.remediation if req.remediation is not None else cve.get('remediation', '')
        meta = {'review_comment': req.review_comment or '',
                'requested_changes': req.requested_changes or '',
                'ai_suggestions_applied': req.ai_suggestions_applied}
        _write_reviews([(run_id, cve, req.decision, notes, rationale, remediation, meta)], user)
    return {"ok": True, "run_id": run_id}


@app.get("/run/{run_id}/revisions")
def get_revisions(run_id: str, cve_id: str, pkg: str, user: dict = Depends(require_auth)):
    """Ordered submission/decision history for one finding (both roles can read)."""
    check_run(user, run_id)
    return baselines.revisions(run_id, cve_id, pkg)


class ReviewAiRequest(BaseModel):
    cve_id: str
    pkg: str
    mode: str = "draft"            # "draft" (DevOps) | "review" (Cyber)
    justification: str = Field(default="", max_length=20_000)
    remediation: str = Field(default="", max_length=20_000)
    notes: str = Field(default="", max_length=20_000)


@app.post("/run/{run_id}/review-ai")
def review_ai(run_id: str, req: ReviewAiRequest, user: dict = Depends(require_auth)):
    """Evaluate a draft and return structured suggestions. Read-only — writes nothing."""
    run = check_run(user, run_id)
    roles = _roles(user)
    if req.mode == "review" and not (roles & REVIEWER_ROLES):
        raise HTTPException(403, "Your role cannot use review-mode assistance")
    if req.mode != "review" and not (roles & (SUBMITTER_ROLES | REVIEWER_ROLES)):
        raise HTTPException(403, "Your role cannot use draft assistance")
    cve = next((c for c in get_cves(run_id) if c['id'] == req.cve_id and c['pkg'] == req.pkg), None)
    if not cve:
        raise HTTPException(404, "Finding not found")
    with get_conn() as conn:
        row = conn.execute("SELECT markdown FROM scan_context WHERE run_id=?", (run_id,)).fetchone()
    environment_markdown = row[0] if row else ""
    refs = baselines.references(req.cve_id, req.pkg) + baselines.past_approvals(run['project_id'], req.cve_id, req.pkg)
    draft = {"justification": req.justification, "remediation": req.remediation, "notes": req.notes}
    return review_assist.generate_suggestions(cve, draft, environment_markdown, refs, req.mode)


class ChatMessage(BaseModel):
    role: str
    content: str = Field(max_length=4000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(max_length=30)
    run_id: Optional[str] = None


def _chat_context(user: dict, run_id: str | None) -> str:
    """Build the grounding context from ONLY what this user is allowed to see."""
    lines: list[str] = []
    if run_id:
        run = check_run(user, run_id)  # 404 if not accessible
        cves = _report_cves(user, run)  # applies historical-content withholding
        lines.append(f"Current scan #{run.get('run_id','')[:8]}: image {run['image_ref']}, status {run['status']}, {len(cves)} findings.")
        for c in sorted(cves, key=lambda x: -float(x.get('cvss') or 0))[:30]:
            rat = (c.get('rationale') or '').replace('\n', ' ')[:160]
            lines.append(f"- {c['id']} [{c['pkg']} {c.get('version','')}] severity={c['severity']} cvss={c.get('cvss',0)} status={c['status']}. {rat}")
    else:
        summaries = get_scan_summaries(project_ids=accessible_projects(user))
        if not summaries:
            return "This user has no scans yet."
        tot = sum(s['totalCves'] for s in summaries)
        appr = sum(s['approved'] for s in summaries)
        rej = sum(s['rejected'] for s in summaries)
        cr = sum(s.get('changesRequested', 0) for s in summaries)
        lines.append(f"{len(summaries)} scans across the user's projects; {tot} findings total ({appr} approved, {rej} rejected, {cr} changes-requested).")
        for s in summaries[:15]:
            lines.append(f"- scan #{s['seq']} {s['image']} status={s['status']} findings={s['totalCves']} (critical {s['critical']}, high {s['high']}, medium {s['medium']})")
    return "\n".join(lines)


@app.post("/chat")
def chat(req: ChatRequest, user: dict = Depends(require_auth)):
    """Scoped product + CVE assistant. Read-only; grounded on the user's visible data."""
    if not req.messages or req.messages[-1].role != "user":
        raise HTTPException(422, "The last message must be from the user")
    context = _chat_context(user, req.run_id)
    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    return assistant.answer(messages, context)


@app.post("/run/{run_id}/apply-baselines")
def apply_baselines(run_id: str, user: dict = Depends(require_auth)):
    """Reconcile an open run against currently-published baselines: auto-approve any
    pending finding that exactly matches a Cyber Manager baseline. Lets runs scanned
    before a baseline existed catch up. Read-safe: only reuses human-published
    decisions, fully audited, attributed to the agent."""
    run = check_run(user, run_id)
    if run.get("status") != "awaiting_approval":
        return {"applied": 0}
    agent_user = {"name": "Control Tower Agent", "role": "AGENT"}
    with REVIEW_LOCK:
        changes = []
        for cve in get_cves(run_id):
            if cve["status"] not in ("pending", "changes_requested"):
                continue
            bl = baselines.references(cve["id"], cve["pkg"])
            if not bl:
                continue
            top = bl[0]
            origin = top.get("approver") or "a Cyber Manager"
            meta = {"review_comment": f"Auto-approved from a published Cyber Manager baseline (originally approved by {origin}).",
                    "requested_changes": "", "ai_suggestions_applied": None}
            changes.append((run_id, cve, "approved", cve.get("manual_notes", ""),
                            top["rationale"], top["remediation"], meta))
        if changes:
            _write_reviews(changes, agent_user)
    return {"applied": len(changes)}


# ── LLM gateway settings (Claude / IBM RAD, Anthropic-compatible) ─────────────
class LlmConfigRequest(BaseModel):
    base_url: str = Field(min_length=4, max_length=300)
    model: str = Field(min_length=1, max_length=120)
    token: Optional[str] = None  # new token; blank/omitted keeps the existing one


def _token_hint(tok: str) -> str:
    if not tok:
        return ""
    return f"{tok[:5]}…{tok[-4:]}" if len(tok) > 12 else "set"


def _llm_payload() -> dict:
    tok = synthesis.RAD_AUTH_TOKEN
    return {"base_url": synthesis.RAD_BASE_URL, "model": synthesis.RAD_MODEL,
            "token_set": bool(tok), "token_hint": _token_hint(tok)}


def _probe_gateway(base_url: str, model: str, token: str) -> tuple[bool, str]:
    """Live check against the Anthropic-compatible gateway; returns (ok, detail)."""
    import json as _json, urllib.request, urllib.error
    if not token:
        return False, "No API token configured."
    url = base_url.rstrip("/") + "/v1/chat/completions"
    body = _json.dumps({"model": model, "max_tokens": 8,
                        "messages": [{"role": "user", "content": "ping"}]}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "x-api-key": token})
    try:
        with urllib.request.urlopen(req, timeout=20):
            return True, "Connection successful."
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:200]
        msg = {401: "Invalid API token.", 403: "Forbidden — check the base URL and token.",
               404: "Model or endpoint not found — check the model id.",
               429: "Rate limited or budget exceeded for this token's team."}.get(e.code, f"HTTP {e.code}.")
        return False, f"{msg} ({raw})"
    except Exception as e:  # network / DNS / timeout
        return False, f"Could not reach the gateway: {type(e).__name__}."


def _write_env(updates: dict[str, str]) -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    seen, out = set(), []
    for line in lines:
        m = re.match(r"^([A-Z0-9_]+)=", line)
        if m and m.group(1) in updates:
            out.append(f"{m.group(1)}={updates[m.group(1)]}"); seen.add(m.group(1))
        else:
            out.append(line)
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")
    env_path.write_text("\n".join(out) + "\n")


@app.get("/settings/llm")
def get_llm(user: dict = Depends(require_super_admin)):
    return _llm_payload()


@app.post("/settings/llm/test")
def test_llm(req: LlmConfigRequest, user: dict = Depends(require_super_admin)):
    token = req.token.strip() if (req.token and "…" not in req.token) else synthesis.RAD_AUTH_TOKEN
    ok, detail = _probe_gateway(req.base_url.strip(), req.model.strip(), token)
    return {"ok": ok, "detail": detail}


@app.put("/settings/llm")
def set_llm(req: LlmConfigRequest, user: dict = Depends(require_super_admin)):
    synthesis.RAD_BASE_URL = req.base_url.strip()
    synthesis.RAD_MODEL = req.model.strip()
    env = {"ANTHROPIC_BASE_URL": synthesis.RAD_BASE_URL, "RAD_MODEL": synthesis.RAD_MODEL}
    if req.token and req.token.strip() and "…" not in req.token:
        synthesis.RAD_AUTH_TOKEN = req.token.strip()
        env["ANTHROPIC_AUTH_TOKEN"] = synthesis.RAD_AUTH_TOKEN
    _write_env(env)  # persist so it survives a restart (.env is authoritative)
    return _llm_payload()


class CsvImportRequest(BaseModel):
    content: str = Field(max_length=5_000_000)


class BaselineRequest(BaseModel):
    cve_id: str
    pkg: str
    justification: str = Field(min_length=1, max_length=20_000)
    remediation: str = Field(min_length=1, max_length=20_000)


def _report_cves(user, run):
    cves = get_cves(run['run_id'])
    if not run.get('project_scoped') and 'SUPER_ADMIN' not in _roles(user):
        for c in cves:
            for key in ('rationale','remediation','manual_notes'):
                c[key] = 'Historical content withheld; rescan for project-isolated analysis.'
    return cves


@app.get('/projects/{project_id}/report')
def project_report(project_id: str, template: bool = False, user: dict = Depends(require_auth)):
    check_project(user, project_id)
    with get_conn() as conn:
        runs = [dict(r) for r in conn.execute('SELECT * FROM runs WHERE project_id=? ORDER BY started_at DESC', (project_id,))]
    rows = [] if template else [(run,cve) for run in runs for cve in _report_cves(user,run)]
    return Response(project_reports.export(rows), media_type='text/csv', headers={
        'Content-Disposition': 'attachment; filename="project-template.csv"' if template else 'attachment; filename="project-report.csv"'})


@app.post('/projects/{project_id}/report')
def import_project_report(project_id: str, req: CsvImportRequest, user: dict = Depends(require_auth)):
    check_project(user, project_id)
    # Any project member may upload. What each role may actually change is enforced per row by
    # _validate_transition (DevOps can only submit; Admin/DSO approve pending; only Cyber
    # approves submitted findings or rejects), so the upload cannot bypass the review workflow.
    rows = project_reports.parse(req.content)
    with REVIEW_LOCK:
        changes = []
        run_cache = {}
        finding_cache = {}
        for number, row in enumerate(rows, 2):
            if row['Run ID'] not in run_cache:
                run_cache[row['Run ID']] = check_run(user,row['Run ID'])
                finding_cache[row['Run ID']] = {(c['id'],c['pkg']): c for c in get_cves(row['Run ID'])}
            run = run_cache[row['Run ID']]
            if run['project_id'] != project_id:
                raise HTTPException(422, f'Row {number}: finding belongs to another project')
            if row['Image'] != run['image_ref']:
                raise HTTPException(422, f'Row {number}: image does not match run')
            cve = finding_cache[run['run_id']].get((row['CVE ID'],row['Package']))
            if cve is None:
                raise HTTPException(422, f'Row {number}: finding not found')
            if row['Version'] != (cve.get('version') or '') or row['Severity'] != cve['severity']:
                raise HTTPException(422, f'Row {number}: finding metadata has changed')
            unchanged = all(row[k] == (cve.get(v) or '') for k,v in [('Status','status'),('Justification','rationale'),('Remediation','remediation'),('Manual Notes','manual_notes')])
            if unchanged:
                continue
            if run['status'] != 'awaiting_approval':
                raise HTTPException(409, f'Row {number}: run is not awaiting approval')
            _validate_transition(user,cve['status'],row['Status'])
            if row['Status'] not in ('submitted','approved','rejected'):
                raise HTTPException(422, f'Row {number}: Status must be submitted, approved or rejected')
            if not row['Justification'].strip() or not row['Remediation'].strip():
                raise HTTPException(422, f'Row {number}: justification and remediation are required')
            changes.append((run['run_id'],cve,row['Status'],row['Manual Notes'],row['Justification'],row['Remediation']))
        _write_reviews(changes,user)
    return {'updated': len(changes), 'unchanged': len(rows)-len(changes)}


@app.post('/run/{run_id}/baseline')
def publish_baseline(run_id: str, req: BaselineRequest, user: dict = Depends(require_auth)):
    run = check_run(user,run_id)
    if not _roles(user) & CYBER_APPROVER_ROLES:
        raise HTTPException(403, 'Only Cyber Managers can publish a shared baseline')
    if not run.get('project_scoped'):
        raise HTTPException(409, 'Rescan legacy findings before publishing a baseline')
    cve = next((c for c in get_cves(run_id) if c['id']==req.cve_id and c['pkg']==req.pkg),None)
    if not cve or cve['status'] != 'approved':
        raise HTTPException(409, 'Only an approved finding can be published')
    if not req.justification.strip() or not req.remediation.strip():
        raise HTTPException(422, 'Provide shareable justification and remediation')
    return {'id': baselines.publish(run_id,cve,req.justification,req.remediation,user['name'])}


@app.get('/baselines')
def list_baselines(user: dict = Depends(require_auth)):
    return baselines.references()


@app.delete('/baselines/{baseline_id}')
def revoke_baseline(baseline_id: str, user: dict = Depends(require_auth)):
    if not _roles(user) & CYBER_APPROVER_ROLES:
        raise HTTPException(403, 'Only Cyber Managers can withdraw a baseline')
    with get_conn() as conn:
        row = conn.execute('SELECT source_run FROM shared_baselines WHERE id=? AND active=1',(baseline_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Baseline not found')
        check_run(user,row['source_run'])
        conn.execute('UPDATE shared_baselines SET active=0 WHERE id=?',(baseline_id,))
    return {'ok': True}


@app.get("/scans")
def list_scans(project_id: str | None = None, user: dict = Depends(require_auth)):
    """Return past scan summaries for the dashboard table — sourced from SQLite."""
    return get_scan_summaries(project_ids=accessible_projects(user, project_id))


# ── Reports ────────────────────────────────────────────────────────────────

def _report_filename(image_ref: str, run_id: str, ext: str) -> str:
    safe_image = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_ref or "image").strip("_") or "image"
    return f"report_{safe_image}_{run_id[:8]}.{ext}"


def _pdf_safe(text) -> str:
    """fpdf2's core Helvetica font only supports latin-1 — replace anything else
    rather than let an unexpected character (em dash, curly quote, emoji, …) in
    AI-generated text crash report generation."""
    return str(text if text is not None else "").encode("latin-1", "replace").decode("latin-1")


def _build_csv_report(run: dict, cves: list[dict]) -> str:
    return project_reports.export([(run, cve) for cve in cves])


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
    cves = _report_cves(user, run)
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
