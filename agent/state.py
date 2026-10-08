"""
AgentState — shared state dict threaded through every LangGraph node.
"""
from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict


class CveRecord(TypedDict):
    id: str
    severity: str          # critical | high | medium | low
    pkg: str
    version: str
    fixed_in: str
    cvss: float
    vector: str
    auth_required: str
    impact: str
    description: str
    rationale: str         # justification text — filled by synthesis node
    remediation: str       # concrete fix action — filled by synthesis node
    manual_notes: str      # human-added remarks, kept separate from the AI text
    edited: bool           # True once a human has added manual notes
    edited_by_role: str    # role of the human who added manual_notes (e.g. "ADMIN")
    rag_match: Optional[dict]  # filled by synthesis node
    status: str            # queued | pending | approved | rejected


class AgentStep(TypedDict):
    id: str
    title: str
    desc: str
    chips: list[dict]
    state: str             # done | active | waiting


class AgentState(TypedDict):
    # ── Input ──────────────────────────────────────────────────────────────
    run_id: str
    image_ref: str
    project_id: str
    cis_profile: str
    severity_threshold: str    # critical | high | medium | low — filter applied at ingest
    trivy_json: dict           # raw Trivy JSON blob

    # ── Pipeline state ─────────────────────────────────────────────────────
    cves: list[CveRecord]          # populated by ingest node
    current_cve_index: int         # which CVE the agent is currently working on
    agent_steps: list[AgentStep]   # timeline shown in the UI drawer

    # ── Streaming ──────────────────────────────────────────────────────────
    token_fragment: str            # partial Granite stream for the UI

    # ── Stats ───────────────────────────────────────────────────────────────
    total: int
    approved: int
    rejected: int
    avg_synthesis_s: float
    rag_hits: int
    tokens_used: int

    # ── Human gate ─────────────────────────────────────────────────────────
    # LangGraph interrupt() stores the resume payload here
    human_decision: Optional[dict]  # {cve_id, decision, edited_rationale?}
