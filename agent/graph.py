"""
LangGraph pipeline — Agentic Cloud Security Control Tower
Graph topology:
    ingest → master → synthesis (parallel CVE slaves) → approval ──(more pending?)──→ approval  (loop)
                                  └─(all done)───────→ persist → END
"""
from __future__ import annotations

import uuid
from typing import Literal

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from agent.state import AgentState
from agent.nodes.ingest import ingest_node
from agent.nodes.master import master_node
from agent.nodes.synthesis import synthesis_node
from agent.nodes.auto_triage import auto_triage_node
from agent.nodes.approval import approval_node
from agent.nodes.persist import persist_node


# ── Routing logic ──────────────────────────────────────────────────────────────

def _route_after_approval(state: AgentState) -> Literal["approval", "persist"]:
    """Loop back to approval while any CVE is still non-terminal; otherwise persist.

    Non-terminal = awaiting a human: `pending` (not yet submitted), `submitted`
    (awaiting Cyber approval), or `changes_requested` (sent back to DevOps to
    revise and resubmit). Persist runs only once every CVE is approved/rejected.
    """
    non_terminal = [c for c in state["cves"] if c["status"] in ("pending", "submitted", "changes_requested")]
    return "approval" if non_terminal else "persist"


# ── Build the graph ────────────────────────────────────────────────────────────

def build_graph(checkpointer=None) -> StateGraph:
    builder = StateGraph(AgentState)

    builder.add_node("ingest", ingest_node)
    builder.add_node("master", master_node)
    builder.add_node("synthesis", synthesis_node)
    builder.add_node("auto_triage", auto_triage_node)
    builder.add_node("approval", approval_node)
    builder.add_node("persist", persist_node)

    builder.set_entry_point("ingest")
    builder.add_edge("ingest", "master")
    builder.add_edge("master", "synthesis")
    builder.add_edge("synthesis", "auto_triage")
    builder.add_edge("auto_triage", "approval")
    builder.add_conditional_edges(
        "approval",
        _route_after_approval,
        {"approval": "approval", "persist": "persist"},
    )
    builder.add_edge("persist", END)

    return builder.compile(
        checkpointer=checkpointer or MemorySaver(),
    )


def make_initial_state(
    scan_json: dict,
    image_ref: str = "",
    project_id: str = "",
    cis_profile: str = "CIS Level 1",
    severity_threshold: str = "high",
    scanner: str = "trivy",
    run_id: str | None = None,
    environment_markdown: str = "",
    auto_approve_below: str = "none",
    severities: list[str] | None = None,
) -> AgentState:
    return AgentState(
        run_id=run_id or str(uuid.uuid4()),
        image_ref=image_ref,
        project_id=project_id,
        cis_profile=cis_profile,
        environment_markdown=environment_markdown,
        severity_threshold=severity_threshold,
        severities=[s.lower() for s in severities or []],
        scanner=scanner,
        scan_json=scan_json,
        auto_approve_below=auto_approve_below,
        cves=[],
        current_cve_index=0,
        agent_steps=[],
        token_fragment="",
        total=0,
        approved=0,
        rejected=0,
        avg_synthesis_s=0.0,
        rag_hits=0,
        tokens_used=0,
        human_decision=None,
    )
