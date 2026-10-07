"""
LangGraph pipeline — Agentic Cloud Security Control Tower
Graph topology:
    ingest → synthesis → approval ──(more pending?)──→ approval  (loop)
                                  └─(all done)───────→ persist → END
"""
from __future__ import annotations

import uuid
from typing import Literal

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from agent.state import AgentState
from agent.nodes.ingest import ingest_node
from agent.nodes.synthesis import synthesis_node
from agent.nodes.approval import approval_node
from agent.nodes.persist import persist_node


# ── Routing logic ──────────────────────────────────────────────────────────────

def _route_after_approval(state: AgentState) -> Literal["approval", "persist"]:
    """Loop back to approval if there are still pending CVEs; otherwise persist."""
    pending = [c for c in state["cves"] if c["status"] == "pending"]
    return "approval" if pending else "persist"


# ── Build the graph ────────────────────────────────────────────────────────────

def build_graph(checkpointer=None) -> StateGraph:
    builder = StateGraph(AgentState)

    builder.add_node("ingest", ingest_node)
    builder.add_node("synthesis", synthesis_node)
    builder.add_node("approval", approval_node)
    builder.add_node("persist", persist_node)

    builder.set_entry_point("ingest")
    builder.add_edge("ingest", "synthesis")
    builder.add_edge("synthesis", "approval")
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
    trivy_json: dict,
    image_ref: str = "",
    project_id: str = "",
    cis_profile: str = "CIS Level 1",
    severity_threshold: str = "high",
    run_id: str | None = None,
) -> AgentState:
    return AgentState(
        run_id=run_id or str(uuid.uuid4()),
        image_ref=image_ref,
        project_id=project_id,
        cis_profile=cis_profile,
        severity_threshold=severity_threshold,
        trivy_json=trivy_json,
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
