"""
Node 04 — Persistence
Embeds approved CVE rationales and upserts them into the Milvus RAG store.
"""
from __future__ import annotations

import time

from agent.state import AgentState, AgentStep
from rag.store import persist_decision


def persist_node(state: AgentState) -> dict:
    """
    LangGraph node: write all approved decisions to RAG memory.
    Called once after all CVEs have been through the approval gate.
    """
    cves = state["cves"]
    project_id = state.get("project_id", "UNKNOWN")
    steps = list(state.get("agent_steps", []))

    persisted = 0
    for cve in cves:
        if cve["status"] != "approved":
            continue
        if not cve.get("rationale"):
            continue

        persist_decision(
            cve_id=cve["id"],
            project_id=project_id,
            severity=cve["severity"],
            rationale=cve["rationale"],
            approver="Auth Lead",   # populated from session in production
            decision="approved",
        )
        persisted += 1

    steps.append(
        AgentStep(
            id="persist",
            title=f"Persisted {persisted} decision(s) to RAG memory",
            desc=f"Project {project_id} · {persisted} approved rationale(s) stored.",
            chips=[
                {"label": "◈ persist_decision", "variant": "rag"},
                {"label": f"{persisted} stored", "variant": "done"},
            ],
            state="done",
        )
    )

    return {"agent_steps": steps}
