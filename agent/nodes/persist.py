"""
Node 04 — Persistence
Embeds approved CVE rationales and upserts them into the Milvus RAG store.
"""
from __future__ import annotations

import time

from agent.state import AgentState, AgentStep
from rag.store import persist_decision
from db.database import get_conn


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

        with get_conn() as conn:
            audit = conn.execute("SELECT reviewer FROM review_audit WHERE run_id=? AND cve_id=? AND pkg=? AND decision='approved' ORDER BY id DESC LIMIT 1",
                                 (state['run_id'],cve['id'],cve['pkg'])).fetchone()
        persist_decision(
            cve_id=cve["id"],
            project_id=project_id,
            severity=cve["severity"],
            rationale=cve["rationale"],
            approver=audit[0] if audit else "Historical reviewer (unrecorded)",
            decision="approved",
            pkg=cve["pkg"], remediation=cve.get("remediation", ""), run_id=state["run_id"],
            image_ref=state.get("image_ref", ""),
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
