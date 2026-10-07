"""
Node 03 — Human Approval Gate
Uses LangGraph interrupt() to pause the graph and wait for the human decision.
Resume by calling: GRAPH.stream(Command(resume=decision_payload), config=config)
"""
from __future__ import annotations

from langgraph.types import interrupt

from agent.state import AgentState, AgentStep


def approval_node(state: AgentState) -> dict:
    """
    LangGraph node: find the first pending CVE, interrupt() to surface it,
    then apply the human decision on resume.

    LangGraph interrupt() contract:
      - Calling interrupt(value) raises an internal exception that checkpoints
        the graph and returns the value to the caller.
      - On resume via Command(resume=payload), execution continues from the
        line AFTER the interrupt() call with `payload` as the return value.
    """
    steps = list(state.get("agent_steps", []))
    cves = [dict(c) for c in state["cves"]]

    # Find next CVE that is pending (has a rationale, awaiting human decision)
    pending = [i for i, c in enumerate(cves) if c["status"] == "pending"]
    if not pending:
        # Nothing left — route to persist
        return {"cves": cves, "agent_steps": steps}

    current_idx = pending[0]
    current_cve = cves[current_idx]

    # Add a waiting step to the timeline
    steps.append(
        AgentStep(
            id=f"approval-{current_cve['id']}",
            title=f"Awaiting authority approval — {current_cve['id']}",
            desc="Human security lead review gate. Interrupt active.",
            chips=[{"label": "human_gate", "variant": "stream"}],
            state="active",
        )
    )

    # ── INTERRUPT: pause graph here, return current CVE info to the API ───
    decision_payload = interrupt(
        {
            "cve_id": current_cve["id"],
            "cve": current_cve,
        }
    )
    # ─────────────────────────────────────────────────────────────────────
    # Execution resumes HERE after Command(resume=decision_payload) is sent

    cve_id = decision_payload.get("cve_id", current_cve["id"])
    decision = decision_payload.get("decision", "rejected")
    edited_rationale = decision_payload.get("edited_rationale")

    # Apply decision to the matching CVE
    for i, cve in enumerate(cves):
        if cve["id"] == cve_id:
            cves[i]["status"] = decision
            if edited_rationale:
                cves[i]["rationale"] = edited_rationale
            break

    # Mark the approval step as done
    for step in steps:
        if step["id"] == f"approval-{cve_id}":
            step["state"] = "done"
            step["chips"] = [{"label": decision, "variant": "done"}]
            break

    approved = sum(1 for c in cves if c["status"] == "approved")
    rejected = sum(1 for c in cves if c["status"] == "rejected")

    return {
        "cves": cves,
        "agent_steps": steps,
        "human_decision": None,
        "approved": approved,
        "rejected": rejected,
    }
