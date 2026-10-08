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

    # Step id is scoped by position, not just the CVE id — the same CVE id can
    # appear more than once in a run (e.g. musl + musl-utils share one CVE),
    # and a plain f"approval-{id}" would collide between those entries.
    step_id = f"approval-{current_idx}-{current_cve['id']}"

    # Add a waiting step to the timeline
    steps.append(
        AgentStep(
            id=step_id,
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
    #
    # IMPORTANT: the UI lets a human decide on CVEs in any order, not just
    # whichever one this interrupt happened to pause on (`current_cve`) — so
    # the resume payload's `cve_id` may refer to a *different* CVE than
    # `current_idx`. We must look it up again, matched by id (and `pkg` when
    # given, to disambiguate the rare case where one CVE id spans multiple
    # packages in the same run — e.g. musl + musl-utils). Do NOT apply the
    # decision to `cves[current_idx]` directly; that would silently
    # misattribute it whenever the human didn't act in backend-pending order.

    target_cve_id = decision_payload.get("cve_id", current_cve["id"])
    target_pkg    = decision_payload.get("pkg")
    decision      = decision_payload.get("decision", "rejected")
    manual_notes  = decision_payload.get("edited_rationale")  # field name kept for API compat

    target_idx = None
    for i, cve in enumerate(cves):
        if cve["id"] != target_cve_id:
            continue
        if target_pkg is not None and cve["pkg"] != target_pkg:
            continue
        target_idx = i
        break
    if target_idx is None:
        # No pkg given and/or no exact match found — fall back to whichever
        # CVE this interrupt actually paused on, so a decision is never lost.
        target_idx = current_idx

    cves[target_idx]["status"] = decision
    if manual_notes:
        cves[target_idx]["manual_notes"] = manual_notes
        cves[target_idx]["edited"] = True
        cves[target_idx]["edited_by_role"] = decision_payload.get("edited_by_role", "")

    # Mark the step for whichever CVE was actually decided as done — not
    # necessarily `step_id` (the one this interrupt paused on) if the human
    # acted on a different, already-pending CVE out of order. The step for
    # that CVE was created with this exact id the one time it was itself
    # `current_idx` — exact match (not just an id suffix) so this can't
    # collide between two entries that happen to share the same CVE id.
    decided_step_id = f"approval-{target_idx}-{cves[target_idx]['id']}"
    for step in steps:
        if step["id"] == step_id or step["id"] == decided_step_id:
            step["state"] = "done"
            step["chips"] = [{"label": decision, "variant": "done"}]

    approved = sum(1 for c in cves if c["status"] == "approved")
    rejected = sum(1 for c in cves if c["status"] == "rejected")

    return {
        "cves": cves,
        "agent_steps": steps,
        "human_decision": None,
        "approved": approved,
        "rejected": rejected,
    }
