"""
Node 02b - Agentic auto-triage.

Runs after synthesis, before the human gate. For each still-pending finding it
checks whether a Cyber Manager has *explicitly published a shared baseline* for
the same CVE id + package. If so, the agent adopts that baseline decision and
auto-approves the finding, writing a full audit trail. Any finding without a
published baseline is left `pending` for a human.

An exact CVE+package baseline is a deliberate per-finding human sign-off, so
severity is NOT re-gated here - the agent only removes the repetitive
re-approval of decisions a human already blessed for cross-project reuse.
"""
from __future__ import annotations

from datetime import datetime, timezone

from agent.state import AgentState, AgentStep
from db.baselines import references, record_revision
from db.database import get_conn


def auto_triage_node(state: AgentState) -> dict:
    enabled = (state.get("auto_approve_below") or "none").lower() != "none"
    if not enabled:  # disabled -> no-op
        return {}

    run_id = state["run_id"]
    cves = [dict(c) for c in state["cves"]]
    steps = list(state.get("agent_steps", []))
    now = datetime.now(timezone.utc).isoformat()
    auto_count = 0

    for c in cves:
        if c.get("status") != "pending":
            continue
        matches = references(c["id"], c["pkg"])  # published shared baselines only
        if not matches:
            continue
        top = matches[0]
        origin = top.get("approver") or "a Cyber Manager"
        # Adopt the human-blessed baseline decision verbatim.
        c["rationale"] = top.get("rationale") or c.get("rationale", "")
        c["remediation"] = top.get("remediation") or c.get("remediation", "")
        c["status"] = "approved"
        c["edited"] = True
        c["edited_by_role"] = "AGENT"
        c["rag_match"] = {
            "pct": 100, "project": "Shared Cyber Manager baseline", "approver": origin,
            "date": top.get("published_at", ""), "summary": c["rationale"],
            "remediation": c["remediation"], "baselineId": top.get("id"),
        }
        # Audit trail: review_audit (attribution for RAG persist) + a revision snapshot.
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO review_audit(run_id,cve_id,pkg,decision,reviewer,reviewed_at) VALUES (?,?,?,?,?,?)",
                (run_id, c["id"], c["pkg"], "approved", f"Agent - baseline by {origin}", now),
            )
        record_revision(
            run_id, c["id"], c["pkg"], "approved", "Control Tower Agent", "AGENT",
            justification=c["rationale"], remediation=c["remediation"], manual_notes="",
            review_comment=f"Auto-approved from a published Cyber Manager baseline (originally approved by {origin}).",
        )
        auto_count += 1

    if auto_count:
        steps.append(AgentStep(
            id="auto-triage",
            title=f"Agent auto-approved {auto_count} finding(s) from baselines",
            desc="Matched findings to Cyber Manager baselines already approved for reuse; everything else was routed to human review.",
            chips=[{"label": "check_baseline", "variant": "rag"},
                   {"label": f"{auto_count} auto-approved", "variant": "done"}],
            state="done",
        ))

    approved = sum(1 for c in cves if c["status"] == "approved")
    rejected = sum(1 for c in cves if c["status"] == "rejected")
    return {"cves": cves, "agent_steps": steps, "approved": approved, "rejected": rejected}
