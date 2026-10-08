"""
Scoped product assistant — answers ONLY about Control Tower (the product, its
review workflow and features) and about container vulnerabilities / the findings
in the user's workspace. Anything else is politely declined.

Reuses the IBM Services Essentials gateway from the synthesis node; falls back
to a deterministic offline responder when the gateway is unavailable.
"""
from __future__ import annotations

import logging

from agent.nodes import synthesis  # reference attrs via module so tests can patch

logger = logging.getLogger("control_tower")

PRODUCT_FACTS = """ABOUT CONTROL TOWER (ground truth — use this to answer product questions):
- Control Tower is an agentic container-security review platform. It scans container images with Trivy, an AI agent synthesises a justification and remediation for each CVE, and humans approve or reject findings through a review workflow.
- Review workflow states: queued -> pending -> submitted -> approved | rejected, plus changes_requested.
  * DevOps Engineers prepare a finding (edit the justification, proposed remediation and notes) and SUBMIT it for approval.
  * Cyber Managers review SUBMITTED findings and either APPROVE (optionally with a note) or "Reject & request changes" (which sends it back as CHANGES_REQUESTED with a reason and the evidence required).
  * DevOps then revise and RESUBMIT a changes_requested finding. Every submission and decision is preserved as a revision in the history.
- Review AI: both roles get an on-demand assistant that evaluates a draft (DevOps) or helps draft review comments (Cyber). It only suggests; it never changes a finding or its status automatically.
- Roles: Super Admin (everything), DevOps Engineer (scan + submit), Cyber Manager (approve/reject submitted findings), DSO Manager (scan + project admin), Admin.
- Shared baselines: a Cyber Manager can publish an approved finding as a cross-project reference. Approved rationales are also remembered (RAG memory) and surfaced on future scans.
- Reports: findings export to CSV/PDF; Cyber Managers can bulk-import completed reviews via CSV."""

SYSTEM = """You are the Control Tower Assistant, an in-product helper.

STRICT SCOPE — you may ONLY discuss:
  1. This product (Control Tower): how it works, the review workflow, roles, features, how to do something in the app.
  2. Container vulnerabilities / CVEs and the specific findings in the user's workspace (shown below as context).

If the user asks about anything else — general knowledge, chit-chat, coding help unrelated to CVEs, other products, personal questions, world facts — politely decline in one sentence and steer back, e.g. "I can only help with Control Tower and the vulnerabilities in your workspace." Do not answer the off-topic question even partially.

Rules:
- Be concise and practical. Prefer short paragraphs or tight bullet lists.
- Formatting: this renders in a narrow chat bubble. Use short paragraphs, "- " bullet lists, **bold** for key terms, and `code` for statuses/fields. Do NOT use Markdown tables, headings larger than "##", or horizontal rules.
- For finding-specific facts (status, severity, rationale, remediation), use ONLY the WORKSPACE CONTEXT below. If it is not in the context, say you don't have that finding in view rather than inventing details.
- Never fabricate CVE identifiers, CVSS scores, or remediation that aren't in the context.
- You are advisory: you cannot approve, reject, or submit anything yourself — tell the user which action/role does that."""


def _format_context(findings_context: str) -> str:
    return findings_context.strip() or "(No findings are currently in view for this user.)"


def _build_prompt(messages: list[dict], findings_context: str) -> str:
    convo = []
    for m in messages[-8:]:
        role = "User" if m.get("role") == "user" else "Assistant"
        convo.append(f"{role}: {m.get('content','').strip()}")
    convo_text = "\n".join(convo)
    return f"""{SYSTEM}

{PRODUCT_FACTS}

WORKSPACE CONTEXT (the findings/scans this user can see):
{_format_context(findings_context)}

Conversation so far:
{convo_text}
Assistant:"""


# ── Offline fallback ─────────────────────────────────────────────────────────
_ONTOPIC = ("cve", "vuln", "finding", "scan", "approve", "reject", "submit", "review",
            "remediation", "severity", "cvss", "baseline", "rationale", "control tower",
            "workflow", "devops", "cyber", "role", "report", "image", "container",
            "changes", "revise", "resubmit", "how do i", "what is", "help", "memory", "rag")


def _stub(messages: list[dict], findings_context: str) -> str:
    last = (messages[-1]["content"] if messages else "").lower().strip()
    if not last:
        return "Hi — I can help with Control Tower and the vulnerabilities in your workspace. Ask me how the review workflow works, or about a specific finding you can see."
    greet = any(g in last for g in ("hello", "hi", "hey", "thanks", "thank you"))
    on_topic = any(k in last for k in _ONTOPIC)
    if greet and not on_topic:
        return "Hello! I can explain how Control Tower works or help with the CVEs in your workspace. What would you like to know?"
    if not on_topic:
        return "I can only help with Control Tower and the vulnerabilities in your workspace, so I can't help with that. Try asking about the review workflow, a role, or a specific finding."
    if any(k in last for k in ("workflow", "how does", "how do i", "approve", "submit", "reject", "review", "changes", "resubmit")):
        return ("In Control Tower, a DevOps Engineer prepares a finding (justification, proposed remediation, notes) and submits it. "
                "A Cyber Manager then approves it or uses \"Reject & request changes\" to send it back with the evidence required; "
                "DevOps revises and resubmits. Every round is kept in the revision history. "
                "(Offline mode: connect the AI gateway for richer answers.)")
    if any(k in last for k in ("cve", "finding", "severity", "remediation", "which", "list", "open")):
        ctx = findings_context.strip()
        return (f"Here's what I can see in your workspace:\n\n{ctx}\n\nAsk about any of these by CVE id or package."
                if ctx else "I don't have any findings in view for you right now. Open a scan to see its findings.")
    return ("I can help with the review workflow, roles, reports, shared baselines, or any specific finding in your workspace. "
            "What would you like to know? (Offline mode — connect the AI gateway for richer answers.)")


def answer(messages: list[dict], findings_context: str) -> dict:
    """Return {reply, source}. Scoped to product + the user's visible findings."""
    if synthesis.RAD_AUTH_TOKEN:
        try:
            reply = synthesis._rad_generate_sync(_build_prompt(messages, findings_context), max_tokens=700)
            if reply:
                return {"reply": reply.strip(), "source": "rad"}
        except Exception as e:
            logger.warning("Assistant gateway failed (%s) — using offline responder", e)
    return {"reply": _stub(messages, findings_context), "source": "stub"}
