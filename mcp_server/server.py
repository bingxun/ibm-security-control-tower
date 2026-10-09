"""
Memory Server — Agentic Cloud Security Control Tower
Exposes tools to Bob / LLM agents:
  query_memory      — semantic search over past CVE decisions
  persist_decision  — store a new approved/rejected decision
  synthesise_cve    — ask Bob to generate a mitigation rationale (no watsonx key needed)
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP
from rag.store import query_memory, persist_decision, count_decisions
from db.database import get_session_user, has_project_access, list_projects

mcp = FastMCP(
    name="control-tower-rag",
    instructions=(
        "Tools for the Agentic Cloud Security Control Tower. "
        "Use query_memory to retrieve similar past CVE decisions, "
        "synthesise_cve to generate a mitigation rationale for a CVE finding, "
        "and persist_decision to store approved decisions for future reuse."
    ),
)


def _project_user(session_token: str, project_id: str | None = None) -> dict:
    user = get_session_user(session_token)
    if not user or (project_id is not None and not has_project_access(user, project_id)):
        raise ValueError("Not authenticated or project not assigned")
    return user


@mcp.tool()
def query_memory_tool(
    cve_id: str,
    description: str,
    severity: str,
    top_k: int = 5,
    project_id: str | None = None,
    session_token: str = "",
) -> list[dict]:
    """
    Search the RAG memory store for past decisions similar to the given CVE.

    Args:
        cve_id:      CVE identifier e.g. CVE-2024-3094
        description: Full CVE description text
        severity:    critical | high | medium | low
        top_k:       Maximum number of results to return (default 5)

    Returns:
        List of matching decisions, each with:
        cve_id, project_id, rationale, approver, decision, score (0-100)
    """
    _project_user(session_token, project_id)
    return query_memory(
        cve_id=cve_id,
        description=description,
        severity=severity,
        top_k=top_k,
        project_id=project_id,
    )


@mcp.tool()
def persist_decision_tool(
    cve_id: str,
    project_id: str,
    severity: str,
    rationale: str,
    approver: str,
    decision: str,
    session_token: str = "",
) -> dict:
    """
    Persist an approved or rejected CVE decision to the RAG memory store.
    The rationale is embedded and stored for future semantic retrieval.

    Args:
        cve_id:      CVE identifier e.g. CVE-2024-3094
        project_id:  Project this decision belongs to e.g. CLOUD-247
        severity:    critical | high | medium | low
        rationale:   Full mitigation rationale text
        approver:    Name or ID of the approving authority
        decision:    approved | rejected

    Returns:
        {"id": "<record_id>", "stored": true}
    """
    user = _project_user(session_token, project_id)
    if not (set(user.get("roles") or [user.get("role")]) & {"SUPER_ADMIN", "ADMIN", "CYBER_MANAGER"}):
        raise ValueError("Your role cannot persist decisions")
    record_id = persist_decision(
        cve_id=cve_id,
        project_id=project_id,
        severity=severity,
        rationale=rationale,
        approver=user["name"],
        decision=decision,
    )
    return {"id": record_id, "stored": True}


@mcp.tool()
def memory_stats_tool(session_token: str = "") -> dict:
    """
    Return statistics about the RAG memory store.

    Returns:
        {"total_decisions": int}
    """
    user = _project_user(session_token)
    is_super = "SUPER_ADMIN" in (user.get("roles") or [user.get("role")])
    project_ids = None if is_super else [p["id"] for p in list_projects(user)]
    return {"total_decisions": count_decisions(project_ids)}


@mcp.tool()
def synthesise_cve(
    cve_id: str,
    severity: str,
    pkg: str,
    version: str,
    fixed_in: str,
    cvss: float,
    vector: str,
    description: str,
    impact: str,
    project_id: str,
    cis_profile: str,
    prior_rationale: str = "",
    prior_project: str = "",
    prior_approver: str = "",
) -> dict:
    """
    Generate a concise, technical mitigation rationale for a container CVE finding.

    You are a cloud security architect at IBM. Write a 2-3 sentence mitigation rationale that:
    - States whether the vulnerability is exploitable given typical cloud controls
    - Specifies a concrete remediation action (patch version, config change, or accepted risk)
    - References the CIS profile and project context
    - Uses precise technical language suitable for a CSA Tier 1 security report

    If a prior_rationale is provided, use it as grounding context but write a fresh rationale
    tailored to this specific project.

    Args:
        cve_id:          CVE identifier e.g. CVE-2024-3094
        severity:        critical | high | medium | low
        pkg:             Affected package name
        version:         Installed version
        fixed_in:        Fixed version (empty if no fix available)
        cvss:            CVSS v3 base score
        vector:          Attack vector: Network | Local | Physical
        description:     Full CVE description
        impact:          Short impact summary / title
        project_id:      Project context e.g. CLOUD-247
        cis_profile:     CIS benchmark profile e.g. CIS Docker Benchmark v1.6
        prior_rationale: Optional — rationale from a similar past decision
        prior_project:   Optional — project the prior decision came from
        prior_approver:  Optional — approver of the prior decision

    Returns:
        {"rationale": "<generated text>", "source": "bob"}
    """
    # This tool is intentionally left for Bob to implement via its LLM.
    # When Bob calls this tool it will see the docstring as the prompt and
    # return the generated rationale as the tool result.
    # The fallback below is used only when called outside of Bob context.
    fix_note = f"upgrade to {fixed_in}" if fixed_in else "apply vendor patches when available"
    prior_note = (
        f" Prior decision from {prior_project} (approved by {prior_approver}): {prior_rationale}"
        if prior_rationale else ""
    )
    rationale = (
        f"{cve_id} is a {severity.upper()}-severity vulnerability (CVSS {cvss}) in {pkg} {version} "
        f"exploitable via {vector.lower()} attack vector.{prior_note} "
        f"Under {cis_profile}, the recommended remediation is to {fix_note}; "
        f"assess network-level controls in {project_id} to determine if compensating controls "
        f"reduce exploitability before approving."
    )
    return {"rationale": rationale, "source": "stub"}


if __name__ == "__main__":
    import sys
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "http":
        port = int(os.getenv("MCP_PORT", "8001"))
        # Patch host/port/mount_path onto the existing instance before run()
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port
        mcp.settings.mount_path = "/mcp"
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
