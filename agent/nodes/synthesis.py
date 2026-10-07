"""
Node 02 — Context Synthesis
For each CVE:
  1. Query RAG memory for similar past decisions
  2. Call the Bob MCP server (synthesise_cve tool) to generate a mitigation rationale
  3. Falls back to an offline stub if the MCP server is unreachable

No watsonx API key required — Bob's LLM handles generation.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

from agent.state import AgentState, AgentStep
from rag.store import query_memory

logger = logging.getLogger("control_tower")

MCP_URL  = os.getenv("MCP_URL", "http://localhost:8001/mcp")
MCP_TIMEOUT = int(os.getenv("MCP_TIMEOUT", "30"))   # seconds per CVE


# ── MCP client ─────────────────────────────────────────────────────────────

def _mcp_post(url: str, payload: bytes, headers: dict) -> tuple[str, dict]:
    """POST to MCP, return (raw_body, response_headers_dict)."""
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=MCP_TIMEOUT) as resp:
        return resp.read().decode(), dict(resp.headers)


def _parse_sse(raw: str) -> str:
    """Extract the JSON body from an SSE envelope (data: {...})."""
    for line in raw.splitlines():
        if line.startswith("data:"):
            return line[len("data:"):].strip()
    return raw


def _mcp_call(tool: str, arguments: dict[str, Any]) -> Any:
    """
    Call a tool on the MCP server using the streamable-HTTP transport.
    Handles the initialize → tools/call session flow.
    """
    base_headers = {
        "Content-Type": "application/json",
        "Accept":       "application/json, text/event-stream",
    }

    # 1. Initialize session
    init_payload = json.dumps({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "control-tower", "version": "1.0"},
        },
    }).encode()
    _, init_headers = _mcp_post(MCP_URL, init_payload, base_headers)
    session_id = init_headers.get("mcp-session-id", "")
    if not session_id:
        raise RuntimeError("MCP server did not return a session ID")

    # 2. Call the tool
    call_headers = {**base_headers, "mcp-session-id": session_id}
    call_payload = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode()
    raw, _ = _mcp_post(MCP_URL, call_payload, call_headers)

    body   = _parse_sse(raw)
    result = json.loads(body)

    if "error" in result:
        raise RuntimeError(f"MCP error: {result['error']}")

    content = result.get("result", {}).get("content", [])
    for block in content:
        if block.get("type") == "text":
            try:
                return json.loads(block["text"])
            except json.JSONDecodeError:
                return {"rationale": block["text"], "source": "bob"}

    raise RuntimeError("Empty MCP response")


# ── Offline stub ────────────────────────────────────────────────────────────

def _stub_rationale(cve: dict) -> str:
    """
    Plain-English fallback when the MCP server is unreachable.
    Built entirely from CVE fields — no network call needed.
    """
    sev   = cve["severity"].upper()
    cvss  = cve["cvss"]
    pkg   = cve["pkg"]
    ver   = cve["version"]
    fix   = cve["fixed_in"] or "the latest patched release"
    vec   = cve.get("vector", "Network")
    title = cve.get("impact", "") or cve.get("description", "")[:80]
    return (
        f"{cve['id']} is a {sev}-severity vulnerability (CVSS {cvss}) in {pkg} {ver} "
        f"with a {vec.lower()} attack vector. "
        f"{title + '. ' if title else ''}"
        f"Recommended remediation: upgrade {pkg} to {fix}. "
        f"Review exploitability against this project's network controls before approving."
    )


# ── Synthesis node ──────────────────────────────────────────────────────────

def synthesis_node(state: AgentState) -> dict:
    """
    LangGraph node: synthesise rationale for every queued CVE via Bob MCP.
    Processes all CVEs in one pass. Falls back to offline stub if MCP unavailable.
    """
    cves        = [dict(c) for c in state["cves"]]
    project_id  = state.get("project_id", "UNKNOWN")
    cis_profile = state.get("cis_profile", "CIS Level 1")

    steps: list[AgentStep]     = list(state.get("agent_steps", []))
    total_tokens: int          = state.get("tokens_used", 0)
    rag_hit_count: int         = state.get("rag_hits", 0)
    synthesis_times: list[float] = []
    last_fragment              = ""

    for i, cve in enumerate(cves):
        if cve["status"] not in ("queued",):
            continue

        t0 = time.time()

        # ── 1. RAG retrieval ────────────────────────────────────────────────
        hits = query_memory(
            cve_id=cve["id"],
            description=cve["description"],
            severity=cve["severity"],
        )
        if hits:
            rag_hit_count += 1
            top = hits[0]
            cves[i]["rag_match"] = {
                "pct":      top["score"],
                "project":  top["project_id"],
                "approver": top["approver"],
                "date":     "",
                "summary":  top["rationale"][:120] + "…" if len(top["rationale"]) > 120 else top["rationale"],
            }

        rag_chips = [{"label": "◈ query_memory", "variant": "rag"}]
        rag_chips.append({
            "label":   f"{len(hits)} hit{'s' if len(hits) > 1 else ''}",
            "variant": "done",
        } if hits else {"label": "no prior match", "variant": "stream"})

        steps.append(AgentStep(
            id=f"rag-{cve['id']}",
            title=f"Memory search — {cve['id']}",
            desc=f"{len(hits)} prior decision(s) found." if hits else "No prior match — generating from scratch.",
            chips=rag_chips,
            state="done",
        ))

        # ── 2. Bob MCP synthesis ────────────────────────────────────────────
        rationale = ""
        source    = "stub"

        top_hit = hits[0] if hits else {}
        mcp_args = {
            "cve_id":          cve["id"],
            "severity":        cve["severity"],
            "pkg":             cve["pkg"],
            "version":         cve["version"],
            "fixed_in":        cve.get("fixed_in", ""),
            "cvss":            cve.get("cvss", 0.0),
            "vector":          cve.get("vector", "Network"),
            "description":     cve.get("description", ""),
            "impact":          cve.get("impact", ""),
            "project_id":      project_id,
            "cis_profile":     cis_profile,
            "prior_rationale": top_hit.get("rationale", ""),
            "prior_project":   top_hit.get("project_id", ""),
            "prior_approver":  top_hit.get("approver", ""),
        }

        try:
            result   = _mcp_call("synthesise_cve", mcp_args)
            rationale = result.get("rationale", "")
            source    = result.get("source", "bob")
        except Exception as e:
            logger.warning("MCP synthesise_cve failed for %s (%s) — using stub", cve["id"], e)

        if not rationale:
            rationale = _stub_rationale(cve)
            source    = "stub"

        last_fragment          = rationale
        cves[i]["rationale"]   = rationale
        cves[i]["status"]      = "pending"

        elapsed = round(time.time() - t0, 2)
        synthesis_times.append(elapsed)

        label_variant = "llm" if source == "bob" else "stream"
        source_label  = "bob_mcp" if source == "bob" else "offline_stub"

        steps.append(AgentStep(
            id=f"draft-{cve['id']}",
            title=f"Rationale drafted — {cve['id']}",
            desc=rationale[:120] + "…" if len(rationale) > 120 else rationale,
            chips=[
                {"label": source_label,      "variant": label_variant},
                {"label": f"{elapsed}s",     "variant": "done"},
            ],
            state="done",
        ))

    avg_s = round(sum(synthesis_times) / len(synthesis_times), 1) if synthesis_times else 0.0

    return {
        "cves":           cves,
        "agent_steps":    steps,
        "token_fragment": last_fragment,
        "tokens_used":    total_tokens,
        "rag_hits":       rag_hit_count,
        "avg_synthesis_s": avg_s,
    }
