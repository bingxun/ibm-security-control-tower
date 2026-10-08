"""
Node 02 — Context Synthesis
For each CVE:
  1. Query RAG memory for similar past decisions
  2. Call IBM RAD gateway (Anthropic-compatible) to generate a mitigation rationale
  3. Falls back to an offline stub if the gateway is unreachable

Set env vars:
  ANTHROPIC_BASE_URL   = https://llm.ibm-rad.com   (or any LiteLLM gateway)
  ANTHROPIC_AUTH_TOKEN = sk-...                     (your RAD usage key)
  RAD_MODEL            = claude-3-5-sonnet-20241022 (optional, default below)
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from typing import Any

from agent.state import AgentState, AgentStep
from rag.store import query_memory

logger = logging.getLogger("control_tower")

# ── IBM RAD / Anthropic gateway config ────────────────────────────────────
RAD_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://llm.ibm-rad.com")
RAD_AUTH_TOKEN = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
RAD_MODEL    = os.getenv("RAD_MODEL", "global.anthropic.claude-sonnet-4-6")
RAD_TIMEOUT  = int(os.getenv("RAD_TIMEOUT", "60"))   # seconds per CVE


# ── Anthropic messages API client ──────────────────────────────────────────

def _rad_generate(prompt: str) -> str:
    """
    Call the IBM RAD gateway (Anthropic-compatible /v1/messages endpoint).
    Returns the generated text, or raises on error.
    """
    url = f"{RAD_BASE_URL.rstrip('/')}/v1/messages"

    payload = json.dumps({
        "model":      RAD_MODEL,
        "max_tokens": 300,
        "messages": [
            {"role": "user", "content": prompt}
        ],
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         RAD_AUTH_TOKEN,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=RAD_TIMEOUT) as resp:
        body = json.loads(resp.read().decode())

    # Anthropic response: body["content"][0]["text"]
    content = body.get("content", [])
    if content and content[0].get("type") == "text":
        return content[0]["text"].strip()

    raise RuntimeError(f"Unexpected RAD response: {body}")


# ── Prompt builder ─────────────────────────────────────────────────────────

def _build_prompt(cve: dict, hits: list[dict], project_id: str, cis_profile: str) -> str:
    prior = ""
    if hits:
        top = hits[0]
        prior = (
            f"\n\nPRIOR DECISION (similarity {top['score']}% — project {top['project_id']}, "
            f"approved by {top['approver']}):\n{top['rationale']}"
        )

    return f"""You are a cloud security architect at IBM. Write a concise, technical mitigation rationale for the following container vulnerability finding.

The rationale MUST:
- State whether the vulnerability is exploitable given typical cloud network controls
- Specify a concrete remediation action (patch version, config change, or accepted risk)
- Reference the CIS profile and project context
- Be 2-3 sentences maximum
- Use precise technical language suitable for a CSA Tier 1 security report

PROJECT: {project_id}
CIS PROFILE: {cis_profile}
CVE ID: {cve['id']}
PACKAGE: {cve['pkg']} {cve['version']} (fix: {cve.get('fixed_in','N/A')})
SEVERITY: {cve['severity'].upper()} (CVSS {cve.get('cvss', 0)})
ATTACK VECTOR: {cve.get('vector','Network')}
IMPACT: {cve.get('impact','')}
DESCRIPTION: {cve.get('description','')}{prior}

Write the mitigation rationale now (2-3 sentences only):"""


# ── Offline stub ────────────────────────────────────────────────────────────

def _stub_rationale(cve: dict) -> str:
    """Plain-English fallback when the RAD gateway is unreachable."""
    sev  = cve["severity"].upper()
    pkg  = cve["pkg"]
    ver  = cve["version"]
    fix  = cve.get("fixed_in") or "the latest patched release"
    vec  = cve.get("vector", "Network")
    desc = cve.get("impact", "") or cve.get("description", "")[:80]
    return (
        f"{cve['id']} is a {sev}-severity vulnerability (CVSS {cve.get('cvss',0)}) "
        f"in {pkg} {ver} with a {vec.lower()} attack vector. "
        f"{desc + '. ' if desc else ''}"
        f"Recommended remediation: upgrade {pkg} to {fix}. "
        f"Review exploitability against this project's network controls before approving."
    )


# ── Synthesis node ──────────────────────────────────────────────────────────

def synthesis_node(state: AgentState) -> dict:
    """
    LangGraph node: synthesise rationale for every queued CVE.
    Calls the IBM RAD gateway (Anthropic-compatible). Falls back to offline stub.
    """
    cves        = [dict(c) for c in state["cves"]]
    project_id  = state.get("project_id", "UNKNOWN")
    cis_profile = state.get("cis_profile", "CIS Level 1")

    steps: list[AgentStep]       = list(state.get("agent_steps", []))
    total_tokens: int            = state.get("tokens_used", 0)
    rag_hit_count: int           = state.get("rag_hits", 0)
    synthesis_times: list[float] = []
    last_fragment                = ""

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
        rag_chips.append(
            {"label": f"{len(hits)} hit{'s' if len(hits) > 1 else ''}", "variant": "done"}
            if hits else {"label": "no prior match", "variant": "stream"}
        )
        steps.append(AgentStep(
            id=f"rag-{cve['id']}",
            title=f"Memory search — {cve['id']}",
            desc=f"{len(hits)} prior decision(s) found." if hits else "No prior match — generating from scratch.",
            chips=rag_chips,
            state="done",
        ))

        # ── 2. IBM RAD generation ───────────────────────────────────────────
        rationale = ""
        source    = "stub"

        if RAD_AUTH_TOKEN:
            try:
                prompt    = _build_prompt(cve, hits, project_id, cis_profile)
                rationale = _rad_generate(prompt)
                source    = "rad"
                # rough token estimate
                total_tokens += len(prompt.split()) + len(rationale.split())
            except Exception as e:
                logger.warning("RAD gateway failed for %s (%s) — using stub", cve["id"], e)
        else:
            logger.info("ANTHROPIC_AUTH_TOKEN not set — using stub for %s", cve["id"])

        if not rationale:
            rationale = _stub_rationale(cve)
            source    = "stub"

        last_fragment        = rationale
        cves[i]["rationale"] = rationale
        cves[i]["status"]    = "pending"

        elapsed = round(time.time() - t0, 2)
        synthesis_times.append(elapsed)

        label_variant = "llm"    if source == "rad"  else "stream"
        source_label  = "ibm_rad" if source == "rad" else "offline_stub"

        steps.append(AgentStep(
            id=f"draft-{cve['id']}",
            title=f"Rationale drafted — {cve['id']}",
            desc=rationale[:120] + "…" if len(rationale) > 120 else rationale,
            chips=[
                {"label": source_label, "variant": label_variant},
                {"label": f"{elapsed}s", "variant": "done"},
            ],
            state="done",
        ))

    avg_s = round(sum(synthesis_times) / len(synthesis_times), 1) if synthesis_times else 0.0

    return {
        "cves":            cves,
        "agent_steps":     steps,
        "token_fragment":  last_fragment,
        "tokens_used":     total_tokens,
        "rag_hits":        rag_hit_count,
        "avg_synthesis_s": avg_s,
    }
