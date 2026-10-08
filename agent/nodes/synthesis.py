"""
Node 02 — Context Synthesis
For each CVE:
  1. Query RAG memory for similar past decisions
  2. Call IBM Services Essentials gateway (OpenAI-compatible) to generate a mitigation rationale
  3. Falls back to an offline stub if the gateway is unreachable

Set env vars:
  ANTHROPIC_BASE_URL   = https://api.servicesessentials.ibm.com
  ANTHROPIC_AUTH_TOKEN = sk-...                     (your gateway API key)
  RAD_MODEL            = claude-sonnet-4-6          (optional, default below)
  RAD_CONCURRENCY      = 5   (max parallel LLM calls, default 5)
  RAD_RETRIES          = 3   (retries on rate-limit / 5xx, default 3)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request

from agent.state import AgentState, AgentStep
from rag.store import query_memory

logger = logging.getLogger("control_tower")

# ── IBM RAD / Anthropic gateway config ────────────────────────────────────
RAD_BASE_URL    = os.getenv("ANTHROPIC_BASE_URL", "https://llm.ibm-rad.com")
RAD_AUTH_TOKEN  = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
RAD_MODEL       = os.getenv("RAD_MODEL", "claude-sonnet-4-6")
RAD_TIMEOUT     = int(os.getenv("RAD_TIMEOUT", "60"))    # seconds per CVE
RAD_CONCURRENCY = int(os.getenv("RAD_CONCURRENCY", "5")) # parallel calls
RAD_RETRIES     = int(os.getenv("RAD_RETRIES", "3"))     # retries on 429/5xx
RAD_MAX_LLM     = int(os.getenv("RAD_MAX_LLM", "20"))    # max CVEs to call LLM for (top by CVSS)


# ── OpenAI-compatible chat completions client (sync, called from thread pool) ──

def _rad_generate_sync(prompt: str) -> str:
    """
    Call the IBM Services Essentials gateway (OpenAI-compatible /v1/chat/completions).
    Returns the generated text, or raises on error.
    Runs synchronously — called via asyncio.to_thread.
    """
    url = f"{RAD_BASE_URL.rstrip('/')}/v1/chat/completions"

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
            "Content-Type": "application/json",
            "x-api-key":    RAD_AUTH_TOKEN,
        },
        method="POST",
    )

    for attempt in range(RAD_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=RAD_TIMEOUT) as resp:
                body = json.loads(resp.read().decode())
            choices = body.get("choices", [])
            if choices and choices[0].get("message", {}).get("content"):
                return choices[0]["message"]["content"].strip()
            raise RuntimeError(f"Unexpected gateway response: {body}")
        except urllib.error.HTTPError as e:
            if e.code in (429, 529) and attempt < RAD_RETRIES - 1:
                # Rate-limited — back off exponentially
                backoff = 2 ** attempt
                logger.warning("Gateway rate-limited (%s), retrying in %ss (attempt %d/%d)",
                               e.code, backoff, attempt + 1, RAD_RETRIES)
                time.sleep(backoff)
                continue
            raise
    raise RuntimeError("Gateway: exhausted retries")


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


# ── Per-CVE async worker ───────────────────────────────────────────────────

async def _synthesise_one(
    cve: dict,
    project_id: str,
    cis_profile: str,
    sem: asyncio.Semaphore,
    use_llm: bool = True,
) -> dict:
    """
    Async worker for a single CVE:
      - RAG lookup (sync, fast — no I/O throttle needed)
      - RAD call under semaphore (I/O bound) — only when use_llm=True
    Returns a dict with keys: cve, rag_hits, steps, elapsed, source, tokens
    """
    async with sem:
        t0 = time.time()

        # RAG lookup (pure Python, no network — run inline)
        hits = query_memory(
            cve_id=cve["id"],
            description=cve["description"],
            severity=cve["severity"],
            project_id=project_id,
        )

        updated_cve = dict(cve)
        if hits:
            top = hits[0]
            updated_cve["rag_match"] = {
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
        rag_step = AgentStep(
            id=f"rag-{cve['id']}",
            title=f"Memory search — {cve['id']}",
            desc=f"{len(hits)} prior decision(s) found." if hits else "No prior match — generating from scratch.",
            chips=rag_chips,
            state="done",
        )

        # RAD generation — only for top-N CVEs by CVSS (use_llm=True)
        rationale = ""
        source    = "stub"
        tokens    = 0

        if use_llm and RAD_AUTH_TOKEN:
            try:
                prompt    = _build_prompt(updated_cve, hits, project_id, cis_profile)
                # Run blocking HTTP call in thread pool so other CVEs proceed in parallel
                rationale = await asyncio.to_thread(_rad_generate_sync, prompt)
                source    = "rad"
                tokens    = len(prompt.split()) + len(rationale.split())
            except Exception as e:
                logger.warning("RAD gateway failed for %s (%s) — using stub", cve["id"], e)
        elif not use_llm:
            logger.debug("Skipping RAD for %s (below top-%d CVSS threshold)", cve["id"], RAD_MAX_LLM)
        else:
            logger.info("ANTHROPIC_AUTH_TOKEN not set — using stub for %s", cve["id"])

        if not rationale:
            rationale = _stub_rationale(updated_cve)
            source    = "stub"

        updated_cve["rationale"] = rationale
        updated_cve["status"]    = "pending"

        elapsed = round(time.time() - t0, 2)

        label_variant = "llm"     if source == "rad"  else "stream"
        source_label  = "ibm_rad" if source == "rad"  else "offline_stub"

        draft_step = AgentStep(
            id=f"draft-{cve['id']}",
            title=f"Rationale drafted — {cve['id']}",
            desc=rationale[:120] + "…" if len(rationale) > 120 else rationale,
            chips=[
                {"label": source_label, "variant": label_variant},
                {"label": f"{elapsed}s",  "variant": "done"},
            ],
            state="done",
        )

        return {
            "cve":      updated_cve,
            "rag_hits": len(hits),
            "steps":    [rag_step, draft_step],
            "elapsed":  elapsed,
            "source":   source,
            "tokens":   tokens,
        }


# ── Synthesis node ──────────────────────────────────────────────────────────

def synthesis_node(state: AgentState) -> dict:
    """
    LangGraph node: synthesise rationale for every queued CVE.
    Calls IBM RAD gateway with up to RAD_CONCURRENCY parallel requests.
    Falls back to offline stub per CVE if the gateway fails.
    """
    cves        = [dict(c) for c in state["cves"]]
    project_id  = state.get("project_id", "UNKNOWN")
    cis_profile = state.get("cis_profile", "CIS Level 1")

    queued = [(i, cve) for i, cve in enumerate(cves) if cve["status"] == "queued"]

    if not queued:
        return {}

    # Determine which CVEs get real LLM calls: top RAD_MAX_LLM by CVSS score
    sorted_by_cvss = sorted(queued, key=lambda x: float(x[1].get("cvss", 0)), reverse=True)
    llm_set = {cve["id"] for _, cve in sorted_by_cvss[:RAD_MAX_LLM]}
    logger.info("synthesis_node: %d queued CVEs, %d will use LLM (top CVSS), %d will use stub",
                len(queued), len(llm_set), len(queued) - len(llm_set))

    async def _run_all():
        sem = asyncio.Semaphore(RAD_CONCURRENCY)
        tasks = [
            _synthesise_one(cve, project_id, cis_profile, sem, use_llm=(cve["id"] in llm_set))
            for _, cve in queued
        ]
        return await asyncio.gather(*tasks)

    # Run the async batch — works whether or not there's an existing event loop
    try:
        loop = asyncio.get_running_loop()
        # We're inside an existing loop (e.g. FastAPI); run in a new thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, _run_all())
            results = future.result()
    except RuntimeError:
        results = asyncio.run(_run_all())

    # Merge results back into cves list
    steps: list[AgentStep] = list(state.get("agent_steps", []))
    total_tokens   = state.get("tokens_used", 0)
    rag_hit_count  = state.get("rag_hits", 0)
    elapsed_times  = []
    last_fragment  = ""

    for (orig_idx, _), result in zip(queued, results):
        cves[orig_idx] = result["cve"]
        steps.extend(result["steps"])
        total_tokens  += result["tokens"]
        rag_hit_count += result["rag_hits"]
        elapsed_times.append(result["elapsed"])
        last_fragment = result["cve"]["rationale"]

    avg_s = round(sum(elapsed_times) / len(elapsed_times), 1) if elapsed_times else 0.0

    return {
        "cves":            cves,
        "agent_steps":     steps,
        "token_fragment":  last_fragment,
        "tokens_used":     total_tokens,
        "rag_hits":        rag_hit_count,
        "avg_synthesis_s": avg_s,
    }
