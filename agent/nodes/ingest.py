"""
Node 01 — Scan Ingest
Parses a Trivy JSON vulnerability report into a list of CveRecord dicts.
Trivy JSON schema ref: https://github.com/aquasecurity/trivy/blob/main/pkg/types/report.go
"""
from __future__ import annotations

import time
from typing import Any

from agent.state import AgentState, CveRecord, AgentStep


# Trivy severity → our severity normalisation
_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}

# Severity levels in ascending order — used for threshold filtering
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# CVSS vector shorthand
def _vector_label(vuln: dict) -> str:
    """Return 'Network' | 'Local' | 'Physical' from CVSS vector string."""
    v = (
        vuln.get("CVSS", {})
        .get("nvd", {})
        .get("V3Vector", "")
        or vuln.get("CVSS", {})
        .get("redhat", {})
        .get("V3Vector", "")
    )
    if "AV:N" in v:
        return "Network"
    if "AV:L" in v:
        return "Local"
    if "AV:P" in v:
        return "Physical"
    return "Network"  # safe default


def _cvss_score(vuln: dict) -> float:
    """Extract best available CVSS v3 score."""
    for source in ("nvd", "redhat", "ghsa"):
        score = (
            vuln.get("CVSS", {})
            .get(source, {})
            .get("V3Score")
        )
        if score is not None:
            return float(score)
    return 0.0


def ingest_node(state: AgentState) -> dict:
    """
    LangGraph node: parse Trivy JSON → cves list.
    Applies severity_threshold filter before synthesis (e.g. "high" keeps critical+high only).
    Returns a partial state update dict.
    """
    t0 = time.time()
    trivy = state["trivy_json"]
    threshold = state.get("severity_threshold", "high")
    threshold_rank = _SEV_ORDER.get(threshold, 1)   # default: high (rank 1)

    all_records: list[CveRecord] = []

    # Trivy JSON has a top-level "Results" array, each with "Vulnerabilities"
    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
            severity = _SEV_MAP.get(vuln.get("Severity", "UNKNOWN"), "low")
            all_records.append(
                CveRecord(
                    id=cve_id,
                    severity=severity,
                    pkg=vuln.get("PkgName", "unknown"),
                    version=vuln.get("InstalledVersion", ""),
                    fixed_in=vuln.get("FixedVersion", ""),
                    cvss=_cvss_score(vuln),
                    vector=_vector_label(vuln),
                    auth_required="None",
                    impact=vuln.get("Title", ""),
                    description=vuln.get("Description", ""),
                    rationale="",       # filled by synthesis
                    remediation="",     # filled by synthesis
                    edited=False,
                    rag_match=None,     # filled by synthesis
                    status="queued",
                )
            )

    # Apply severity threshold filter (rank 0=critical, 1=high, 2=medium, 3=low)
    records = [r for r in all_records if _SEV_ORDER[r["severity"]] <= threshold_rank]

    # Sort: critical first, then by CVSS descending
    records.sort(key=lambda r: (_SEV_ORDER[r["severity"]], -r["cvss"]))

    elapsed = round(time.time() - t0, 2)
    skipped = len(all_records) - len(records)
    skip_note = f" · {skipped} below threshold skipped" if skipped else ""
    step = AgentStep(
        id="ingest",
        title=f"Parsed {len(records)} CVEs from Trivy scan",
        desc=f"{state['image_ref']} · {len(records)} vulnerabilities · threshold={threshold}{skip_note} · {elapsed}s",
        chips=[{"label": "parse_trivy_json", "variant": "done"}],
        state="done",
    )

    return {
        "cves": records,
        "total": len(records),
        "current_cve_index": 0,
        "agent_steps": [step],
    }
