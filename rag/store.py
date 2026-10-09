"""
RAG Store — pure-Python JSON + cosine similarity (no Milvus dependency).
Works on Python 3.13+. Drop-in replacement for the pymilvus version.

Storage layout:  ./data/rag_memory.json
Schema per record:
  id, cve_id, project_id, severity, rationale, approver, decision, embedding
"""
from __future__ import annotations

import json
import math
import os
import uuid
import tempfile
import threading
from datetime import datetime, timezone

_STORE_LOCK = threading.RLock()
from typing import List, Optional

from rag.embedder import embed_text, EMBED_DIM

DB_PATH = os.getenv("MILVUS_DB_PATH", "./data/rag_memory.json")
TOP_K = 5
SIMILARITY_THRESHOLD = 0.70


# ── Persistence helpers ────────────────────────────────────────────────────

def _load() -> list[dict]:
    if not os.path.exists(DB_PATH):
        return []
    with open(DB_PATH, "r") as f:
        return json.load(f)


def _save(records: list[dict]) -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=os.path.dirname(DB_PATH) or ".", delete=False) as f:
            temporary = f.name
            json.dump(records, f)
        os.replace(temporary, DB_PATH)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


# ── Cosine similarity ──────────────────────────────────────────────────────

def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ── Public API ─────────────────────────────────────────────────────────────

def persist_decision(
    cve_id: str,
    project_id: str,
    severity: str,
    rationale: str,
    approver: str,
    decision: str,
    pkg: str = "",
    remediation: str = "",
    run_id: str = "",
    image_ref: str = "",
) -> str:
    """Embed rationale and append to the JSON store. Returns record id."""
    embed_input = f"{cve_id} {severity} {rationale}"
    vector = embed_text(embed_input)

    record = {
        "id": str(uuid.uuid4()),
        "cve_id": cve_id,
        "project_id": project_id,
        "severity": severity,
        "rationale": rationale,
        "approver": approver,
        "decision": decision,
        "embedding": vector,
        "project_scoped": True,
        "pkg": pkg,
        "remediation": remediation,
        "run_id": run_id,
        "image_ref": image_ref,
        "published_at": datetime.now(timezone.utc).isoformat(),
    }

    with _STORE_LOCK:
        records = _load()
        identity = ('cve_id', 'project_id', 'pkg', 'run_id', 'decision', 'rationale', 'remediation')
        prior = next((r for r in records if all(r.get(k, '') == record.get(k, '') for k in identity)), None)
        if prior:
            return prior['id']
        records.append(record)
        _save(records)
    return record["id"]


def query_memory(
    cve_id: str,
    description: str,
    severity: str,
    top_k: int = TOP_K,
    project_id: str | None = None,
) -> list[dict]:
    """
    Return top-k similar past decisions above the similarity threshold, from ALL projects.
    `project_id` only ranks the caller's own approvals first.
    Each result: {cve_id, project_id, rationale, approver, decision, same_project, score}
    Records saved before project scoping existed (no `project_scoped` flag) are not searched.
    """
    records = [r for r in _load() if r.get("project_scoped") and r.get("decision") == "approved"]
    if not records:
        return []

    query_text = f"{cve_id} {severity} {description}"
    query_vec = embed_text(query_text)

    scored = []
    for r in records:
        emb = r.get("embedding")
        if not emb and r.get("cve_id") != cve_id:
            continue
        score = 1.0 if r.get("cve_id") == cve_id else _cosine(query_vec, emb)
        if score >= SIMILARITY_THRESHOLD:
            scored.append((score, r))

    scored.sort(key=lambda x: (x[1].get("project_id") == project_id, x[0]), reverse=True)

    return [
        {
            "cve_id": r["cve_id"],
            "project_id": r["project_id"],
            "rationale": r["rationale"],
            "approver": r["approver"],
            "decision": r["decision"],
            "remediation": r.get("remediation", ""),
            "published_at": r.get("published_at", ""),
            "image_ref": r.get("image_ref", ""),
            "same_project": r.get("project_id") == project_id,
            "score": round(score * 100),
        }
        for score, r in scored[:top_k]
    ]


def count_decisions(project_ids: list[str] | None = None) -> int:
    """Return total number of persisted decisions."""
    return sum(1 for r in _load() if project_ids is None or r.get("project_id") in project_ids)
