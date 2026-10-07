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
    with open(DB_PATH, "w") as f:
        json.dump(records, f)


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
    }

    records = _load()
    records.append(record)
    _save(records)
    return record["id"]


def query_memory(
    cve_id: str,
    description: str,
    severity: str,
    top_k: int = TOP_K,
) -> list[dict]:
    """
    Return top-k similar past decisions above the similarity threshold.
    Each result: {cve_id, project_id, rationale, approver, decision, score}
    """
    records = _load()
    if not records:
        return []

    query_text = f"{cve_id} {severity} {description}"
    query_vec = embed_text(query_text)

    scored = []
    for r in records:
        emb = r.get("embedding")
        if not emb:
            continue
        score = _cosine(query_vec, emb)
        if score >= SIMILARITY_THRESHOLD:
            scored.append((score, r))

    scored.sort(key=lambda x: x[0], reverse=True)

    return [
        {
            "cve_id": r["cve_id"],
            "project_id": r["project_id"],
            "rationale": r["rationale"],
            "approver": r["approver"],
            "decision": r["decision"],
            "score": round(score * 100),
        }
        for score, r in scored[:top_k]
    ]


def count_decisions() -> int:
    """Return total number of persisted decisions."""
    return len(_load())
