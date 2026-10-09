"""
In-flight synthesis progress channel.

synthesis_node runs its CVE workers in a worker-thread event loop, so the
LangGraph stream emits nothing until the whole node returns — the UI would sit
idle for the entire synthesis. Each worker records its completion here as it
finishes; the API's run snapshot overlays this live progress (only while a run
is `running`), so the SSE stream shows workers completing one-by-one with real
counters. Thread-safe: workers run under the GIL plus this lock.
"""
from __future__ import annotations

import threading

_LOCK = threading.RLock()
_PROGRESS: dict[str, dict] = {}


def start(run_id: str, total: int) -> None:
    if not run_id:
        return
    with _LOCK:
        _PROGRESS[run_id] = {"total": total, "cves": {}, "steps": [], "tokens": 0, "rag_hits": 0}


def record(run_id: str, key: str, cve: dict, steps: list, tokens: int, rag_hits: int) -> None:
    """Record one completed worker. `key` is f"{cve_id}::{pkg}"."""
    if not run_id:
        return
    with _LOCK:
        p = _PROGRESS.get(run_id)
        if p is None:
            return
        p["cves"][key] = cve
        p["steps"].extend(steps)
        p["tokens"] += tokens
        p["rag_hits"] += rag_hits


def get(run_id: str) -> dict | None:
    """A snapshot copy of current progress, or None if nothing is tracked."""
    with _LOCK:
        p = _PROGRESS.get(run_id)
        if p is None:
            return None
        return {
            "total": p["total"],
            "cves": dict(p["cves"]),
            "steps": list(p["steps"]),
            "tokens": p["tokens"],
            "rag_hits": p["rag_hits"],
        }


def clear(run_id: str) -> None:
    with _LOCK:
        _PROGRESS.pop(run_id, None)
