"""
SQLite persistence layer — Agentic Cloud Security Control Tower

Tables:
  runs         — one row per scan run
  cves         — one row per CVE, FK → runs
  trivy_logs   — one row per log line, FK → runs
  agent_steps  — one row per timeline step, FK → runs
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

DB_PATH = os.getenv("DB_PATH", "./data/control_tower.db")


# ── Connection ─────────────────────────────────────────────────────────────

@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ─────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id       TEXT PRIMARY KEY,
                status       TEXT NOT NULL DEFAULT 'queued',
                image_ref    TEXT NOT NULL,
                project_id   TEXT NOT NULL,
                cis_profile  TEXT NOT NULL DEFAULT 'CIS Docker Benchmark v1.6',
                scanner      TEXT NOT NULL DEFAULT 'trivy',
                severity_threshold TEXT NOT NULL DEFAULT 'high',
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                error        TEXT,
                tokens_used  INTEGER DEFAULT 0,
                avg_synthesis_s REAL DEFAULT 0,
                rag_hits     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS cves (
                id           TEXT NOT NULL,
                run_id       TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                severity     TEXT NOT NULL,
                pkg          TEXT NOT NULL,
                version      TEXT,
                fixed_in     TEXT,
                cvss         REAL DEFAULT 0,
                vector       TEXT,
                auth_required TEXT,
                impact       TEXT,
                description  TEXT,
                rationale    TEXT,
                rag_match    TEXT,   -- JSON blob
                status       TEXT NOT NULL DEFAULT 'queued',
                PRIMARY KEY (id, run_id)
            );

            CREATE TABLE IF NOT EXISTS trivy_logs (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id   TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                line     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_steps (
                id       TEXT NOT NULL,
                run_id   TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                title    TEXT NOT NULL,
                desc     TEXT,
                chips    TEXT,   -- JSON array
                state    TEXT NOT NULL DEFAULT 'waiting',
                seq      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (id, run_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cves_run ON cves(run_id);
            CREATE INDEX IF NOT EXISTS idx_logs_run ON trivy_logs(run_id);
            CREATE INDEX IF NOT EXISTS idx_steps_run ON agent_steps(run_id);
        """)


# ── Run CRUD ───────────────────────────────────────────────────────────────

def create_run(
    run_id: str,
    image_ref: str,
    project_id: str,
    cis_profile: str = "CIS Docker Benchmark v1.6",
    scanner: str = "trivy",
    severity_threshold: str = "high",
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO runs
               (run_id, status, image_ref, project_id, cis_profile, scanner,
                severity_threshold, started_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                run_id, "queued", image_ref, project_id, cis_profile,
                scanner, severity_threshold,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def update_run_status(run_id: str, status: str, error: str | None = None) -> None:
    finished = datetime.now(timezone.utc).isoformat() if status in ("completed", "error") else None
    with get_conn() as conn:
        conn.execute(
            """UPDATE runs SET status=?, error=?, finished_at=COALESCE(?,finished_at)
               WHERE run_id=?""",
            (status, error, finished, run_id),
        )


def update_run_stats(
    run_id: str,
    tokens_used: int = 0,
    avg_synthesis_s: float = 0.0,
    rag_hits: int = 0,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """UPDATE runs SET tokens_used=?, avg_synthesis_s=?, rag_hits=?
               WHERE run_id=?""",
            (tokens_used, avg_synthesis_s, rag_hits, run_id),
        )


def get_run(run_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return dict(row) if row else None


def list_runs(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── CVE CRUD ───────────────────────────────────────────────────────────────

def upsert_cves(run_id: str, cves: list[dict]) -> None:
    """Insert or replace all CVE records for a run (called after synthesis)."""
    with get_conn() as conn:
        conn.executemany(
            """INSERT OR REPLACE INTO cves
               (id, run_id, severity, pkg, version, fixed_in, cvss, vector,
                auth_required, impact, description, rationale, rag_match, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    c.get("id", ""),
                    run_id,
                    c.get("severity", "low"),
                    c.get("pkg", ""),
                    c.get("version", ""),
                    c.get("fixed_in", ""),
                    c.get("cvss", 0.0),
                    c.get("vector", ""),
                    c.get("auth_required", ""),
                    c.get("impact", ""),
                    c.get("description", ""),
                    c.get("rationale", ""),
                    json.dumps(c.get("rag_match")) if c.get("rag_match") else None,
                    c.get("status", "queued"),
                )
                for c in cves
            ],
        )


def update_cve_decision(
    run_id: str,
    cve_id: str,
    decision: str,
    rationale: str | None = None,
) -> None:
    with get_conn() as conn:
        if rationale:
            conn.execute(
                "UPDATE cves SET status=?, rationale=? WHERE run_id=? AND id=?",
                (decision, rationale, run_id, cve_id),
            )
        else:
            conn.execute(
                "UPDATE cves SET status=? WHERE run_id=? AND id=?",
                (decision, run_id, cve_id),
            )


def get_cves(run_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM cves WHERE run_id=? ORDER BY cvss DESC, severity",
            (run_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["rag_match"] = json.loads(d["rag_match"]) if d.get("rag_match") else None
            result.append(d)
        return result


# ── Trivy logs ─────────────────────────────────────────────────────────────

def append_trivy_log(run_id: str, line: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO trivy_logs (run_id, line) VALUES (?,?)",
            (run_id, line),
        )


def get_trivy_logs(run_id: str) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT line FROM trivy_logs WHERE run_id=? ORDER BY id",
            (run_id,),
        ).fetchall()
        return [r["line"] for r in rows]


# ── Agent steps ────────────────────────────────────────────────────────────

def upsert_agent_steps(run_id: str, steps: list[dict]) -> None:
    with get_conn() as conn:
        conn.executemany(
            """INSERT OR REPLACE INTO agent_steps
               (id, run_id, title, desc, chips, state, seq)
               VALUES (?,?,?,?,?,?,?)""",
            [
                (
                    s.get("id", ""),
                    run_id,
                    s.get("title", ""),
                    s.get("desc", ""),
                    json.dumps(s.get("chips", [])),
                    s.get("state", "waiting"),
                    i,
                )
                for i, s in enumerate(steps)
            ],
        )


def get_agent_steps(run_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM agent_steps WHERE run_id=? ORDER BY seq",
            (run_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["chips"] = json.loads(d.get("chips") or "[]")
            result.append(d)
        return result


# ── Dashboard aggregates ───────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    with get_conn() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        total_cves  = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        approved    = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE status='approved'"
        ).fetchone()[0]
        rate = round((approved / total_cves * 100) if total_cves else 0)
        return {
            "totalScans":      total_scans,
            "cvesTriaged":     total_cves,
            "avgApprovalRate": rate,
            "ragFirstPassRate": rate,
        }


def get_scan_summaries(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            run = dict(r)
            run_id = run["run_id"]
            cve_rows = conn.execute(
                "SELECT severity, status FROM cves WHERE run_id=?", (run_id,)
            ).fetchall()
            cves = [dict(c) for c in cve_rows]
            started = run.get("started_at", "")
            finished = run.get("finished_at", "")
            if started and finished:
                try:
                    s = datetime.fromisoformat(started)
                    f = datetime.fromisoformat(finished)
                    secs = int((f - s).total_seconds())
                    duration = f"{secs // 60}m {secs % 60}s"
                except Exception:
                    duration = "—"
            else:
                duration = "—"
            result.append({
                "id":        run_id,
                "project":   run["project_id"],
                "image":     run["image_ref"],
                "date":      started[:10] if started else "",
                "totalCves": len(cves),
                "critical":  sum(1 for c in cves if c["severity"] == "critical"),
                "high":      sum(1 for c in cves if c["severity"] == "high"),
                "medium":    sum(1 for c in cves if c["severity"] == "medium"),
                "approved":  sum(1 for c in cves if c["status"] == "approved"),
                "rejected":  sum(1 for c in cves if c["status"] == "rejected"),
                "status":    run["status"],
                "duration":  duration,
            })
        return result
