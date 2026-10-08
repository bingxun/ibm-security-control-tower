"""
SQLite persistence layer — Agentic Cloud Security Control Tower

Tables:
  runs         — one row per scan run
  cves         — one row per CVE, FK → runs
  trivy_logs   — one row per log line, FK → runs
  agent_steps  — one row per timeline step, FK → runs
  users        — platform users with hashed passwords and roles
  sessions     — JWT-style token store (opaque tokens, server-side)
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid as _uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator

uuid_gen = _uuid.uuid4

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

def _hash_password(password: str) -> str:
    """SHA-256 + random salt. Production: use bcrypt/argon2."""
    salt = secrets.token_hex(16)
    h    = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return secrets.compare_digest(
            hashlib.sha256(f"{salt}{password}".encode()).hexdigest(), h
        )
    except Exception:
        return False


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
                remediation  TEXT,
                manual_notes TEXT,
                edited       INTEGER NOT NULL DEFAULT 0,
                edited_by_role TEXT DEFAULT '',
                rag_match    TEXT,   -- JSON blob
                status       TEXT NOT NULL DEFAULT 'queued',
                PRIMARY KEY (id, run_id, pkg)
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

            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                email           TEXT NOT NULL UNIQUE,
                name            TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'DEVOPS_ENGINEER',
                password_hash   TEXT NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)

        # Migration: add columns introduced after this table was first created.
        # CREATE TABLE IF NOT EXISTS above is a no-op on an existing table, so
        # older DB files need these added explicitly.
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cves)")}
        if "remediation" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN remediation TEXT DEFAULT ''")
        if "edited" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN edited INTEGER NOT NULL DEFAULT 0")
        if "manual_notes" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN manual_notes TEXT DEFAULT ''")
        if "edited_by_role" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN edited_by_role TEXT DEFAULT ''")

        # Migration: widen the cves primary key to (id, run_id, pkg).
        # The original PK was (id, run_id) only, which silently drops rows
        # via INSERT OR REPLACE whenever one CVE id affects multiple
        # packages in the same run (e.g. musl + musl-utils share one CVE).
        # SQLite can't ALTER a PRIMARY KEY in place, so rebuild the table.
        pk_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cves)") if row["pk"] > 0}
        if pk_cols == {"id", "run_id"}:
            conn.executescript("""
                CREATE TABLE cves_new (
                    id            TEXT NOT NULL,
                    run_id        TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    severity      TEXT NOT NULL,
                    pkg           TEXT NOT NULL,
                    version       TEXT,
                    fixed_in      TEXT,
                    cvss          REAL DEFAULT 0,
                    vector        TEXT,
                    auth_required TEXT,
                    impact        TEXT,
                    description   TEXT,
                    rationale     TEXT,
                    remediation   TEXT,
                    manual_notes  TEXT,
                    edited        INTEGER NOT NULL DEFAULT 0,
                    edited_by_role TEXT DEFAULT '',
                    rag_match     TEXT,
                    status        TEXT NOT NULL DEFAULT 'queued',
                    PRIMARY KEY (id, run_id, pkg)
                );

                INSERT INTO cves_new
                    (id, run_id, severity, pkg, version, fixed_in, cvss, vector,
                     auth_required, impact, description, rationale, remediation,
                     manual_notes, edited, edited_by_role, rag_match, status)
                SELECT
                    id, run_id, severity, pkg, version, fixed_in, cvss, vector,
                    auth_required, impact, description, rationale, remediation,
                    manual_notes, edited, edited_by_role, rag_match, status
                FROM cves;

                DROP TABLE cves;
                ALTER TABLE cves_new RENAME TO cves;

                CREATE INDEX IF NOT EXISTS idx_cves_run ON cves(run_id);
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
                auth_required, impact, description, rationale, remediation,
                manual_notes, edited, edited_by_role, rag_match, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    c.get("remediation", ""),
                    c.get("manual_notes", ""),
                    1 if c.get("edited") else 0,
                    c.get("edited_by_role", ""),
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
    manual_notes: str | None = None,
    pkg: str | None = None,
    edited_by_role: str | None = None,
) -> None:
    """
    `pkg` disambiguates CVEs that share an id across multiple packages in the
    same run (e.g. musl + musl-utils). When omitted, falls back to matching
    by id alone — correct for the common case, but will update every package
    sharing that id if more than one happens to be present.
    """
    pkg_clause = " AND pkg=?" if pkg is not None else ""
    pkg_args = (pkg,) if pkg is not None else ()
    with get_conn() as conn:
        if manual_notes:
            conn.execute(
                f"UPDATE cves SET status=?, manual_notes=?, edited=1, edited_by_role=? WHERE run_id=? AND id=?{pkg_clause}",
                (decision, manual_notes, edited_by_role, run_id, cve_id, *pkg_args),
            )
        else:
            conn.execute(
                f"UPDATE cves SET status=? WHERE run_id=? AND id=?{pkg_clause}",
                (decision, run_id, cve_id, *pkg_args),
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
            d["edited"] = bool(d.get("edited", 0))
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


# ── User CRUD ──────────────────────────────────────────────────────────────

VALID_ROLES = {"ADMIN", "DEVOPS_ENGINEER", "CYBER_MANAGER", "DSO_MANAGER"}
SESSION_TTL_HOURS = 24


def create_user(
    email: str,
    name: str,
    password: str,
    role: str = "DEVOPS_ENGINEER",
) -> dict:
    """Create a new user. Raises ValueError on duplicate email or bad role."""
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    user_id = str(uuid_gen())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        try:
            conn.execute(
                """INSERT INTO users (id, email, name, role, password_hash, is_active, created_at, updated_at)
                   VALUES (?,?,?,?,?,1,?,?)""",
                (user_id, email.lower(), name, role, _hash_password(password), now, now),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Email already registered: {email}")
    return get_user_by_id(user_id)  # type: ignore[return-value]


def get_user_by_id(user_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, name, role, is_active, created_at, updated_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    """Returns user WITH password_hash for authentication."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)
        ).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, email, name, role, is_active, created_at, updated_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def update_user(
    user_id: str,
    *,
    name: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> dict | None:
    if role and role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        if name is not None:
            conn.execute("UPDATE users SET name=?, updated_at=? WHERE id=?", (name, now, user_id))
        if role is not None:
            conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?", (role, now, user_id))
        if is_active is not None:
            conn.execute("UPDATE users SET is_active=?, updated_at=? WHERE id=?", (int(is_active), now, user_id))
        if password is not None:
            conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (_hash_password(password), now, user_id))
    return get_user_by_id(user_id)


def delete_user(user_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))


# ── Session CRUD ───────────────────────────────────────────────────────────

def create_session(user_id: str) -> str:
    """Create an opaque session token valid for SESSION_TTL_HOURS."""
    token    = secrets.token_urlsafe(32)
    now      = datetime.now(timezone.utc)
    expires  = (now + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now.isoformat(), expires),
        )
    return token


def get_session_user(token: str) -> dict | None:
    """Return the user for a valid, non-expired session token."""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            """SELECT u.id, u.email, u.name, u.role, u.is_active
               FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.token=? AND s.expires_at > ? AND u.is_active=1""",
            (token, now),
        ).fetchone()
        return dict(row) if row else None


def delete_session(token: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))


def purge_expired_sessions() -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))


# ── Seed default admin ─────────────────────────────────────────────────────

def seed_admin(
    email: str = "admin@controltower.local",
    password: str = "Admin@1234",
    name: str = "Platform Admin",
) -> None:
    """Idempotent — only creates the admin if no users exist yet."""
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        create_user(email=email, name=name, password=password, role="ADMIN")
        import logging
        logging.getLogger("control_tower").info(
            "Seeded default admin: %s / %s", email, password
        )
