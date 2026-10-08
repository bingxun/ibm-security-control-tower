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
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_members (
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (project_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_members_user ON project_members(user_id);
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role    TEXT NOT NULL,
                PRIMARY KEY (user_id, role)
            );
            CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
            CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY);
            CREATE INDEX IF NOT EXISTS idx_runs_project ON runs(project_id);
        """)

        # Preserve historical scans as projects; membership starts empty (fail closed).
        conn.execute("""INSERT OR IGNORE INTO projects (id, name, created_at)
                        SELECT project_id, CASE WHEN project_id='' THEN 'Legacy project' ELSE project_id END,
                               MIN(started_at) FROM runs GROUP BY project_id""")
        if "project_scoped" not in {row[1] for row in conn.execute("PRAGMA table_info(runs)")}:
            conn.execute("ALTER TABLE runs ADD COLUMN project_scoped INTEGER NOT NULL DEFAULT 0")

        # Migration: add cves columns introduced after the table was first created.
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cves)")}
        if "remediation" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN remediation TEXT DEFAULT ''")
        if "edited" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN edited INTEGER NOT NULL DEFAULT 0")
        if "manual_notes" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN manual_notes TEXT DEFAULT ''")
        if "edited_by_role" not in existing_cols:
            conn.execute("ALTER TABLE cves ADD COLUMN edited_by_role TEXT DEFAULT ''")

        # Migration: widen the cves primary key to (id, run_id, pkg). The original
        # PK (id, run_id) silently dropped rows via INSERT OR REPLACE whenever one
        # CVE id affected multiple packages in a run (e.g. musl + musl-utils).
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
        conn.execute("UPDATE runs SET project_scoped=1 WHERE run_id=?", (run_id,))


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
    same run (e.g. musl + musl-utils). When omitted, falls back to matching by
    id alone — correct for the common case, but will update every package
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

def project_filter(project_ids: list[str] | None, column: str = "project_id") -> tuple[str, list[str]]:
    if project_ids is None:
        return "1=1", []
    if not project_ids:
        return "1=0", []
    return f"{column} IN ({','.join('?' for _ in project_ids)})", project_ids


def get_dashboard_stats(project_ids: list[str] | None = None) -> dict:
    where, args = project_filter(project_ids, "r.project_id")
    with get_conn() as conn:
        total_scans = conn.execute(f"SELECT COUNT(*) FROM runs r WHERE {where}", args).fetchone()[0]
        row = conn.execute(f"""SELECT COUNT(*), COALESCE(SUM(c.status='approved'),0)
                              FROM cves c JOIN runs r ON r.run_id=c.run_id WHERE {where}""", args).fetchone()
        total_cves, approved = row
        rate = round(approved / total_cves * 100) if total_cves else 0
        return {"totalScans": total_scans, "cvesTriaged": total_cves,
                "avgApprovalRate": rate, "ragFirstPassRate": rate}


def get_scan_summaries(limit: int = 50, project_ids: list[str] | None = None) -> list[dict]:
    where, args = project_filter(project_ids)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT rowid AS seq, * FROM runs WHERE {where} ORDER BY started_at DESC LIMIT ?", (*args, limit)
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
                "seq":       run.get("seq"),
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

VALID_ROLES = {"SUPER_ADMIN", "ADMIN", "DEVOPS_ENGINEER", "CYBER_MANAGER", "DSO_MANAGER"}
# Highest privilege first — used only to pick a display "primary" role.
ROLE_PRIORITY = ["SUPER_ADMIN", "ADMIN", "CYBER_MANAGER", "DSO_MANAGER", "DEVOPS_ENGINEER"]
SESSION_TTL_HOURS = 24


def _primary_role(roles: list[str]) -> str:
    """Pick a stable display 'primary' role from a user's role set."""
    for role in ROLE_PRIORITY:
        if role in roles:
            return role
    return roles[0] if roles else "DEVOPS_ENGINEER"


def _attach_roles(conn, row: dict | None) -> dict | None:
    """Populate `roles` (full set, priority-sorted) and `role` (primary) on a user row."""
    if row is None:
        return None
    found = {r[0] for r in conn.execute("SELECT role FROM user_roles WHERE user_id=?", (row["id"],))}
    # Fall back to the legacy column if the join table is empty (pre-migration rows).
    if not found and row.get("role"):
        found = {row["role"]}
    roles = [r for r in ROLE_PRIORITY if r in found] + sorted(found - set(ROLE_PRIORITY))
    row["roles"] = roles
    row["role"] = _primary_role(roles)
    return row


def _write_roles(conn, user_id: str, roles: list[str]) -> None:
    """Replace a user's role set and mirror the primary onto users.role."""
    clean = [r for r in roles if r in VALID_ROLES]
    if not clean:
        raise ValueError("A user must have at least one valid role")
    conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
    conn.executemany("INSERT INTO user_roles(user_id, role) VALUES (?,?)", [(user_id, r) for r in set(clean)])
    conn.execute("UPDATE users SET role=? WHERE id=?", (_primary_role(clean), user_id))


def create_user(
    email: str,
    name: str,
    password: str,
    roles: list[str] | None = None,
) -> dict:
    """Create a new user. Raises ValueError on duplicate email or bad role."""
    roles = roles or ["DEVOPS_ENGINEER"]
    invalid = [r for r in roles if r not in VALID_ROLES]
    if invalid or not roles:
        raise ValueError(f"Invalid role(s): {invalid}")
    user_id = str(uuid_gen())
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        try:
            conn.execute(
                """INSERT INTO users (id, email, name, role, password_hash, is_active, created_at, updated_at)
                   VALUES (?,?,?,?,?,1,?,?)""",
                (user_id, email.lower(), name, _primary_role(roles), _hash_password(password), now, now),
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Email already registered: {email}")
        _write_roles(conn, user_id, roles)
    return get_user_by_id(user_id)  # type: ignore[return-value]


def get_user_by_id(user_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, name, role, is_active, created_at, updated_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        return _attach_roles(conn, dict(row) if row else None)


def get_user_by_email(email: str) -> dict | None:
    """Returns user WITH password_hash for authentication."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)
        ).fetchone()
        return _attach_roles(conn, dict(row) if row else None)


def list_users() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, email, name, role, is_active, created_at, updated_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [_attach_roles(conn, dict(r)) for r in rows]


def update_user(
    user_id: str,
    *,
    name: str | None = None,
    roles: list[str] | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> dict | None:
    if roles is not None:
        invalid = [r for r in roles if r not in VALID_ROLES]
        if invalid or not roles:
            raise ValueError(f"Invalid role(s): {invalid}")
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        if name is not None:
            conn.execute("UPDATE users SET name=?, updated_at=? WHERE id=?", (name, now, user_id))
        if roles is not None:
            _write_roles(conn, user_id, roles)
            conn.execute("UPDATE users SET updated_at=? WHERE id=?", (now, user_id))
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
        return _attach_roles(conn, dict(row) if row else None)


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
        create_user(email=email, name=name, password=password, roles=["SUPER_ADMIN"])
        import logging
        logging.getLogger("control_tower").info(
            "Seeded default admin: %s / %s", email, password
        )


def migrate_super_admin() -> None:
    """One-time bootstrap: promote only the configured, existing admin account."""
    email = os.getenv("SUPER_ADMIN_EMAIL", "admin@controltower.local").lower()
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM schema_migrations WHERE name='project_access_v1'").fetchone():
            return
        if not conn.execute("SELECT 1 FROM users WHERE role='SUPER_ADMIN' AND is_active=1").fetchone():
            cursor = conn.execute("UPDATE users SET role='SUPER_ADMIN' WHERE email=? AND role='ADMIN' AND is_active=1", (email,))
            if not cursor.rowcount:
                raise RuntimeError("Set SUPER_ADMIN_EMAIL to an existing active admin before enabling project access")
        # Keep the authoritative role set in sync with the promoted account.
        conn.execute("""INSERT OR IGNORE INTO user_roles(user_id, role)
                        SELECT id, 'SUPER_ADMIN' FROM users WHERE role='SUPER_ADMIN'""")
        conn.execute("INSERT INTO schema_migrations(name) VALUES ('project_access_v1')")


def migrate_multi_role() -> None:
    """Backfill the user_roles join table from the legacy users.role column (once)."""
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM schema_migrations WHERE name='multi_role_v1'").fetchone():
            return
        conn.execute("""INSERT OR IGNORE INTO user_roles(user_id, role)
                        SELECT id, role FROM users""")
        conn.execute("INSERT INTO schema_migrations(name) VALUES ('multi_role_v1')")


def list_projects(user: dict) -> list[dict]:
    with get_conn() as conn:
        if set(user.get("roles") or [user.get("role")]) & {"SUPER_ADMIN", "DSO_MANAGER"}:
            rows = conn.execute("SELECT * FROM projects ORDER BY name, id").fetchall()
        else:
            rows = conn.execute("""SELECT p.* FROM projects p JOIN project_members m ON p.id=m.project_id
                                   WHERE m.user_id=? ORDER BY p.name, p.id""", (user["id"],)).fetchall()
        return [dict(row) for row in rows]


def get_project(project_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None


def has_project_access(user: dict, project_id: str) -> bool:
    with get_conn() as conn:
        if set(user.get("roles") or [user.get("role")]) & {"SUPER_ADMIN", "DSO_MANAGER"}:
            return conn.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is not None
        return conn.execute("SELECT 1 FROM project_members WHERE project_id=? AND user_id=?", (project_id, user["id"])).fetchone() is not None


def create_project(name: str, description: str = "") -> dict:
    project_id = str(uuid_gen())
    with get_conn() as conn:
        conn.execute("INSERT INTO projects(id,name,description,created_at) VALUES (?,?,?,?)",
                     (project_id, name, description, datetime.now(timezone.utc).isoformat()))
    return get_project(project_id)


def project_member_ids(project_id: str) -> list[str]:
    with get_conn() as conn:
        return [row[0] for row in conn.execute("SELECT user_id FROM project_members WHERE project_id=?", (project_id,))]


def set_project_members(project_id: str, user_ids: list[str]) -> None:
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            raise ValueError("Project not found")
        for user_id in set(user_ids):
            exists = conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone()
            is_super = conn.execute("SELECT 1 FROM user_roles WHERE user_id=? AND role='SUPER_ADMIN'", (user_id,)).fetchone()
            if not exists or is_super:
                raise ValueError("Select valid non-super-admin accounts")
        conn.execute("DELETE FROM project_members WHERE project_id=?", (project_id,))
        conn.executemany("INSERT INTO project_members(project_id,user_id) VALUES (?,?)",
                         [(project_id, user_id) for user_id in set(user_ids)])
