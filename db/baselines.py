"""Explicitly published, project-independent Cyber Manager reference decisions."""
import json
import uuid
from datetime import datetime, timezone
from db.database import get_conn


def init_baselines():
    with get_conn() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS shared_baselines (
                id TEXT PRIMARY KEY, cve_id TEXT NOT NULL, pkg TEXT NOT NULL,
                rationale TEXT NOT NULL, remediation TEXT NOT NULL,
                approver TEXT NOT NULL, published_at TEXT NOT NULL,
                source_run TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS review_audit (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, cve_id TEXT NOT NULL,
                pkg TEXT NOT NULL, decision TEXT NOT NULL, reviewer TEXT NOT NULL,
                reviewed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_context (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                markdown TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS review_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, cve_id TEXT NOT NULL, pkg TEXT NOT NULL,
                round INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL, actor_role TEXT NOT NULL,
                justification TEXT, remediation TEXT, manual_notes TEXT,
                review_comment TEXT, requested_changes TEXT,
                ai_suggestions_applied TEXT,
                created_at TEXT NOT NULL
            );
        ''')


def publish(run_id, cve, rationale, remediation, reviewer):
    baseline_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute('INSERT INTO shared_baselines VALUES (?,?,?,?,?,?,?,?,1)',
                     (baseline_id, cve['id'], cve['pkg'], rationale, remediation,
                      reviewer, datetime.now(timezone.utc).isoformat(), run_id))
    return baseline_id


def references(cve_id=None, pkg=None):
    with get_conn() as conn:
        rows = conn.execute('''SELECT id,cve_id,pkg,rationale,remediation,approver,published_at
            FROM shared_baselines WHERE active=1 ORDER BY published_at DESC''').fetchall()
    return [dict(r) for r in rows if (cve_id is None or r['cve_id'] == cve_id)
            and (pkg is None or r['pkg'] == pkg)]


def project_approvals(project_id, cve_id, pkg):
    """Read current durable approvals even when other findings still await review."""
    with get_conn() as conn:
        rows = conn.execute("""SELECT c.rationale,c.remediation,COALESCE(a.reviewer,'Historical reviewer (unrecorded)') AS approver,COALESCE(a.reviewed_at,r.finished_at,'') AS published_at
            FROM cves c JOIN runs r ON r.run_id=c.run_id
            LEFT JOIN review_audit a ON a.run_id=c.run_id AND a.cve_id=c.id AND a.pkg=c.pkg AND a.decision='approved'
            WHERE r.project_id=? AND r.project_scoped=1 AND c.id=? AND c.pkg=?
              AND c.status='approved'
            ORDER BY a.id DESC LIMIT 5""", (project_id,cve_id,pkg)).fetchall()
    return [{**dict(r),'project_id':project_id,'score':100,'decision':'approved'} for r in rows]


def project_name(project_id):
    """Readable project name for display (falls back to the id)."""
    with get_conn() as conn:
        row = conn.execute("SELECT name FROM projects WHERE id=?", (project_id,)).fetchone()
    return row[0] if row else project_id


def past_approvals(project_id, cve_id, pkg, limit=5):
    """Durable approvals of this CVE + package from ALL projects (memory is shared across projects).

    The calling project's own approval comes first, then the most recent from other projects;
    at most one per project. Runs that predate project scoping are excluded.
    """
    with get_conn() as conn:
        rows = conn.execute("""SELECT c.rationale,c.remediation,
                COALESCE(a.reviewer,'Historical reviewer (unrecorded)') AS approver,
                COALESCE(a.reviewed_at,r.finished_at,'') AS published_at,
                r.project_id AS project_id, COALESCE(p.name, r.project_id) AS project_name, r.image_ref AS image_ref
            FROM cves c JOIN runs r ON r.run_id=c.run_id
            LEFT JOIN projects p ON p.id=r.project_id
            LEFT JOIN review_audit a ON a.run_id=c.run_id AND a.cve_id=c.id AND a.pkg=c.pkg AND a.decision='approved'
            WHERE r.project_scoped=1 AND c.id=? AND c.pkg=? AND c.status='approved'
            ORDER BY (r.project_id=?) DESC, a.id DESC""", (cve_id, pkg, project_id)).fetchall()
    seen, result = set(), []
    for r in rows:
        if r['project_id'] in seen:
            continue
        seen.add(r['project_id'])
        result.append({**dict(r), 'same_project': r['project_id'] == project_id,
                       'score': 100, 'decision': 'approved'})
        if len(result) >= limit:
            break
    return result


def record_revision(run_id, cve_id, pkg, action, actor, actor_role,
                    justification='', remediation='', manual_notes='',
                    review_comment='', requested_changes='', ai_suggestions_applied=None):
    """Append one append-only revision row.

    `round` is 1-based and increments on each `submitted` action — the decision
    that closes a round (approved/rejected/changes_requested) shares the round
    of the submission it responds to.
    """
    with get_conn() as conn:
        prior_submits = conn.execute(
            "SELECT COUNT(*) FROM review_revisions WHERE run_id=? AND cve_id=? AND pkg=? AND action='submitted'",
            (run_id, cve_id, pkg)).fetchone()[0]
        round_no = prior_submits + 1 if action == 'submitted' else max(prior_submits, 1)
        conn.execute("""INSERT INTO review_revisions
            (run_id,cve_id,pkg,round,action,actor,actor_role,justification,remediation,
             manual_notes,review_comment,requested_changes,ai_suggestions_applied,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, cve_id, pkg, round_no, action, actor, actor_role,
             justification, remediation, manual_notes, review_comment, requested_changes,
             json.dumps(ai_suggestions_applied) if ai_suggestions_applied else None,
             datetime.now(timezone.utc).isoformat()))


def revisions(run_id, cve_id, pkg):
    """Ordered revision history for one finding (oldest first)."""
    with get_conn() as conn:
        rows = conn.execute("""SELECT round,action,actor,actor_role,justification,remediation,
            manual_notes,review_comment,requested_changes,ai_suggestions_applied,created_at
            FROM review_revisions WHERE run_id=? AND cve_id=? AND pkg=? ORDER BY id""",
            (run_id, cve_id, pkg)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['ai_suggestions_applied'] = json.loads(d['ai_suggestions_applied']) if d['ai_suggestions_applied'] else []
        result.append(d)
    return result
