"""Project isolation through real HTTP handlers and temporary storage."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from api.main import app, RUNS
from db import database as db
from rag import store


class ProjectAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for target, value in [("db.database.DB_PATH", str(Path(self.temp.name) / "test.db")),
                              ("rag.store.DB_PATH", str(Path(self.temp.name) / "rag.json"))]:
            p = patch(target, value); p.start(); self.addCleanup(p.stop)
        self.client = TestClient(app); self.client.__enter__(); self.addCleanup(self.client.__exit__, None, None, None)
        self.super = self.login("admin@controltower.local", "Admin@1234")
        self.a = self.client.post('/projects', headers=self.super, json={'name': 'Alpha', 'description': 'Private A'}).json()['id']
        self.b = self.client.post('/projects', headers=self.super, json={'name': 'Beta', 'description': 'Private B'}).json()['id']
        self.users = {}
        for role in ['ADMIN', 'DEVOPS_ENGINEER', 'CYBER_MANAGER']:
            email = role.lower() + '@example.com'
            user = db.create_user(email, role, 'Test-only-123', role)
            self.users[role] = (user, self.login(email, 'Test-only-123'))
        db.set_project_members(self.a, [u['id'] for u, _ in self.users.values()])
        for project, run in [(self.a, 'run-a'), (self.b, 'run-b')]:
            db.create_run(run, project + '-image', project)
            db.update_run_status(run, 'completed')
            db.upsert_cves(run, [{'id': 'CVE-test', 'severity': 'high', 'pkg': 'test', 'status': 'approved', 'rationale': project + '-rationale'}])
        self.addCleanup(RUNS.clear)

    def login(self, email, password):
        result = self.client.post('/auth/login', json={'email': email, 'password': password})
        self.assertEqual(result.status_code, 200, result.text)
        return {'Authorization': 'Bearer ' + result.json()['token']}

    def test_super_admin_sees_all_and_only_super_admin_creates(self):
        self.assertEqual(len(self.client.get('/projects', headers=self.super).json()), 2)
        self.assertEqual(self.client.get('/stats', headers=self.super).json()['totalScans'], 2)
        for user, headers in self.users.values():
            self.assertEqual(self.client.post('/projects', headers=headers, json={'name': 'Forbidden'}).status_code, 403)
            self.assertEqual(self.client.put(f'/projects/{self.b}/members', headers=headers, json={'user_ids': [user['id']]}).status_code, 403)
            self.assertEqual(self.client.get('/users', headers=headers).status_code, 403)

    def test_all_roles_are_isolated_in_lists_details_streams_and_stats(self):
        for user, headers in self.users.values():
            with self.subTest(role=user['role']):
                self.assertEqual([p['id'] for p in self.client.get('/projects', headers=headers).json()], [self.a])
                self.assertEqual([r['id'] for r in self.client.get('/scans', headers=headers).json()], ['run-a'])
                self.assertEqual(self.client.get('/stats', headers=headers).json()['cvesTriaged'], 1)
                self.assertEqual(self.client.get('/run/run-a', headers=headers).status_code, 200)
                self.assertEqual(self.client.get('/run/run-a/stream', headers=headers).status_code, 200)
                for path in [f'/projects/{self.b}', '/run/run-b', '/run/run-b/stream', f'/stats?project_id={self.b}', f'/scans?project_id={self.b}']:
                    self.assertEqual(self.client.get(path, headers=headers).status_code, 404, path)
                response = self.client.post('/run/run-b/decision', headers=headers, json={'cve_id': 'CVE-test', 'decision': 'approved'})
                self.assertIn(response.status_code, [403, 404])

    def test_unassigned_user_and_removed_membership_fail_closed(self):
        user, headers = self.users['ADMIN']
        db.set_project_members(self.a, [])
        self.assertEqual(self.client.get('/projects', headers=headers).json(), [])
        self.assertEqual(self.client.get('/scans', headers=headers).json(), [])
        self.assertEqual(self.client.get('/stats', headers=headers).json()['totalScans'], 0)
        self.assertEqual(self.client.get('/run/run-a', headers=headers).status_code, 404)
        self.assertEqual(self.client.get('/run/run-a/stream', headers=headers).status_code, 404)

    def test_no_unauthenticated_project_or_scan_endpoints(self):
        for path in ['/projects', '/scans', '/stats', '/run/run-a', '/run/run-a/stream', f'/scan-image/stream?imageRef=nginx&projectId={self.a}']:
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.post('/scan', json={'projectId': self.a, 'imageRef': 'nginx'}).status_code, 401)
        self.assertEqual(self.client.get('/health').json(), {'status': 'ok'})

    def test_scan_and_review_role_enforcement(self):
        for role, (_, headers) in self.users.items():
            req = {'projectId': self.b, 'imageRef': 'nginx'}
            self.assertIn(self.client.post('/scan', headers=headers, json=req).status_code, [403, 404])
            self.assertIn(self.client.post('/scan-image', headers=headers, json=req).status_code, [403, 404])
            self.assertIn(self.client.get(f'/scan-image/stream?imageRef=nginx&projectId={self.b}', headers=headers).status_code, [403, 404])
        engineer = self.users['DEVOPS_ENGINEER'][1]
        self.assertEqual(self.client.post('/run/run-a/decision', headers=engineer, json={'cve_id': 'CVE-test', 'decision': 'approved'}).status_code, 403)
        self.assertEqual(self.client.post('/scan', headers=engineer, json={'projectId': self.a, 'imageRef': 'nginx', 'autoApproveBelow': 'low'}).status_code, 403)
        with patch('api.main._run_pipeline', new=AsyncMock()):
            self.assertEqual(self.client.post('/scan', headers=engineer, json={'projectId': self.a, 'imageRef': 'nginx'}).status_code, 200)
        self.assertEqual(self.client.post('/scan', headers=self.users['CYBER_MANAGER'][1], json={'projectId': self.a, 'imageRef': 'nginx'}).status_code, 403)

    def test_assignments_atomic_and_durable(self):
        ids = [self.users['ADMIN'][0]['id']]
        response = self.client.put(f'/projects/{self.b}/members', headers=self.super, json={'user_ids': ids})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get(f'/projects/{self.b}/members', headers=self.super).json()['user_ids'], ids)
        response = self.client.put(f'/projects/{self.b}/members', headers=self.super, json={'user_ids': ['nonexistent']})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(db.project_member_ids(self.b), ids)
        self.assertEqual(len(self.client.get('/projects', headers=self.users['ADMIN'][1]).json()), 2)

    def test_rag_memory_does_not_cross_project_boundaries(self):
        with patch('rag.store.embed_text', return_value=[1., 0.]):
            for project in [self.a, self.b]:
                store.persist_decision('CVE-test', project, 'high', project + '-secret', 'Reviewer', 'approved')
            hits = store.query_memory('CVE-test', 'desc', 'high', project_id=self.a)
            self.assertEqual([h['project_id'] for h in hits], [self.a])
            self.assertEqual(store.query_memory('CVE-test', 'desc', 'high'), [])
        self.assertEqual(self.client.get('/stats', headers=self.users['ADMIN'][1]).json()['ragDecisions'], 1)

    def test_legacy_generated_content_is_not_exposed(self):
        with db.get_conn() as conn:
            conn.execute("UPDATE runs SET project_scoped=0 WHERE run_id='run-a'")
        data = self.client.get('/run/run-a', headers=self.users['ADMIN'][1]).json()
        self.assertNotIn(self.a + '-rationale', str(data))
        self.assertIsNone(data['cves'][0]['ragMatch'])
        self.assertEqual(self.client.get('/run/run-a', headers=self.super).json()['cves'][0]['rationale'], self.a + '-rationale')

    def test_open_stream_stops_after_membership_revoked(self):
        from api.main import stream_run
        from starlette.requests import Request
        user, headers = self.users['ADMIN']
        db.update_run_status('run-a', 'running')
        class ConnectedRequest(Request):
            async def is_disconnected(self):
                return False
        request = ConnectedRequest({'type': 'http', 'headers': [(b'authorization', headers['Authorization'].encode())]})
        async def exercise():
            response = await stream_run('run-a', request, user)
            iterator = response.body_iterator
            first = await anext(iterator)
            self.assertIn('run-a', first['data'])
            db.set_project_members(self.a, [])
            with self.assertRaises(StopAsyncIteration):
                await anext(iterator)
        asyncio.run(exercise())

    def test_direct_escalation_and_membership_read_are_denied(self):
        for user, headers in self.users.values():
            self.assertEqual(self.client.get(f'/projects/{self.a}/members', headers=headers).status_code, 403)
            self.assertEqual(self.client.put(f'/users/{user["id"]}', headers=headers,
                json={'role': 'SUPER_ADMIN'}).status_code, 403)
            self.assertEqual(self.client.post('/users', headers=headers,
                json={'email': 'escalate@example.com', 'name': 'Escalation', 'password': 'Test-only-123', 'role': 'SUPER_ADMIN'}).status_code, 403)

    def test_legacy_rag_and_missing_project_are_not_searchable(self):
        store._save([{'cve_id': 'CVE-test', 'project_id': self.a, 'embedding': [1., 0.],
                      'rationale': 'Previously blended private data', 'approver': 'Legacy', 'decision': 'approved'}])
        with patch('rag.store.embed_text', return_value=[1., 0.]):
            self.assertEqual(store.query_memory('CVE-test', 'desc', 'high', project_id=self.a), [])
        self.assertEqual(self.client.get('/projects/does-not-exist', headers=self.super).status_code, 404)
        self.assertEqual(self.client.post('/scan', headers=self.super,
            json={'projectId': 'does-not-exist', 'imageRef': 'nginx'}).status_code, 404)
        self.assertEqual(self.client.post('/projects', headers=self.super, json={'name': '  '}).status_code, 422)

    def test_scoped_filter_is_applied_before_limit(self):
        for index in range(55):
            db.create_run(f'private-{index}', 'private-image', self.b)
        self.assertEqual([r['id'] for r in self.client.get('/scans', headers=self.users['ADMIN'][1]).json()], ['run-a'])

    def test_mcp_memory_tools_enforce_sessions_and_project_membership(self):
        from mcp_server.server import query_memory_tool, persist_decision_tool, memory_stats_tool
        user, headers = self.users['DEVOPS_ENGINEER']
        token = headers['Authorization'].split(' ', 1)[1]
        with self.assertRaises(ValueError):
            query_memory_tool('CVE-test', 'desc', 'high', project_id=self.a)
        with self.assertRaises(ValueError):
            query_memory_tool('CVE-test', 'desc', 'high', project_id=self.b, session_token=token)
        with self.assertRaises(ValueError):
            persist_decision_tool('CVE-test', self.a, 'high', 'rationale', 'forged', 'approved', session_token=token)
        self.assertEqual(memory_stats_tool(session_token=token), {'total_decisions': 0})

    def test_migration_is_idempotent_and_does_not_assign_users(self):
        with db.get_conn() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE name='project_access_v1'")
            conn.execute("UPDATE users SET role='ADMIN' WHERE email='admin@controltower.local'")
        db.migrate_super_admin(); db.migrate_super_admin(); db.init_db()
        self.assertEqual(db.get_user_by_email('admin@controltower.local')['role'], 'SUPER_ADMIN')
        self.assertEqual(db.project_member_ids(self.b), [])
        with db.get_conn() as conn:
            conn.execute("UPDATE users SET role='ADMIN' WHERE email='admin@controltower.local'")
        db.migrate_super_admin()
        self.assertEqual(db.get_user_by_email('admin@controltower.local')['role'], 'ADMIN')


if __name__ == '__main__':
    unittest.main()
