"""User-management API checks using an isolated temporary database."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from api.main import app


class UsersApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch("db.database.DB_PATH", str(Path(self.temp.name) / "users.db"))
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.client = TestClient(app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        response = self.client.post("/auth/login", json={
            "email": "admin@controltower.local", "password": "Admin@1234",
        })
        self.assertEqual(response.status_code, 200)
        self.admin = response.json()["user"]
        self.headers = {"Authorization": "Bearer " + response.json()["token"]}

    def create_user(self, email="test@example.com", role="DEVOPS_ENGINEER"):
        response = self.client.post("/users", headers=self.headers, json={
            "email": email, "name": "Test User", "password": "Test-only-123", "role": role,
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertNotIn("password_hash", response.json())
        return response.json()

    def test_create_change_role_and_deactivate_persist(self):
        user = self.create_user()
        login = self.client.post("/auth/login", json={"email": user["email"], "password": "Test-only-123"})
        user_headers = {"Authorization": "Bearer " + login.json()["token"]}
        self.assertEqual(self.client.get("/users", headers=user_headers).status_code, 403)
        response = self.client.put(f'/users/{user["id"]}', headers=self.headers, json={"role": "CYBER_MANAGER"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/auth/me", headers=user_headers).json()["role"], "CYBER_MANAGER")
        self.assertEqual(self.client.get("/users", headers=user_headers).status_code, 403)
        self.client.put(f'/users/{user["id"]}', headers=self.headers, json={"is_active": False})
        stored = next(item for item in self.client.get("/users", headers=self.headers).json() if item["id"] == user["id"])
        self.assertEqual(stored["role"], "CYBER_MANAGER")
        self.assertFalse(stored["is_active"])
        self.assertEqual(self.client.get("/auth/me", headers=user_headers).status_code, 401)
        denied = self.client.post("/auth/login", json={"email": user["email"], "password": "Test-only-123"})
        self.assertEqual(denied.status_code, 403)
        self.client.put(f'/users/{user["id"]}', headers=self.headers, json={"is_active": True})
        self.assertEqual(self.client.post("/auth/login", json={"email": user["email"], "password": "Test-only-123"}).status_code, 200)

    def test_duplicate_and_invalid_role_do_not_create_accounts(self):
        user = self.create_user()
        payload = {"email": user["email"], "name": "Duplicate", "password": "Test-only-123", "role": "ADMIN"}
        self.assertEqual(self.client.post("/users", headers=self.headers, json=payload).status_code, 409)
        payload.update(email="other@example.com", role="reviewer")
        self.assertEqual(self.client.post("/users", headers=self.headers, json=payload).status_code, 422)
        self.assertEqual(len(self.client.get("/users", headers=self.headers).json()), 2)

    def test_admin_cannot_remove_own_access(self):
        path = f'/users/{self.admin["id"]}'
        for payload in ({"is_active": False}, {"role": "CYBER_MANAGER"}, {"role": "DEVOPS_ENGINEER"}):
            self.assertEqual(self.client.put(path, headers=self.headers, json=payload).status_code, 400)
        self.assertEqual(self.client.delete(path, headers=self.headers).status_code, 400)
        self.assertEqual(self.client.get("/users", headers=self.headers).status_code, 200)

    def test_non_admin_cannot_manage_users(self):
        user = self.create_user(role="CYBER_MANAGER")
        login = self.client.post("/auth/login", json={"email": user["email"], "password": "Test-only-123"})
        headers = {"Authorization": "Bearer " + login.json()["token"]}
        self.assertEqual(self.client.get("/users").status_code, 401)
        self.assertEqual(self.client.post("/users", headers=headers, json={"email": "new@example.com", "name": "New", "password": "Test-only-123"}).status_code, 403)
        self.assertEqual(self.client.put(f'/users/{user["id"]}', headers=headers, json={"role": "ADMIN"}).status_code, 403)
        self.assertEqual(self.client.delete(f'/users/{user["id"]}', headers=headers).status_code, 403)


if __name__ == "__main__":
    unittest.main()
