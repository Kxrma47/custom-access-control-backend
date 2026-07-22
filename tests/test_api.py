from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from access_app import Settings, create_server


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "api.sqlite3"
        self.settings = Settings(
            database_path=self.database_path,
            secret_key="test-secret",
            token_ttl_seconds=3600,
            host="127.0.0.1",
            port=0,
        )
        self.server = create_server(self.settings)
        self.host, self.port = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.tempdir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        raw_body = json.dumps(body).encode("utf-8") if body is not None else None

        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        connection.request(method, path, body=raw_body, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, payload

    def login(self, email: str, password: str) -> str:
        status, payload = self.request(
            "POST",
            "/auth/login",
            {"email": email, "password": password},
        )
        self.assertEqual(status, 200, payload)
        return str(payload["access_token"])

    def test_health_and_admin_rule_listing(self) -> None:
        status, payload = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

        admin_token = self.login("admin@example.com", "AdminPass123!")
        status, payload = self.request("GET", "/access/rules", token=admin_token)

        self.assertEqual(status, 200, payload)
        self.assertGreaterEqual(len(payload["rules"]), 8)
        self.assertTrue(
            any(
                rule["role"] == "admin" and rule["element"] == "access_rules"
                for rule in payload["rules"]
            )
        )

    def test_register_login_profile_update_and_logout(self) -> None:
        status, payload = self.request(
            "POST",
            "/auth/register",
            {
                "last_name": "Ivanov",
                "first_name": "Ivan",
                "middle_name": "Ivanovich",
                "email": "ivan@example.com",
                "password": "StrongPass123!",
                "password_repeat": "StrongPass123!",
            },
        )
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["user"]["roles"], ["user"])

        token = self.login("ivan@example.com", "StrongPass123!")
        status, payload = self.request("GET", "/me", token=token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["user"]["email"], "ivan@example.com")

        status, payload = self.request(
            "PATCH",
            "/me",
            {"first_name": "Ivan Updated"},
            token=token,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["user"]["first_name"], "Ivan Updated")

        status, payload = self.request("POST", "/auth/logout", token=token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "logged_out")

        status, payload = self.request("GET", "/me", token=token)
        self.assertEqual(status, 401, payload)

    def test_soft_delete_blocks_future_login(self) -> None:
        status, payload = self.request(
            "POST",
            "/auth/register",
            {
                "last_name": "Petrova",
                "first_name": "Anna",
                "middle_name": "",
                "email": "anna@example.com",
                "password": "StrongPass123!",
                "password_repeat": "StrongPass123!",
            },
        )
        self.assertEqual(status, 201, payload)

        token = self.login("anna@example.com", "StrongPass123!")
        status, payload = self.request("DELETE", "/me", token=token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "account_deactivated")

        status, payload = self.request(
            "POST",
            "/auth/login",
            {"email": "anna@example.com", "password": "StrongPass123!"},
        )
        self.assertEqual(status, 401, payload)
        self.assertEqual(payload["error"], "User account is inactive.")

    def test_business_resources_return_401_403_and_allowed_results(self) -> None:
        status, payload = self.request("GET", "/business/orders")
        self.assertEqual(status, 401, payload)

        user_token = self.login("user@example.com", "UserPass123!")
        status, payload = self.request("GET", "/business/orders", token=user_token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["scope"], "own")
        self.assertEqual([item["id"] for item in payload["items"]], [1, 3])

        status, payload = self.request("GET", "/business/reports", token=user_token)
        self.assertEqual(status, 403, payload)

        status, payload = self.request(
            "POST",
            "/business/products",
            {"sku": "PRD-NEW", "name": "New product"},
            token=user_token,
        )
        self.assertEqual(status, 403, payload)

        manager_token = self.login("manager@example.com", "ManagerPass123!")
        status, payload = self.request("GET", "/business/reports", token=manager_token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["scope"], "all")
        self.assertEqual(len(payload["items"]), 2)

    def test_admin_can_change_rules_for_user_role(self) -> None:
        user_token = self.login("user@example.com", "UserPass123!")
        status, payload = self.request("GET", "/business/reports", token=user_token)
        self.assertEqual(status, 403, payload)

        admin_token = self.login("admin@example.com", "AdminPass123!")
        status, payload = self.request(
            "POST",
            "/access/rules",
            {
                "role": "user",
                "element": "reports",
                "permissions": {
                    "read_permission": True,
                    "read_all_permission": True,
                    "create_permission": False,
                    "update_permission": False,
                    "update_all_permission": False,
                    "delete_permission": False,
                    "delete_all_permission": False,
                },
            },
            token=admin_token,
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["rule"]["permissions"]["read_all_permission"])

        status, payload = self.request("GET", "/business/reports", token=user_token)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["scope"], "all")


if __name__ == "__main__":
    unittest.main()
