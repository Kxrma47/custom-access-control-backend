from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from access_app.database import connect, initialize_database
from access_app.permissions import decide_access, is_admin


class PermissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "test.sqlite3"
        self.connection = connect(self.database_path)
        initialize_database(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.tempdir.cleanup()

    def test_seeded_roles_match_expected_scopes(self) -> None:
        self.assertTrue(is_admin(self.connection, 1))
        self.assertFalse(is_admin(self.connection, 3))

        user_own_order = decide_access(
            self.connection,
            user_id=3,
            element_code="orders",
            action="read",
            owner_id=3,
        )
        user_other_order = decide_access(
            self.connection,
            user_id=3,
            element_code="orders",
            action="read",
            owner_id=2,
        )
        manager_reports = decide_access(
            self.connection,
            user_id=2,
            element_code="reports",
            action="read",
        )

        self.assertTrue(user_own_order.allowed)
        self.assertEqual(user_own_order.scope, "own")
        self.assertFalse(user_other_order.allowed)
        self.assertTrue(manager_reports.allowed)
        self.assertEqual(manager_reports.scope, "all")


if __name__ == "__main__":
    unittest.main()
