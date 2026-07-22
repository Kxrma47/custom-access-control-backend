from __future__ import annotations

import sqlite3
from pathlib import Path

from .auth import hash_password, to_iso, utc_now


PERMISSION_COLUMNS = (
    "read_permission",
    "read_all_permission",
    "create_permission",
    "update_permission",
    "update_all_permission",
    "delete_permission",
    "delete_all_permission",
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_name TEXT NOT NULL,
    first_name TEXT NOT NULL,
    middle_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS business_elements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    element_id INTEGER NOT NULL REFERENCES business_elements(id) ON DELETE CASCADE,
    read_permission INTEGER NOT NULL DEFAULT 0,
    read_all_permission INTEGER NOT NULL DEFAULT 0,
    create_permission INTEGER NOT NULL DEFAULT 0,
    update_permission INTEGER NOT NULL DEFAULT 0,
    update_all_permission INTEGER NOT NULL DEFAULT 0,
    delete_permission INTEGER NOT NULL DEFAULT 0,
    delete_all_permission INTEGER NOT NULL DEFAULT 0,
    UNIQUE (role_id, element_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
"""


ROLES = (
    ("admin", "Administrator"),
    ("manager", "Manager"),
    ("user", "User"),
)


ELEMENTS = (
    ("orders", "Orders", "Customer order resources."),
    ("products", "Products", "Product catalog resources."),
    ("reports", "Reports", "Business report resources."),
    ("access_rules", "Access rules", "Authorization policy resources."),
)


RULES = {
    "admin": {
        "orders": dict.fromkeys(PERMISSION_COLUMNS, 1),
        "products": dict.fromkeys(PERMISSION_COLUMNS, 1),
        "reports": dict.fromkeys(PERMISSION_COLUMNS, 1),
        "access_rules": dict.fromkeys(PERMISSION_COLUMNS, 1),
    },
    "manager": {
        "orders": {
            "read_permission": 1,
            "read_all_permission": 1,
            "create_permission": 1,
            "update_permission": 1,
            "update_all_permission": 1,
            "delete_permission": 0,
            "delete_all_permission": 0,
        },
        "products": {
            "read_permission": 1,
            "read_all_permission": 1,
            "create_permission": 1,
            "update_permission": 1,
            "update_all_permission": 1,
            "delete_permission": 0,
            "delete_all_permission": 0,
        },
        "reports": {
            "read_permission": 1,
            "read_all_permission": 1,
            "create_permission": 0,
            "update_permission": 0,
            "update_all_permission": 0,
            "delete_permission": 0,
            "delete_all_permission": 0,
        },
    },
    "user": {
        "orders": {
            "read_permission": 1,
            "read_all_permission": 0,
            "create_permission": 1,
            "update_permission": 1,
            "update_all_permission": 0,
            "delete_permission": 1,
            "delete_all_permission": 0,
        },
        "products": {
            "read_permission": 1,
            "read_all_permission": 1,
            "create_permission": 0,
            "update_permission": 0,
            "update_all_permission": 0,
            "delete_permission": 0,
            "delete_all_permission": 0,
        },
        "reports": {
            "read_permission": 0,
            "read_all_permission": 0,
            "create_permission": 0,
            "update_permission": 0,
            "update_all_permission": 0,
            "delete_permission": 0,
            "delete_all_permission": 0,
        },
    },
}


SEEDED_USERS = (
    {
        "last_name": "Admin",
        "first_name": "System",
        "middle_name": "",
        "email": "admin@example.com",
        "password": "AdminPass123!",
        "role": "admin",
    },
    {
        "last_name": "Manager",
        "first_name": "Mary",
        "middle_name": "",
        "email": "manager@example.com",
        "password": "ManagerPass123!",
        "role": "manager",
    },
    {
        "last_name": "User",
        "first_name": "Peter",
        "middle_name": "",
        "email": "user@example.com",
        "password": "UserPass123!",
        "role": "user",
    },
)


def connect(database_path: Path | str) -> sqlite3.Connection:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    seed_database(connection)
    connection.commit()


def seed_database(connection: sqlite3.Connection) -> None:
    now = to_iso(utc_now())

    for code, name in ROLES:
        connection.execute(
            "INSERT OR IGNORE INTO roles (code, name) VALUES (?, ?)",
            (code, name),
        )

    for code, name, description in ELEMENTS:
        connection.execute(
            """
            INSERT OR IGNORE INTO business_elements (code, name, description)
            VALUES (?, ?, ?)
            """,
            (code, name, description),
        )

    for user in SEEDED_USERS:
        connection.execute(
            """
            INSERT OR IGNORE INTO users (
                last_name, first_name, middle_name, email, password_hash,
                is_active, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                user["last_name"],
                user["first_name"],
                user["middle_name"],
                user["email"],
                hash_password(user["password"]),
                now,
                now,
            ),
        )
        user_id = _id_for_code(connection, "users", "email", user["email"])
        role_id = _id_for_code(connection, "roles", "code", user["role"])
        connection.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
            (user_id, role_id),
        )

    for role_code, element_rules in RULES.items():
        role_id = _id_for_code(connection, "roles", "code", role_code)
        for element_code, permissions in element_rules.items():
            element_id = _id_for_code(
                connection,
                "business_elements",
                "code",
                element_code,
            )
            values = [int(bool(permissions.get(column, 0))) for column in PERMISSION_COLUMNS]
            connection.execute(
                f"""
                INSERT OR IGNORE INTO access_rules (
                    role_id, element_id, {", ".join(PERMISSION_COLUMNS)}
                )
                VALUES (?, ?, {", ".join("?" for _ in PERMISSION_COLUMNS)})
                """,
                (role_id, element_id, *values),
            )


def _id_for_code(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    value: str,
) -> int:
    row = connection.execute(
        f"SELECT id FROM {table} WHERE {column} = ?",
        (value,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Missing seed row in {table}: {value}")
    return int(row["id"])
