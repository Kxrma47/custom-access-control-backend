from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .auth import (
    TokenError,
    create_access_token,
    decode_access_token,
    from_iso,
    hash_password,
    new_token_id,
    to_iso,
    token_expiry,
    utc_now,
    verify_password,
)
from .database import PERMISSION_COLUMNS, connect, initialize_database
from .permissions import AuthorizationError, decide_access, is_admin, require_access
from .settings import Settings


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PATH_ID_RE = re.compile(r"^/access/rules/(\d+)$")


MOCK_OBJECTS: dict[str, list[dict[str, Any]]] = {
    "orders": [
        {"id": 1, "owner_id": 3, "number": "ORD-1001", "amount": 1840.0},
        {"id": 2, "owner_id": 2, "number": "ORD-1002", "amount": 920.0},
        {"id": 3, "owner_id": 3, "number": "ORD-1003", "amount": 310.0},
    ],
    "products": [
        {"id": 1, "owner_id": 2, "sku": "PRD-001", "name": "Desk lamp"},
        {"id": 2, "owner_id": 2, "sku": "PRD-002", "name": "Notebook"},
    ],
    "reports": [
        {"id": 1, "owner_id": 2, "title": "Quarterly sales"},
        {"id": 2, "owner_id": 2, "title": "Customer retention"},
    ],
}


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class CurrentUser:
    id: int
    email: str
    first_name: str
    last_name: str
    middle_name: str
    session_id: int
    token_id: str


class AccessApplication:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def initialize(self) -> None:
        connection = connect(self.settings.database_path)
        try:
            initialize_database(connection)
        finally:
            connection.close()

    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        parsed_path = urlparse(path).path.rstrip("/") or "/"
        connection = connect(self.settings.database_path)
        try:
            return self._dispatch(
                connection=connection,
                method=method.upper(),
                path=parsed_path,
                headers=headers,
                body=body or {},
            )
        except ApiError as error:
            return error.status, {"error": error.message}
        except AuthorizationError:
            return HTTPStatus.FORBIDDEN, {"error": "Forbidden."}
        finally:
            connection.close()

    def _dispatch(
        self,
        *,
        connection: sqlite3.Connection,
        method: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        if method == "GET" and path == "/health":
            return HTTPStatus.OK, {"status": "ok"}

        if method == "POST" and path == "/auth/register":
            return self._register(connection, body)
        if method == "POST" and path == "/auth/login":
            return self._login(connection, body)
        if method == "POST" and path == "/auth/logout":
            current_user = self._current_user(connection, headers)
            return self._logout(connection, current_user)

        if path == "/me":
            current_user = self._current_user(connection, headers)
            if method == "GET":
                return HTTPStatus.OK, {"user": self._public_user(connection, current_user.id)}
            if method == "PATCH":
                return self._update_me(connection, current_user.id, body)
            if method == "DELETE":
                return self._delete_me(connection, current_user)

        if path.startswith("/access/"):
            current_user = self._current_user(connection, headers)
            self._require_admin(connection, current_user.id)
            if method == "GET" and path == "/access/roles":
                return HTTPStatus.OK, {"roles": self._list_roles(connection)}
            if method == "GET" and path == "/access/elements":
                return HTTPStatus.OK, {"elements": self._list_elements(connection)}
            if method == "GET" and path == "/access/rules":
                return HTTPStatus.OK, {"rules": self._list_rules(connection)}
            if method == "POST" and path == "/access/rules":
                return self._upsert_rule(connection, body)
            match = PATH_ID_RE.match(path)
            if match and method == "PATCH":
                return self._patch_rule(connection, int(match.group(1)), body)
            if match and method == "DELETE":
                return self._delete_rule(connection, int(match.group(1)))

        if path.startswith("/business/"):
            current_user = self._current_user(connection, headers)
            element_code = path.split("/", 2)[2]
            if method == "GET":
                return self._list_business_objects(connection, current_user.id, element_code)
            if method == "POST":
                return self._create_business_object(connection, current_user.id, element_code, body)

        raise ApiError(HTTPStatus.NOT_FOUND, "Route not found.")

    def _register(
        self,
        connection: sqlite3.Connection,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        required = ("last_name", "first_name", "email", "password", "password_repeat")
        missing = [field for field in required if not str(body.get(field, "")).strip()]
        if missing:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"Missing fields: {', '.join(missing)}.")

        email = str(body["email"]).strip().lower()
        password = str(body["password"])
        if not EMAIL_RE.match(email):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid email.")
        if password != str(body["password_repeat"]):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Passwords do not match.")
        if len(password) < 8:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Password must contain at least 8 characters.")

        now = to_iso(utc_now())
        try:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    last_name, first_name, middle_name, email, password_hash,
                    is_active, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    str(body["last_name"]).strip(),
                    str(body["first_name"]).strip(),
                    str(body.get("middle_name", "")).strip(),
                    email,
                    hash_password(password),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            raise ApiError(HTTPStatus.CONFLICT, "Email is already registered.") from None

        user_id = int(cursor.lastrowid)
        role_id = self._role_id(connection, "user")
        connection.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
            (user_id, role_id),
        )
        connection.commit()
        return HTTPStatus.CREATED, {"user": self._public_user(connection, user_id)}

    def _login(
        self,
        connection: sqlite3.Connection,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        email = str(body.get("email", "")).strip().lower()
        password = str(body.get("password", ""))
        row = connection.execute(
            """
            SELECT id, email, password_hash, is_active
            FROM users
            WHERE lower(email) = ?
            """,
            (email,),
        ).fetchone()

        if row is None or not verify_password(password, str(row["password_hash"])):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Invalid email or password.")
        if int(row["is_active"]) != 1:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "User account is inactive.")

        token_id = new_token_id()
        expires_at = token_expiry(self.settings.token_ttl_seconds)
        cursor = connection.execute(
            """
            INSERT INTO sessions (user_id, token_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (int(row["id"]), token_id, to_iso(utc_now()), to_iso(expires_at)),
        )
        session_id = int(cursor.lastrowid)
        access_token = create_access_token(
            user_id=int(row["id"]),
            session_id=session_id,
            token_id=token_id,
            secret_key=self.settings.secret_key,
            ttl_seconds=self.settings.token_ttl_seconds,
        )
        connection.commit()
        return (
            HTTPStatus.OK,
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_at": to_iso(expires_at),
                "user": self._public_user(connection, int(row["id"])),
            },
        )

    def _logout(
        self,
        connection: sqlite3.Connection,
        current_user: CurrentUser,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        connection.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ?",
            (to_iso(utc_now()), current_user.session_id),
        )
        connection.commit()
        return HTTPStatus.OK, {"status": "logged_out"}

    def _update_me(
        self,
        connection: sqlite3.Connection,
        user_id: int,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        allowed_fields = {"last_name", "first_name", "middle_name", "email", "password"}
        updates = {key: value for key, value in body.items() if key in allowed_fields}
        if not updates:
            raise ApiError(HTTPStatus.BAD_REQUEST, "No supported profile fields supplied.")

        values: list[Any] = []
        assignments: list[str] = []
        if "email" in updates:
            email = str(updates["email"]).strip().lower()
            if not EMAIL_RE.match(email):
                raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid email.")
            assignments.append("email = ?")
            values.append(email)

        for field in ("last_name", "first_name", "middle_name"):
            if field in updates:
                assignments.append(f"{field} = ?")
                values.append(str(updates[field]).strip())

        if "password" in updates:
            password = str(updates["password"])
            if len(password) < 8:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Password must contain at least 8 characters.")
            assignments.append("password_hash = ?")
            values.append(hash_password(password))

        assignments.append("updated_at = ?")
        values.append(to_iso(utc_now()))
        values.append(user_id)

        try:
            connection.execute(
                f"UPDATE users SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
        except sqlite3.IntegrityError:
            raise ApiError(HTTPStatus.CONFLICT, "Email is already registered.") from None
        connection.commit()
        return HTTPStatus.OK, {"user": self._public_user(connection, user_id)}

    def _delete_me(
        self,
        connection: sqlite3.Connection,
        current_user: CurrentUser,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        now = to_iso(utc_now())
        connection.execute(
            "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
            (now, current_user.id),
        )
        connection.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now, current_user.id),
        )
        connection.commit()
        return HTTPStatus.OK, {"status": "account_deactivated"}

    def _current_user(
        self,
        connection: sqlite3.Connection,
        headers: dict[str, str],
    ) -> CurrentUser:
        authorization = headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Authentication required.")

        token = authorization.removeprefix("Bearer ").strip()
        try:
            payload = decode_access_token(token, secret_key=self.settings.secret_key)
        except TokenError as error:
            raise ApiError(HTTPStatus.UNAUTHORIZED, str(error)) from None

        row = connection.execute(
            """
            SELECT
                users.id,
                users.email,
                users.first_name,
                users.last_name,
                users.middle_name,
                users.is_active,
                sessions.id AS session_id,
                sessions.token_id,
                sessions.expires_at,
                sessions.revoked_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.id = ?
              AND sessions.token_id = ?
              AND users.id = ?
            """,
            (payload["session_id"], payload["jti"], payload["user_id"]),
        ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Authentication required.")
        if int(row["is_active"]) != 1 or row["revoked_at"] is not None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Authentication required.")
        if from_iso(str(row["expires_at"])) < utc_now():
            raise ApiError(HTTPStatus.UNAUTHORIZED, "Bearer token has expired.")

        return CurrentUser(
            id=int(row["id"]),
            email=str(row["email"]),
            first_name=str(row["first_name"]),
            last_name=str(row["last_name"]),
            middle_name=str(row["middle_name"]),
            session_id=int(row["session_id"]),
            token_id=str(row["token_id"]),
        )

    def _require_admin(self, connection: sqlite3.Connection, user_id: int) -> None:
        if not is_admin(connection, user_id):
            raise AuthorizationError("Forbidden.")

    def _public_user(self, connection: sqlite3.Connection, user_id: int) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT id, last_name, first_name, middle_name, email, is_active
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "User not found.")
        return {
            "id": int(row["id"]),
            "last_name": str(row["last_name"]),
            "first_name": str(row["first_name"]),
            "middle_name": str(row["middle_name"]),
            "email": str(row["email"]),
            "is_active": bool(row["is_active"]),
            "roles": self._roles_for_user(connection, user_id),
        }

    def _roles_for_user(self, connection: sqlite3.Connection, user_id: int) -> list[str]:
        rows = connection.execute(
            """
            SELECT roles.code
            FROM roles
            JOIN user_roles ON user_roles.role_id = roles.id
            WHERE user_roles.user_id = ?
            ORDER BY roles.code
            """,
            (user_id,),
        ).fetchall()
        return [str(row["code"]) for row in rows]

    def _list_roles(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute("SELECT id, code, name FROM roles ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def _list_elements(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT id, code, name, description FROM business_elements ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]

    def _list_rules(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            f"""
            SELECT
                access_rules.id,
                roles.code AS role,
                business_elements.code AS element,
                {", ".join("access_rules." + column for column in PERMISSION_COLUMNS)}
            FROM access_rules
            JOIN roles ON roles.id = access_rules.role_id
            JOIN business_elements ON business_elements.id = access_rules.element_id
            ORDER BY roles.code, business_elements.code
            """
        ).fetchall()
        return [self._rule_response(row) for row in rows]

    def _upsert_rule(
        self,
        connection: sqlite3.Connection,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        role_code = str(body.get("role", "")).strip()
        element_code = str(body.get("element", "")).strip()
        role_id = self._role_id(connection, role_code)
        element_id = self._element_id(connection, element_code)
        permissions = self._permissions_from_body(body)

        value_slots = ", ".join("?" for _ in PERMISSION_COLUMNS)
        updates = ", ".join(f"{column} = excluded.{column}" for column in PERMISSION_COLUMNS)
        connection.execute(
            f"""
            INSERT INTO access_rules (
                role_id, element_id, {", ".join(PERMISSION_COLUMNS)}
            )
            VALUES (?, ?, {value_slots})
            ON CONFLICT(role_id, element_id) DO UPDATE SET {updates}
            """,
            (role_id, element_id, *[permissions[column] for column in PERMISSION_COLUMNS]),
        )
        connection.commit()
        rule = self._rule_by_role_and_element(connection, role_id, element_id)
        return HTTPStatus.OK, {"rule": rule}

    def _patch_rule(
        self,
        connection: sqlite3.Connection,
        rule_id: int,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        self._ensure_rule_exists(connection, rule_id)
        fields = [field for field in PERMISSION_COLUMNS if field in body]
        if not fields:
            raise ApiError(HTTPStatus.BAD_REQUEST, "No supported permission fields supplied.")

        values = [self._as_permission(body[field], field) for field in fields]
        connection.execute(
            f"UPDATE access_rules SET {', '.join(field + ' = ?' for field in fields)} WHERE id = ?",
            (*values, rule_id),
        )
        connection.commit()
        return HTTPStatus.OK, {"rule": self._rule_by_id(connection, rule_id)}

    def _delete_rule(
        self,
        connection: sqlite3.Connection,
        rule_id: int,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        self._ensure_rule_exists(connection, rule_id)
        connection.execute("DELETE FROM access_rules WHERE id = ?", (rule_id,))
        connection.commit()
        return HTTPStatus.OK, {"status": "rule_deleted"}

    def _list_business_objects(
        self,
        connection: sqlite3.Connection,
        user_id: int,
        element_code: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        self._element_id(connection, element_code)
        decision = require_access(
            connection,
            user_id=user_id,
            element_code=element_code,
            action="read",
        )
        objects = list(MOCK_OBJECTS.get(element_code, []))
        if decision.scope == "own":
            objects = [item for item in objects if item.get("owner_id") == user_id]
        return HTTPStatus.OK, {"items": objects, "scope": decision.scope}

    def _create_business_object(
        self,
        connection: sqlite3.Connection,
        user_id: int,
        element_code: str,
        body: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        self._element_id(connection, element_code)
        require_access(
            connection,
            user_id=user_id,
            element_code=element_code,
            action="create",
        )
        item = {
            "id": len(MOCK_OBJECTS.get(element_code, [])) + 1,
            "owner_id": user_id,
            "data": body,
        }
        return HTTPStatus.CREATED, {"item": item}

    def _rule_response(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "role": str(row["role"]),
            "element": str(row["element"]),
            "permissions": {
                column: bool(row[column])
                for column in PERMISSION_COLUMNS
            },
        }

    def _permissions_from_body(self, body: dict[str, Any]) -> dict[str, int]:
        permissions = body.get("permissions", body)
        if not isinstance(permissions, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Permissions must be an object.")
        return {
            column: self._as_permission(permissions.get(column, False), column)
            for column in PERMISSION_COLUMNS
        }

    def _as_permission(self, value: Any, field: str) -> int:
        if isinstance(value, bool):
            return int(value)
        if value in (0, 1):
            return int(value)
        raise ApiError(HTTPStatus.BAD_REQUEST, f"{field} must be a boolean.")

    def _role_id(self, connection: sqlite3.Connection, code: str) -> int:
        row = connection.execute("SELECT id FROM roles WHERE code = ?", (code,)).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Unknown role.")
        return int(row["id"])

    def _element_id(self, connection: sqlite3.Connection, code: str) -> int:
        row = connection.execute(
            "SELECT id FROM business_elements WHERE code = ?",
            (code,),
        ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Business element not found.")
        return int(row["id"])

    def _ensure_rule_exists(self, connection: sqlite3.Connection, rule_id: int) -> None:
        row = connection.execute("SELECT id FROM access_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Access rule not found.")

    def _rule_by_id(self, connection: sqlite3.Connection, rule_id: int) -> dict[str, Any]:
        row = connection.execute(
            f"""
            SELECT
                access_rules.id,
                roles.code AS role,
                business_elements.code AS element,
                {", ".join("access_rules." + column for column in PERMISSION_COLUMNS)}
            FROM access_rules
            JOIN roles ON roles.id = access_rules.role_id
            JOIN business_elements ON business_elements.id = access_rules.element_id
            WHERE access_rules.id = ?
            """,
            (rule_id,),
        ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Access rule not found.")
        return self._rule_response(row)

    def _rule_by_role_and_element(
        self,
        connection: sqlite3.Connection,
        role_id: int,
        element_id: int,
    ) -> dict[str, Any]:
        row = connection.execute(
            f"""
            SELECT
                access_rules.id,
                roles.code AS role,
                business_elements.code AS element,
                {", ".join("access_rules." + column for column in PERMISSION_COLUMNS)}
            FROM access_rules
            JOIN roles ON roles.id = access_rules.role_id
            JOIN business_elements ON business_elements.id = access_rules.element_id
            WHERE access_rules.role_id = ?
              AND access_rules.element_id = ?
            """,
            (role_id, element_id),
        ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Access rule not found.")
        return self._rule_response(row)


def create_server(settings: Settings | None = None) -> ThreadingHTTPServer:
    settings = settings or Settings.from_env()
    application = AccessApplication(settings)
    application.initialize()

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "AccessApplication/1.0"

        def do_GET(self) -> None:
            self._handle_request()

        def do_POST(self) -> None:
            self._handle_request()

        def do_PATCH(self) -> None:
            self._handle_request()

        def do_DELETE(self) -> None:
            self._handle_request()

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _handle_request(self) -> None:
            try:
                body = self._read_json_body()
                headers = {
                    key.lower(): value
                    for key, value in self.headers.items()
                }
                status, payload = application.handle(
                    method=self.command,
                    path=self.path,
                    headers=headers,
                    body=body,
                )
            except ApiError as error:
                status, payload = error.status, {"error": error.message}

            raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                decoded = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid JSON.") from None
            if not isinstance(decoded, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "JSON body must be an object.")
            return decoded

    return ThreadingHTTPServer((settings.host, settings.port), RequestHandler)
