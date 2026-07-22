from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .database import PERMISSION_COLUMNS


ACTION_COLUMNS = {
    "read": ("read_permission", "read_all_permission"),
    "create": ("create_permission", None),
    "update": ("update_permission", "update_all_permission"),
    "delete": ("delete_permission", "delete_all_permission"),
}


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    scope: str = "none"


def role_codes_for_user(connection: sqlite3.Connection, user_id: int) -> list[str]:
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


def is_admin(connection: sqlite3.Connection, user_id: int) -> bool:
    return "admin" in role_codes_for_user(connection, user_id)


def decide_access(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    element_code: str,
    action: str,
    owner_id: int | None = None,
) -> AccessDecision:
    if action not in ACTION_COLUMNS:
        raise ValueError(f"Unsupported action: {action}")

    own_column, all_column = ACTION_COLUMNS[action]
    selected_columns = [own_column]
    if all_column:
        selected_columns.append(all_column)

    rows = connection.execute(
        f"""
        SELECT {", ".join("access_rules." + column for column in PERMISSION_COLUMNS)}
        FROM access_rules
        JOIN roles ON roles.id = access_rules.role_id
        JOIN user_roles ON user_roles.role_id = roles.id
        JOIN business_elements ON business_elements.id = access_rules.element_id
        WHERE user_roles.user_id = ?
          AND business_elements.code = ?
        """,
        (user_id, element_code),
    ).fetchall()

    if not rows:
        return AccessDecision(False)

    if all_column and any(int(row[all_column]) == 1 for row in rows):
        return AccessDecision(True, "all")

    if any(int(row[own_column]) == 1 for row in rows):
        if action == "create":
            return AccessDecision(True, "own")
        if owner_id is None:
            return AccessDecision(True, "own")
        if owner_id == user_id:
            return AccessDecision(True, "own")

    return AccessDecision(False)


def require_access(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    element_code: str,
    action: str,
    owner_id: int | None = None,
) -> AccessDecision:
    decision = decide_access(
        connection,
        user_id=user_id,
        element_code=element_code,
        action=action,
        owner_id=owner_id,
    )
    if not decision.allowed:
        raise AuthorizationError("Forbidden.")
    return decision
