from __future__ import annotations

import http.client
import json
import tempfile
import threading
from pathlib import Path
from typing import Any

from access_app import Settings, create_server


def main() -> None:
    with tempfile.TemporaryDirectory() as tempdir:
        settings = Settings(
            database_path=Path(tempdir) / "demo.sqlite3",
            secret_key="demo-secret",
            token_ttl_seconds=3600,
            host="127.0.0.1",
            port=0,
        )
        server = create_server(settings)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            run_demo(host, port)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw_body = json.dumps(body).encode("utf-8") if body is not None else None
    connection = http.client.HTTPConnection(host, port, timeout=5)
    connection.request(method, path, body=raw_body, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, payload


def run_demo(host: str, port: int) -> None:
    status, payload = request(host, port, "GET", "/health")
    print(f"GET /health -> {status} {payload}")

    status, payload = request(host, port, "GET", "/business/orders")
    print(f"GET /business/orders without token -> {status} {payload}")

    status, payload = request(
        host,
        port,
        "POST",
        "/auth/login",
        {"email": "user@example.com", "password": "UserPass123!"},
    )
    user_token = payload["access_token"]
    print(f"POST /auth/login user@example.com -> {status} token_type={payload['token_type']}")

    status, payload = request(host, port, "GET", "/business/orders", token=user_token)
    order_ids = [item["id"] for item in payload["items"]]
    print(f"GET /business/orders as user -> {status} scope={payload['scope']} ids={order_ids}")

    status, payload = request(host, port, "GET", "/business/reports", token=user_token)
    print(f"GET /business/reports as user -> {status} {payload}")

    status, payload = request(
        host,
        port,
        "POST",
        "/auth/login",
        {"email": "admin@example.com", "password": "AdminPass123!"},
    )
    admin_token = payload["access_token"]
    print(f"POST /auth/login admin@example.com -> {status} token_type={payload['token_type']}")

    status, payload = request(
        host,
        port,
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
    print(
        "POST /access/rules as admin -> "
        f"{status} role={payload['rule']['role']} element={payload['rule']['element']}"
    )

    status, payload = request(host, port, "GET", "/business/reports", token=user_token)
    print(f"GET /business/reports as user after rule change -> {status} scope={payload['scope']}")


if __name__ == "__main__":
    main()
