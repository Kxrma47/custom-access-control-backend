from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_path: Path
    secret_key: str
    token_ttl_seconds: int = 3600
    host: str = "127.0.0.1"
    port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        database_path = Path(
            os.environ.get("ACCESS_APP_DB", str(PROJECT_ROOT / "data" / "app.sqlite3"))
        )
        secret_key = os.environ.get(
            "ACCESS_APP_SECRET",
            "development-secret-change-before-production",
        )
        token_ttl_seconds = int(os.environ.get("ACCESS_APP_TOKEN_TTL", "3600"))
        host = os.environ.get("ACCESS_APP_HOST", "127.0.0.1")
        port = int(os.environ.get("ACCESS_APP_PORT", "8000"))
        return cls(
            database_path=database_path,
            secret_key=secret_key,
            token_ttl_seconds=token_ttl_seconds,
            host=host,
            port=port,
        )
