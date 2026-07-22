from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any


HASH_ALGORITHM = "pbkdf2_sha256"
HASH_ITERATIONS = 310_000


class TokenError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def to_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def from_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(UTC)


def hash_password(password: str, *, salt: str | None = None) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        HASH_ITERATIONS,
    )
    return f"{HASH_ALGORITHM}${HASH_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$", 3)
        if algorithm != HASH_ALGORITHM or int(iterations) != HASH_ITERATIONS:
            return False
        candidate = hash_password(password, salt=salt).split("$", 3)[3]
    except (AttributeError, TypeError, ValueError):
        return False

    return hmac.compare_digest(candidate, expected)


def new_token_id() -> str:
    return secrets.token_urlsafe(24)


def token_expiry(ttl_seconds: int) -> datetime:
    return utc_now() + timedelta(seconds=ttl_seconds)


def create_access_token(
    *,
    user_id: int,
    session_id: int,
    token_id: str,
    secret_key: str,
    ttl_seconds: int,
) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": token_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(
        [
            _encode_json(header),
            _encode_json(payload),
        ]
    )
    signature = _sign(signing_input, secret_key)
    return f"{signing_input}.{signature}"


def decode_access_token(
    token: str,
    *,
    secret_key: str,
    now: int | None = None,
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("Invalid bearer token.")

    signing_input = ".".join(parts[:2])
    expected_signature = _sign(signing_input, secret_key)
    if not hmac.compare_digest(expected_signature, parts[2]):
        raise TokenError("Invalid bearer token.")

    try:
        header = json.loads(_decode_segment(parts[0]))
        payload = json.loads(_decode_segment(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise TokenError("Invalid bearer token.") from None

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise TokenError("Unsupported bearer token.")

    required = {"sub", "sid", "jti", "iat", "exp"}
    if not required.issubset(payload):
        raise TokenError("Invalid bearer token.")

    current_time = int(time.time()) if now is None else now
    if int(payload["exp"]) < current_time:
        raise TokenError("Bearer token has expired.")

    try:
        payload["user_id"] = int(payload["sub"])
        payload["session_id"] = int(payload["sid"])
    except (TypeError, ValueError):
        raise TokenError("Invalid bearer token.") from None

    return payload


def _encode_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _encode_segment(raw)


def _encode_segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_segment(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8")


def _sign(signing_input: str, secret_key: str) -> str:
    signature = hmac.new(
        secret_key.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _encode_segment(signature)
