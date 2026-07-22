from __future__ import annotations

import time
import unittest

from access_app.auth import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


class AuthTests(unittest.TestCase):
    def test_password_hash_verification(self) -> None:
        stored_hash = hash_password("CorrectPass123!")

        self.assertTrue(verify_password("CorrectPass123!", stored_hash))
        self.assertFalse(verify_password("WrongPass123!", stored_hash))
        self.assertNotIn("CorrectPass123!", stored_hash)

    def test_token_round_trip_and_tamper_detection(self) -> None:
        token = create_access_token(
            user_id=7,
            session_id=11,
            token_id="token-id",
            secret_key="test-secret",
            ttl_seconds=60,
        )

        payload = decode_access_token(token, secret_key="test-secret")
        self.assertEqual(payload["user_id"], 7)
        self.assertEqual(payload["session_id"], 11)
        self.assertEqual(payload["jti"], "token-id")

        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(TokenError):
            decode_access_token(tampered, secret_key="test-secret")

    def test_expired_token_is_rejected(self) -> None:
        token = create_access_token(
            user_id=1,
            session_id=1,
            token_id="expired-token",
            secret_key="test-secret",
            ttl_seconds=1,
        )

        with self.assertRaises(TokenError):
            decode_access_token(token, secret_key="test-secret", now=int(time.time()) + 2)


if __name__ == "__main__":
    unittest.main()
