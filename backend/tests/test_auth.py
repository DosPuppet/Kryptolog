"""Tests for /auth endpoints — nonce generation and login flow."""

from conftest import (
    TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY,
    get_nonce, do_login, auth_header,
)


class TestNonce:
    def test_get_nonce_returns_hex_string(self, client):
        nonce = get_nonce(client, TEST_USER_ADDRESS)
        assert isinstance(nonce, str)
        assert len(nonce) == 32  # token_hex(16) → 32 hex chars

    def test_get_nonce_replaces_on_second_call(self, client):
        nonce1 = get_nonce(client, TEST_USER_ADDRESS)
        nonce2 = get_nonce(client, TEST_USER_ADDRESS)
        assert isinstance(nonce2, str)
        assert len(nonce2) == 32

    def test_get_nonce_normalizes_to_lowercase(self, client):
        addr = "PQC_UPPER_" + "A" * 100
        nonce = get_nonce(client, addr)
        assert len(nonce) == 32


class TestLogin:
    def test_login_success_creates_user(self, client):
        token, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        assert token is not None
        assert len(token) > 0
        assert user["address"] == TEST_USER_ADDRESS.lower()
        assert user["username"] == "Alice"

    def test_login_returns_bearer_token(self, client):
        nonce = get_nonce(client, TEST_USER_ADDRESS)
        resp = client.post("/auth/login", json={
            "address": TEST_USER_ADDRESS,
            "signature": "fake",
            "nonce": nonce,
            "encryption_public_key": TEST_ENCRYPTION_KEY,
        })
        data = resp.json()
        assert data["token_type"] == "bearer"

    def test_login_with_wrong_nonce_fails(self, client):
        get_nonce(client, TEST_USER_ADDRESS)
        resp = client.post("/auth/login", json={
            "address": TEST_USER_ADDRESS,
            "signature": "fake",
            "nonce": "wrong_nonce_value",
        })
        assert resp.status_code == 400

    def test_login_without_requesting_nonce_fails(self, client):
        resp = client.post("/auth/login", json={
            "address": TEST_USER_ADDRESS,
            "signature": "fake",
            "nonce": "whatever",
        })
        assert resp.status_code == 400

    def test_nonce_consumed_after_login(self, client):
        """Anti-replay: same nonce cannot be used twice."""
        nonce = get_nonce(client, TEST_USER_ADDRESS)
        body = {
            "address": TEST_USER_ADDRESS,
            "signature": "fake",
            "nonce": nonce,
            "encryption_public_key": TEST_ENCRYPTION_KEY,
        }
        resp1 = client.post("/auth/login", json=body)
        assert resp1.status_code == 200
        resp2 = client.post("/auth/login", json=body)
        assert resp2.status_code == 400

    def test_login_updates_encryption_key(self, client):
        do_login(client, TEST_USER_ADDRESS, "old_key_" + "x" * 100)
        token2, user2 = do_login(client, TEST_USER_ADDRESS, "new_key_" + "y" * 100)
        assert user2["encryption_public_key"] == "new_key_" + "y" * 100

    def test_login_default_username_from_address(self, client):
        token, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY)
        assert user["username"] == TEST_USER_ADDRESS.lower()[:7]
