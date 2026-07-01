"""Tests for the invite-code access filter (audit §5).

The gate is opt-in via KRYPTOLOG_REQUIRE_INVITE and only covers *account
creation*. `config.invites_required()` is read at call time, so we toggle the
env var per-test with monkeypatch.
"""
import pytest

from conftest import (
    TEST_USER_ADDRESS, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY,
    get_nonce, do_login, auth_header,
)
import invites
from database import get_db
from main import app


@pytest.fixture
def require_invites(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_REQUIRE_INVITE", "true")
    yield


def _db():
    # The same session-factory override the app uses in tests.
    gen = app.dependency_overrides[get_db]()
    db = next(gen)
    return db, gen


def _mint(**kwargs):
    db, gen = _db()
    try:
        codes = invites.create_invites(db, **kwargs)
    finally:
        gen.close()
    return codes


def _login_with(client, address, code=None, encryption_key=TEST_ENCRYPTION_KEY):
    nonce = get_nonce(client, address)
    body = {
        "address": address,
        "signature": "fake_signature_for_testing",
        "nonce": nonce,
        "encryption_public_key": encryption_key,
        # Distinct username per address: the test addresses share the first 7
        # chars, so the default username (address[:7]) would collide and 409
        # before the invite is ever checked. address[:20] keeps them unique.
        "username": address[:20],
    }
    if code is not None:
        body["invite_code"] = code
    return client.post("/auth/login", json=body)


class TestInvitesDisabledByDefault:
    def test_registration_works_without_code_when_not_required(self, client):
        # No env flag set ⇒ invites not required ⇒ normal behavior.
        token, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        assert token


class TestInvitesRequired:
    def test_new_user_without_code_is_rejected(self, client, require_invites):
        resp = _login_with(client, TEST_USER_ADDRESS, code=None)
        assert resp.status_code == 403

    def test_new_user_with_invalid_code_is_rejected(self, client, require_invites):
        resp = _login_with(client, TEST_USER_ADDRESS, code="not-a-real-code")
        assert resp.status_code == 403

    def test_new_user_with_valid_code_registers(self, client, require_invites):
        code = _mint(count=1)[0]
        resp = _login_with(client, TEST_USER_ADDRESS, code=code)
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["address"] == TEST_USER_ADDRESS.lower()

    def test_single_use_code_cannot_be_reused(self, client, require_invites):
        code = _mint(count=1)[0]
        # First identity consumes it.
        assert _login_with(client, TEST_USER_ADDRESS, code=code).status_code == 200
        # A different new identity can't reuse the same single-use code.
        assert _login_with(client, TEST_USER_ADDRESS_2, code=code).status_code == 403

    def test_multi_use_code_admits_several(self, client, require_invites):
        code = _mint(count=1, max_uses=2)[0]
        assert _login_with(client, TEST_USER_ADDRESS, code=code).status_code == 200
        assert _login_with(client, TEST_USER_ADDRESS_2, code=code).status_code == 200
        # Third distinct identity exceeds max_uses.
        third = "pqc_test_user_" + "e" * 100
        assert _login_with(client, third, code=code).status_code == 403

    def test_expired_code_is_rejected(self, client, require_invites):
        code = _mint(count=1, expires_in_days=-1)[0]  # already expired
        assert _login_with(client, TEST_USER_ADDRESS, code=code).status_code == 403

    def test_existing_user_logs_in_without_code(self, client, monkeypatch):
        # Register while invites are NOT required…
        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        # …then turn the gate on. The existing user still logs in with no code.
        monkeypatch.setenv("KRYPTOLOG_REQUIRE_INVITE", "true")
        resp = _login_with(client, TEST_USER_ADDRESS, code=None)
        assert resp.status_code == 200

    def test_username_clash_does_not_consume_code(self, client, require_invites):
        # An existing user occupies the username "Taken".
        occupier = "pqc_test_user_" + "g" * 100
        nonce = get_nonce(client, occupier)
        assert client.post("/auth/login", json={
            "address": occupier, "signature": "fake", "nonce": nonce,
            "encryption_public_key": TEST_ENCRYPTION_KEY,
            "username": "Taken", "invite_code": _mint(count=1)[0],
        }).status_code == 200

        # A brand-new identity requests the same username with a valid code → 409.
        code = _mint(count=1)[0]
        clash = "pqc_test_user_" + "f" * 100
        resp = client.post("/auth/login", json={
            "address": clash, "signature": "fake", "nonce": get_nonce(client, clash),
            "encryption_public_key": TEST_ENCRYPTION_KEY,
            "username": "Taken", "invite_code": code,
        })
        assert resp.status_code == 409
        # The code wasn't burned: another new identity can still redeem it.
        assert _login_with(client, "pqc_test_user_" + "h" * 100, code=code).status_code == 200
