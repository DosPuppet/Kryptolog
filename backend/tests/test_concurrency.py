"""Concurrency tests for the single-use guarantees (KRY-003, KRY-004).

These run real threads against real Postgres. A SELECT-then-DELETE
implementation lets several callers observe the same live row before any
delete lands; the assertion here is the one that actually matters — *exactly
one* caller may succeed, not merely "at least one".

They are inherently probabilistic: a passing run does not prove the absence of
a race, but the pre-fix code fails these reliably (verified by reverting).
"""

import threading
from datetime import UTC

import pytest
from conftest import (
    TEST_ENCRYPTION_KEY,
    TEST_ORIGIN,
    TEST_USER_ADDRESS,
    TestingSessionLocal,
    auth_header,
    do_login,
    server_deployment,
)
from fastapi.testclient import TestClient

import models
from main import app

CONCURRENCY = 24
BLOB = '{"salt":"00","iv":"11","data":"deadbeef"}'


def _run_concurrently(fn, count=CONCURRENCY):
    """Fire `count` threads at `fn`, released together to maximise overlap."""
    results = [None] * count
    start = threading.Barrier(count)

    def worker(i):
        client = TestClient(app)
        try:
            start.wait(timeout=10)
            results[i] = fn(client, i)
        except Exception as exc:  # record, don't kill the thread
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return results


@pytest.fixture(autouse=True)
def _no_rate_limits():
    """These tests deliberately exceed the per-minute limits; the limiter is
    not what is under test here."""
    from dependencies import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


class TestTransferClaimIsSingleUse:
    """KRY-003: concurrent claims must not both receive the ciphertext."""

    def test_concurrent_claims_yield_exactly_one_success(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        tid = client.post(
            "/transfers", json={"ciphertext": BLOB}, headers=auth_header(token)
        ).json()["id"]

        results = _run_concurrently(lambda c, i: c.get(f"/transfers/{tid}"))

        codes = [r.status_code for r in results if hasattr(r, "status_code")]
        successes = [c for c in codes if c == 200]
        assert len(successes) == 1, (
            f"transfer claimed {len(successes)} times — single-use broken (codes: {sorted(codes)})"
        )
        assert all(c in (200, 404) for c in codes), sorted(codes)

        # And the row is gone.
        db = TestingSessionLocal()
        try:
            assert db.query(models.KeyTransfer).filter(models.KeyTransfer.id == tid).first() is None
        finally:
            db.close()

    def test_only_one_body_carries_the_ciphertext(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        tid = client.post(
            "/transfers", json={"ciphertext": BLOB}, headers=auth_header(token)
        ).json()["id"]

        results = _run_concurrently(lambda c, i: c.get(f"/transfers/{tid}"))
        bodies = [
            r.json().get("ciphertext")
            for r in results
            if hasattr(r, "status_code") and r.status_code == 200
        ]
        assert bodies == [BLOB], f"ciphertext handed out {len(bodies)} times"


class TestNonceIsSingleUse:
    """KRY-004: one nonce must mint at most one token."""

    def test_concurrent_logins_on_one_nonce_yield_exactly_one_token(self, client):
        # Register first so the concurrent logins take the existing-user path.
        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")

        nonce = client.get(f"/auth/nonce/{TEST_USER_ADDRESS}").json()["nonce"]
        body = {
            "address": TEST_USER_ADDRESS,
            "signature": "fake_signature_for_testing",
            "nonce": nonce,
            "origin": TEST_ORIGIN,
            "deployment": server_deployment(),
        }

        results = _run_concurrently(lambda c, i: c.post("/auth/login", json=body))

        codes = [r.status_code for r in results if hasattr(r, "status_code")]
        successes = [c for c in codes if c == 200]
        assert len(successes) == 1, (
            f"nonce accepted {len(successes)} times — replay window open (codes: {sorted(codes)})"
        )

    def test_nonce_is_consumed_even_when_signature_is_invalid(self, client):
        """A rejected attempt must still burn the nonce, or a failed guess
        leaves a replayable challenge sitting there."""
        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        nonce = client.get(f"/auth/nonce/{TEST_USER_ADDRESS}").json()["nonce"]

        from unittest.mock import patch

        with patch("auth.verify_signature", return_value=False):
            bad = client.post(
                "/auth/login",
                json={
                    "address": TEST_USER_ADDRESS,
                    "signature": "wrong",
                    "nonce": nonce,
                    "origin": TEST_ORIGIN,
                    "deployment": server_deployment(),
                },
            )
        assert bad.status_code == 401

        # Same nonce, now with a valid signature: must be refused.
        retry = client.post(
            "/auth/login",
            json={
                "address": TEST_USER_ADDRESS,
                "signature": "fake_signature_for_testing",
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
            },
        )
        assert retry.status_code == 400, retry.text

    def test_expired_nonce_is_refused(self, client, db_session):
        from datetime import datetime, timedelta

        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        nonce = client.get(f"/auth/nonce/{TEST_USER_ADDRESS}").json()["nonce"]

        row = (
            db_session.query(models.Nonce)
            .filter(models.Nonce.address == TEST_USER_ADDRESS.lower())
            .first()
        )
        row.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)
        db_session.commit()

        resp = client.post(
            "/auth/login",
            json={
                "address": TEST_USER_ADDRESS,
                "signature": "fake_signature_for_testing",
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
            },
        )
        assert resp.status_code == 400


class TestOneGrantPerGrantee:
    """Audit 2026-09-23 F-1: twelve concurrent shares of one secret to one
    person left two grants, and revoking one left the other serving the key."""

    def test_concurrent_shares_leave_one_grant_and_one_revoke_ends_access(
        self, client, user1, user2, db_session
    ):
        owner_token, _ = user1
        bob_token, bob = user2
        secret_id = client.post(
            "/secrets",
            json={
                "name": "s",
                "type": "standard",
                "encrypted_data": "YWI=",
                "encrypted_key": "YWI=",
            },
            headers=auth_header(owner_token),
        ).json()["id"]

        def share(c, i):
            return c.post(
                "/secrets/share",
                json={
                    "secret_id": secret_id,
                    "grantee_address": bob["address"],
                    "encrypted_key": f"k{i:02d}",
                },
                headers=auth_header(owner_token),
            ).status_code

        assert set(_run_concurrently(share, 12)) == {200}
        grants = (
            db_session.query(models.AccessGrant)
            .filter_by(secret_id=secret_id, grantee_address=bob["address"])
            .all()
        )
        assert len(grants) == 1

        assert (
            client.delete(
                f"/secrets/share/{grants[0].id}", headers=auth_header(owner_token)
            ).status_code
            == 200
        )
        assert (
            client.get(f"/secrets/{secret_id}", headers=auth_header(bob_token)).status_code == 404
        )
