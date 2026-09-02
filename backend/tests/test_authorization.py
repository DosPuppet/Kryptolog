"""Authorization regression tests (KRY-001) and the push-subscription IDOR.

The audit's headline finding: an AccessGrant that had passed its expires_at
still unlocked the file-chunk endpoints, because only the *listing* endpoints
filtered on expiry.
"""
from datetime import datetime, timedelta, timezone

import models
from conftest import (
    TEST_USER_ADDRESS, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY,
    do_login, auth_header,
)


def _naive_utc(dt):
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _make_shared_secret_with_chunk(client, owner_token, grantee_address, expires_in=None):
    """Owner creates a secret with one chunk and shares it with grantee."""
    secret = client.post(
        "/secrets",
        json={
            "name": "shared",
            "type": "note",
            "encrypted_data": "deadbeef",
            "encrypted_key": "aabbcc",
        },
        headers=auth_header(owner_token),
    ).json()

    client.post(
        "/secrets/chunks",
        json={
            "secret_id": secret["id"],
            "chunk_index": 0,
            "iv": "00" * 12,
            "encrypted_data": "abcdef",
        },
        headers=auth_header(owner_token),
    )

    body = {
        "secret_id": secret["id"],
        "grantee_address": grantee_address,
        "encrypted_key": "ddeeff",
    }
    if expires_in is not None:
        body["expires_in"] = expires_in
    resp = client.post("/secrets/share", json=body, headers=auth_header(owner_token))
    assert resp.status_code == 200, resp.text
    return secret["id"], resp.json()["id"]


def _expire_grant(db_session, grant_id):
    grant = db_session.query(models.AccessGrant).filter(
        models.AccessGrant.id == grant_id
    ).first()
    grant.expires_at = _naive_utc(datetime.now(timezone.utc)) - timedelta(minutes=1)
    db_session.commit()


class TestExpiredGrantBlocksFileAccess:
    """KRY-001: the exact bypass the audit described."""

    def test_expiry_flips_chunk_access_from_allowed_to_refused(self, client, db_session):
        """Both sides of the transition, on one grant.

        Previously asserted against the bulk `GET /secrets/{id}/chunks`, removed
        as audit H-2; the single-chunk endpoint enforces the same rule through
        the same `_check_secret_access` path.
        """
        owner, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        bob, bob_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Bob")
        secret_id, grant_id = _make_shared_secret_with_chunk(
            client, owner, bob_user["address"], expires_in=60
        )

        # Live grant: Bob can read.
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(bob)
        ).status_code == 200

        _expire_grant(db_session, grant_id)

        # Expired grant: Bob must be refused.
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(bob)
        ).status_code == 403

    def test_expired_grant_cannot_download_single_chunk(self, client, db_session):
        owner, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        bob, bob_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Bob")
        secret_id, grant_id = _make_shared_secret_with_chunk(
            client, owner, bob_user["address"], expires_in=60
        )
        _expire_grant(db_session, grant_id)

        # The audit's scenario: skip the UI, hit the chunk endpoint directly.
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(bob)
        ).status_code == 403

    def test_revoked_grant_cannot_download_chunk(self, client):
        owner, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        bob, bob_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Bob")
        secret_id, grant_id = _make_shared_secret_with_chunk(
            client, owner, bob_user["address"]
        )
        assert client.delete(
            f"/secrets/share/{grant_id}", headers=auth_header(owner)
        ).status_code == 200
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(bob)
        ).status_code == 403

    def test_grant_without_expiry_still_works(self, client):
        """NULL expires_at means 'no expiry' — must not be caught by the fix."""
        owner, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        bob, bob_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Bob")
        secret_id, _ = _make_shared_secret_with_chunk(client, owner, bob_user["address"])
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(bob)
        ).status_code == 200

    def test_owner_access_is_unaffected_by_grant_expiry(self, client, db_session):
        owner, owner_user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        bob, bob_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Bob")
        secret_id, grant_id = _make_shared_secret_with_chunk(
            client, owner, bob_user["address"], expires_in=60
        )
        _expire_grant(db_session, grant_id)
        # The owner's own access never depended on a grant.
        assert client.get(
            f"/secrets/{secret_id}/chunks/0", headers=auth_header(owner)
        ).status_code == 200

    def test_unrelated_user_is_refused(self, client):
        owner, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Owner")
        stranger, _ = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Stranger")
        secret = client.post(
            "/secrets",
            json={"name": "s", "type": "note", "encrypted_data": "de", "encrypted_key": "ad"},
            headers=auth_header(owner),
        ).json()
        assert client.get(
            f"/secrets/{secret['id']}/chunks/0", headers=auth_header(stranger)
        ).status_code == 403


class TestPushSubscriptionOwnership:
    """Not in the audit: /notifications/subscribe matched on endpoint alone,
    so any authenticated user could seize another user's subscription row."""

    def test_cannot_hijack_another_users_subscription(self, client, db_session):
        alice, alice_user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        mallory, mallory_user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "Mallory")

        endpoint = "https://fcm.googleapis.com/fcm/send/alice-device"
        sub = models.PushSubscription(
            user_address=alice_user["address"],
            endpoint=endpoint,
            p256dh="alice-key",
            auth="alice-auth",
        )
        db_session.add(sub)
        db_session.commit()
        original_id = sub.id

        # Mallory claims Alice's endpoint.
        resp = client.post(
            "/notifications/subscribe",
            json={"endpoint": endpoint, "p256dh": "m", "auth": "m"},
            headers=auth_header(mallory),
        )
        assert resp.status_code == 200, resp.text

        # Alice's original row must be gone rather than silently reassigned,
        # and Mallory must not have inherited Alice's row id.
        db_session.expire_all()
        alice_rows = db_session.query(models.PushSubscription).filter(
            models.PushSubscription.user_address == alice_user["address"]
        ).all()
        assert alice_rows == []

        mallory_rows = db_session.query(models.PushSubscription).filter(
            models.PushSubscription.user_address == mallory_user["address"]
        ).all()
        assert len(mallory_rows) == 1
        assert mallory_rows[0].id != original_id

    def test_resubscribing_own_endpoint_updates_in_place(self, client, db_session):
        alice, alice_user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        endpoint = "https://fcm.googleapis.com/fcm/send/alice-device"

        first = client.post(
            "/notifications/subscribe",
            json={"endpoint": endpoint, "p256dh": "k1", "auth": "a1"},
            headers=auth_header(alice),
        ).json()
        second = client.post(
            "/notifications/subscribe",
            json={"endpoint": endpoint, "p256dh": "k2", "auth": "a2"},
            headers=auth_header(alice),
        ).json()

        assert first["id"] == second["id"]
        assert second["p256dh"] == "k2"

    def test_ssrf_endpoint_is_rejected_at_subscribe(self, client):
        alice, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Alice")
        for endpoint in [
            "https://127.0.0.1/push",
            "https://169.254.169.254/latest/meta-data/",
            "http://fcm.googleapis.com/fcm/send/x",
        ]:
            resp = client.post(
                "/notifications/subscribe",
                json={"endpoint": endpoint, "p256dh": "k", "auth": "a"},
                headers=auth_header(alice),
            )
            assert resp.status_code == 400, f"{endpoint} -> {resp.status_code}"
