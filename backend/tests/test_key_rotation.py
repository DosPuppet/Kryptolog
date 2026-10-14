"""Replacing an identity's encryption key, and moving what it holds onto the
new one (crypto-core 5.1.0, lot 12f; rules in security/key_rotation.py)."""

import base64
import json
import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from conftest import (
    TEST_ENCRYPTION_KEY,
    TEST_ORIGIN,
    CompositeSigner,
    auth_header,
    do_login,
    get_nonce,
    identity_key_of,
    server_deployment,
    synthetic_address,
    synthetic_encryption_key,
)
from test_account_deletion import DUMMY_SIG, _create_group, _delete, _dm_content, _send_dm
from test_multisig import _create_workflow

import auth
import models
from security.crypto_validation import KEM_ENVELOPE_ALG, encryption_key_id
from utils.clock import utcnow_naive

KEY_B = synthetic_encryption_key("rotation-b")
KEY_C = synthetic_encryption_key("rotation-c")
KID_A = encryption_key_id(TEST_ENCRYPTION_KEY)
KID_B = encryption_key_id(KEY_B)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _wrap(kid: str, *, content: bool = True) -> str:
    """A KEM envelope in the exact current shape, sealed (as far as the server
    can tell) to `kid` — the message-envelope form a grant holds by default,
    or a wrapped session key. The server never opens one, so zeros do."""
    sealed = {"content": bytes(64 + 16)} if content else {"encKey": bytes(48)}
    return json.dumps(
        {
            "v": 5,
            "alg": KEM_ENVELOPE_ALG,
            "kid": kid,
            "kem": base64.b64encode(bytes(97 + 1088)).decode(),
            "iv": base64.b64encode(bytes(12)).decode(),
            **{k: base64.b64encode(v).decode() for k, v in sealed.items()},
        }
    )


def _rotate(client, token, key=KEY_B, *, ts=None, signature=DUMMY_SIG, attestation=DUMMY_SIG):
    return client.post(
        "/account/encryption-key/rotate",
        json={
            "encryption_public_key": key,
            "encryption_key_attestation": attestation,
            "ts": _now_ms() if ts is None else ts,
            "signature": signature,
        },
        headers=auth_header(token),
    )


def _secret(client, token, encrypted_key):
    resp = client.post(
        "/secrets",
        json={
            "name": "n",
            "type": "standard",
            "encrypted_data": "d",
            "encrypted_key": encrypted_key,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _stale(client, token, **params):
    resp = client.get(
        "/account/encryption-key/stale-wraps", params=params, headers=auth_header(token)
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _rewrap(client, token, items):
    return client.put(
        "/account/encryption-key/wraps", json={"items": items}, headers=auth_header(token)
    )


class TestRotate:
    def test_rotates_records_and_serves_the_rotation(self, client, user1, db_session):
        token, user = user1
        resp = _rotate(client, token)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["encryption_public_key"] == KEY_B
        assert body["key_changed_at"] is not None
        [record] = body["encryption_key_rotations"]
        assert (record["old_kid"], record["new_kid"]) == (KID_A, KID_B)
        assert record["alg"] == "HKDFwSHA384_P384_ML-KEM-768_CatKDF"
        row = db_session.query(models.User).filter_by(address=user["address"]).one()
        assert (row.encryption_key_id, row.encryption_key_alg) == (KID_B, record["alg"])
        # The directory serves it to everybody, newest first.
        listed = client.get(f"/users/{user['address']}", headers=auth_header(token)).json()
        assert listed["encryption_key_rotations"] == [record]

    def test_the_signed_body_is_built_from_the_CURRENT_key(self, client, user1):
        """Rule 1: the client never names the old key, so a recorded rotation
        cannot roll a later key back."""
        token, user = user1
        seen = []
        with patch(
            "auth.verify_identity_signature",
            side_effect=lambda key, message, sig: seen.append(message) or True,
        ):
            assert _rotate(client, token, ts=1_000 + _now_ms()).status_code == 200
        rotation_body = seen[-1]
        assert rotation_body == auth.key_rotation_message(
            user["address"], KID_A, KID_B, int(rotation_body.rsplit("ts=", 1)[1])
        )

    def test_chains_newest_first(self, client, user1):
        token, _ = user1
        assert _rotate(client, token, KEY_B).status_code == 200
        resp = _rotate(client, token, KEY_C)
        assert resp.status_code == 200, resp.text
        records = resp.json()["encryption_key_rotations"]
        assert [(r["old_kid"], r["new_kid"]) for r in records] == [
            (KID_B, encryption_key_id(KEY_C)),
            (KID_A, KID_B),
        ]

    @pytest.mark.parametrize(
        "case, kwargs, status",
        [
            ("the same key", {"key": TEST_ENCRYPTION_KEY}, 400),
            ("not a key", {"key": "ab" * 1281}, 400),
            ("a clock an hour off", {"ts": 3_600_000}, 400),
        ],
    )
    def test_refusals(self, client, user1, db_session, case, kwargs, status):
        token, user = user1
        if "ts" in kwargs:
            kwargs = {"ts": _now_ms() - kwargs["ts"]}
        assert _rotate(client, token, **kwargs).status_code == status, case
        row = db_session.query(models.User).filter_by(address=user["address"]).one()
        assert row.encryption_public_key == TEST_ENCRYPTION_KEY
        assert db_session.query(models.EncryptionKeyRotation).count() == 0

    def test_a_bad_attestation_and_a_bad_signature_are_refused(self, client, user1, db_session):
        token, _ = user1
        with patch("auth.verify_identity_signature", return_value=False):
            assert _rotate(client, token).status_code == 400  # the attestation, first
        rotation = "context=key-rotation"
        with patch(
            "auth.verify_identity_signature",
            side_effect=lambda key, message, sig: rotation not in message,
        ):
            assert _rotate(client, token).status_code == 401
        assert db_session.query(models.EncryptionKeyRotation).count() == 0

    def test_an_identity_without_a_key_has_nothing_to_rotate(self, client):
        token, _ = do_login(client, synthetic_address("keyless"))
        assert _rotate(client, token).status_code == 409


class TestContactsAreTold:
    def test_dm_partners_and_group_co_members_get_KEY_ROTATED_and_nobody_else(
        self, client, user1, user2, user3
    ):
        """Their clients hold the old key in a cached record and in the session
        keys they keep wrapping to it; told, they refetch and stop on the
        change (K-05) instead of sealing to a key its owner rotated away from."""
        token1, u1 = user1
        token2, u2 = user2
        _, u3 = user3
        stranger, _ = do_login(client, synthetic_address("not-a-contact"), TEST_ENCRYPTION_KEY)
        _send_dm(client, token2, u1["address"], _dm_content("sid-1"))  # u2 wrote to u1
        _create_group(client, token1, [u3["address"]])
        sent = []
        with patch(
            "routers.encryption_keys.manager.send_many",
            side_effect=lambda frames: sent.extend(frames),
        ):
            assert _rotate(client, token1).status_code == 200
        assert {addr for _, addr in sent} == {u2["address"], u3["address"]}
        assert all(frame == {"type": "KEY_ROTATED", "address": u1["address"]} for frame, _ in sent)


class TestRewrap:
    def test_lists_only_wraps_not_sealed_to_the_current_key_and_takes_them_back(
        self, client, user1
    ):
        token, _ = user1
        secret_id = _secret(client, token, _wrap(KID_A))
        assert _stale(client, token) == []  # sealed to the current key
        assert _rotate(client, token).status_code == 200
        [stale] = _stale(client, token)
        assert stale["kind"] == "grant"
        # Either shape is accepted, as long as it names the current key.
        for shape in (_wrap(KID_B, content=False), _wrap(KID_B)):
            resp = _rewrap(client, token, [{**stale, "encrypted_key": shape}])
            assert resp.status_code == 200, resp.text
        assert _stale(client, token) == []
        detail = client.get(f"/secrets/{secret_id}", headers=auth_header(token)).json()
        assert json.loads(detail["encrypted_key"])["kid"] == KID_B

    def test_a_wrap_must_name_the_current_key_and_have_the_shape(self, client, user1):
        token, _ = user1
        _secret(client, token, _wrap(KID_A))
        assert _rotate(client, token).status_code == 200
        [stale] = _stale(client, token)
        both = {
            **json.loads(_wrap(KID_B)),
            "encKey": json.loads(_wrap(KID_B, content=False))["encKey"],
        }
        short_key = {
            **json.loads(_wrap(KID_B, content=False)),
            "encKey": base64.b64encode(bytes(47)).decode(),
        }
        for bad in (
            _wrap(KID_A),
            _wrap(KID_B).replace('"v": 5', '"v": 4'),
            json.dumps({**json.loads(_wrap(KID_B)), "extra": "x"}),
            json.dumps(both),  # two sealed fields: neither shape
            json.dumps(short_key),  # a session key is exactly 32 bytes plus its tag
            "not json",
        ):
            resp = _rewrap(client, token, [{**stale, "encrypted_key": bad}])
            assert resp.status_code in (400, 422), bad[:40]
        assert len(_stale(client, token)) == 1

    def test_someone_elses_wrap_is_a_404_and_refuses_the_whole_batch(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        _secret(client, token1, _wrap(KID_A))
        theirs = _secret(client, token2, _wrap(KID_A))
        assert _rotate(client, token1).status_code == 200
        [mine] = _stale(client, token1)
        grant_2 = client.get(f"/secrets/{theirs}/access", headers=auth_header(token2)).json()[0]
        resp = _rewrap(
            client,
            token1,
            [
                {**mine, "encrypted_key": _wrap(KID_B)},
                {"kind": "grant", "id": grant_2["id"], "encrypted_key": _wrap(KID_B)},
            ],
        )
        assert resp.status_code == 404
        assert len(_stale(client, token1)) == 1  # all or nothing

    def test_an_unopenable_wrap_can_be_stepped_past(self, client, user1):
        """A wrap the client cannot open (sealed to a key it destroyed) stays
        listed; `offset` is how the client walks past it to the next."""
        token, _ = user1
        _secret(client, token, _wrap(KID_A))
        _secret(client, token, _wrap(KID_A))
        assert _rotate(client, token).status_code == 200
        everything = _stale(client, token)
        assert len(everything) == 2
        assert _stale(client, token, limit=1) == everything[:1]
        assert _stale(client, token, limit=1, offset=1) == everything[1:]

    def test_an_expired_grant_is_neither_listed_nor_rewrapped(
        self, client, user1, user2, db_session
    ):
        """Re-wrapping must not revive a time-bombed share: past its expiry the
        grantee can no longer read the grant, so it is not theirs to reseal."""
        owner_token, _ = user1
        token2, u2 = user2
        secret_id = _secret(client, owner_token, _wrap(KID_A))
        resp = client.post(
            "/secrets/share",
            json={
                "secret_id": secret_id,
                "grantee_address": u2["address"],
                "encrypted_key": _wrap(KID_A),
                "expires_in": 60,
            },
            headers=auth_header(owner_token),
        )
        assert resp.status_code == 200, resp.text
        assert _rotate(client, token2, KEY_C).status_code == 200
        [live] = _stale(client, token2)
        grant = db_session.get(models.AccessGrant, live["id"])
        grant.expires_at = utcnow_naive() - timedelta(minutes=1)
        db_session.commit()
        assert _stale(client, token2) == []
        resealed = {**live, "encrypted_key": _wrap(encryption_key_id(KEY_C))}
        assert _rewrap(client, token2, [resealed]).status_code == 404

    def test_a_recipient_key_is_not_handed_out_before_release(self, client, user1, user2):
        """The threshold is the point of a workflow: a recipient's wrap is held
        until it completes, and re-wrapping must not become a way around it."""
        token1, _ = user1
        token2, u2 = user2
        token3, u3 = do_login(
            client, synthetic_address("rotation-recipient"), TEST_ENCRYPTION_KEY, "Recipient"
        )
        wf = _create_workflow(client, token1, [u2["address"]], [u3["address"]]).json()
        assert _rotate(client, token3, synthetic_encryption_key("recipient-b")).status_code == 200
        assert _stale(client, token3) == []
        # The signer's own wrap, by contrast, is theirs to read today.
        assert _rotate(client, token2, synthetic_encryption_key("signer-b")).status_code == 200
        assert [s["kind"] for s in _stale(client, token2)] == ["signer"]
        assert wf["status"] == "pending"
        # Released — by a signer whose client still had the recipient's OLD
        # key — the recipient's wrap is theirs, and listed for re-wrapping.
        resp = client.post(
            f"/multisig/workflow/{wf['id']}/sign",
            json={"signature": "sig_final", "recipient_keys": {u3["address"]: _wrap(KID_A)}},
            headers=auth_header(token2),
        )
        assert resp.json()["status"] == "completed", resp.text
        assert [s["kind"] for s in _stale(client, token3)] == ["recipient"]


class TestDeletion:
    def test_an_erase_removes_the_records_and_a_leave_keeps_them(
        self, client, user1, user2, db_session
    ):
        token1, u1 = user1
        token2, u2 = user2
        assert _rotate(client, token1).status_code == 200
        assert _rotate(client, token2, KEY_C).status_code == 200
        assert _delete(client, token1, u1["address"], "leave").status_code == 200
        assert _delete(client, token2, u2["address"], "erase").status_code == 200
        by = models.EncryptionKeyRotation.user_address
        assert db_session.query(models.EncryptionKeyRotation).filter(by == u1["address"]).count()
        assert not (
            db_session.query(models.EncryptionKeyRotation).filter(by == u2["address"]).count()
        )


class TestRealSignatures:
    @staticmethod
    def _sign(message, signer):
        return base64.b64encode(signer.sign(message.encode("utf-8"))).decode()

    def _login(self, client, signer):
        nonce = get_nonce(client, signer.address)
        resp = client.post(
            "/auth/login",
            json={
                "address": signer.address,
                "identity_public_key": identity_key_of(signer.address),
                "signature": self._sign(
                    auth._login_message(
                        nonce,
                        encryption_public_key=TEST_ENCRYPTION_KEY,
                        origin=TEST_ORIGIN,
                        deployment=server_deployment(),
                    ),
                    signer,
                ),
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
                "encryption_public_key": TEST_ENCRYPTION_KEY,
                "encryption_key_attestation": self._sign(
                    auth.encryption_key_attestation_message(signer.address, TEST_ENCRYPTION_KEY),
                    signer,
                ),
            },
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]

    @pytest.mark.real_signatures
    def test_a_genuine_rotation_is_accepted_and_one_for_another_old_key_is_not(self, client):
        signer = CompositeSigner()
        token = self._login(client, signer)
        ts = _now_ms()
        attestation = self._sign(
            auth.encryption_key_attestation_message(signer.address, KEY_B), signer
        )
        # Signed as if from a key the server does not hold: refused.
        forged_old = encryption_key_id(KEY_C)
        bad = self._sign(auth.key_rotation_message(signer.address, forged_old, KID_B, ts), signer)
        resp = _rotate(client, token, ts=ts, signature=bad, attestation=attestation)
        assert resp.status_code == 401, resp.text
        good = self._sign(auth.key_rotation_message(signer.address, KID_A, KID_B, ts), signer)
        resp = _rotate(client, token, ts=ts, signature=good, attestation=attestation)
        assert resp.status_code == 200, resp.text
        assert resp.json()["encryption_key_rotations"][0]["signature"] == good
