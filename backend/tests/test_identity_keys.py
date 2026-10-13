"""An identity's key, stored apart from its address (crypto-core 3.3.0).

Until 4.0.0 the two are the same string, which is exactly why these tests do
not trust that: a verifier handed the ADDRESS would pass every other test in
the suite today and break the day the address becomes a hash. So the routes
that verify a signature are driven here with the stored key overwritten by a
different one, and must hand THAT to the verifier (audit 2026-10-12 K-10).
"""

from unittest.mock import patch

from conftest import (
    TEST_ENCRYPTION_KEY,
    auth_header,
    get_nonce,
    identity_key_of,
    login_body,
    register_identity,
    synthetic_address,
)
from test_account_deletion import _delete, _dm_content, _send_dm
from test_conversations import _erase
from test_multisig import _create_workflow

import models

# A well-formed key that is nobody's address: if a route verifies against the
# address instead of the stored key, the recorder sees the address, not this.
SENTINEL = identity_key_of(synthetic_address("identity-key-sentinel"))


def _store_sentinel(db_session, address):
    db_session.query(models.User).filter_by(address=address).update(
        {"identity_public_key": SENTINEL}
    )
    db_session.commit()


class _Recorder:
    def __init__(self):
        self.keys = []

    def __call__(self, identity_public_key, message, signature):
        self.keys.append(identity_public_key)
        return True


class TestLoginBindsTheKeyToTheAddress:
    def test_a_key_the_address_does_not_name_is_refused_and_nothing_is_stored(
        self, client, db_session
    ):
        """With the verifier stubbed to accept anything: the binding is the
        route's check, not the verifier's."""
        address = synthetic_address("binding-victim")
        body = login_body(address, get_nonce(client, address), TEST_ENCRYPTION_KEY)
        body["identity_public_key"] = identity_key_of(synthetic_address("binding-forger"))
        resp = client.post("/auth/login", json=body)
        assert resp.status_code == 400, resp.text
        assert "not the one the address names" in resp.json()["detail"]
        assert db_session.query(models.User).filter_by(address=address).count() == 0

    def test_a_key_whose_ed25519_half_has_a_torsion_component_is_refused(self, client, db_session):
        """Bound to its address, so the binding passes — the order check is what
        refuses it (crypto-core 4.0.0, security/ed25519_subgroup.py). Such a key
        would let its owner sign approvals OpenSSL accepts and every client
        refuses. The key is the one tests/fixtures/hybrid_interop.json carries."""
        import json
        import pathlib

        from security.crypto_validation import address_of

        fixture = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/hybrid_interop.json"
        key = json.loads(fixture.read_text())["ed25519_edges"]["mixed_order_A_even_k"]["public_key"]
        address = register_identity(key)
        assert address == address_of(key)
        body = login_body(address, get_nonce(client, address), TEST_ENCRYPTION_KEY)
        resp = client.post("/auth/login", json=body)
        assert resp.status_code == 400, resp.text
        assert "malformed" in resp.json()["detail"]
        assert db_session.query(models.User).filter_by(address=address).count() == 0

    def test_a_login_without_a_key_is_malformed(self, client):
        address = synthetic_address("no-key")
        body = login_body(address, get_nonce(client, address))
        del body["identity_public_key"]
        assert client.post("/auth/login", json=body).status_code == 422

    def test_the_login_signature_and_attestation_are_checked_against_the_submitted_key(
        self, client
    ):
        address = synthetic_address("submitted-key")
        seen = []
        with (
            patch(
                "auth.verify_signature", side_effect=lambda key, *a, **k: seen.append(key) or True
            ),
            patch("auth.verify_identity_signature", side_effect=_Recorder()) as att,
        ):
            body = login_body(address, get_nonce(client, address), TEST_ENCRYPTION_KEY)
            assert client.post("/auth/login", json=body).status_code == 200
        assert seen == [identity_key_of(address)]
        assert att.call_args.args[0] == identity_key_of(address)


class TestTheKeyIsServedWithTheUser:
    def test_the_directory_record_carries_it(self, client, user1, user2):
        token, me = user1
        _, bob = user2
        record = client.get(f"/users/{bob['address']}", headers=auth_header(token)).json()
        assert record["identity_public_key"] == identity_key_of(bob["address"])
        assert me["identity_public_key"] == identity_key_of(me["address"])

    def test_it_is_embedded_where_a_message_names_its_sender(self, client, user1, user2):
        token, me = user1
        bob_token, bob = user2
        _send_dm(client, token, bob["address"], _dm_content("s-1"))
        rows = client.post(
            "/messages/history",
            json={"partner_address": me["address"]},
            headers=auth_header(bob_token),
        ).json()
        assert rows and rows[0]["sender"]["identity_public_key"] == identity_key_of(me["address"])

    def test_a_deleted_identity_keeps_it_so_its_messages_still_verify(
        self, client, user1, user2, user3
    ):
        token, me = user1
        token2, leaver = user2
        token3, eraser = user3
        assert _delete(client, token2, leaver["address"], "leave").status_code == 200
        assert _delete(client, token3, eraser["address"], "erase").status_code == 200
        for gone in (leaver, eraser):
            record = client.get(f"/users/{gone['address']}", headers=auth_header(token)).json()
            assert record["deleted"] is True
            assert record["identity_public_key"] == identity_key_of(gone["address"])


class TestEverySignatureIsVerifiedAgainstTheStoredKey:
    def test_account_deletion(self, client, db_session, user1):
        token, me = user1
        _store_sentinel(db_session, me["address"])
        recorder = _Recorder()
        with patch("auth.verify_identity_signature", side_effect=recorder):
            assert _delete(client, token, me["address"], "leave").status_code == 200
        assert recorder.keys == [SENTINEL]

    def test_a_conversation_erase_and_its_redactions(self, client, db_session, user1, user2):
        token, me = user1
        _, bob = user2
        _send_dm(client, token, bob["address"], _dm_content("s-1"))
        _store_sentinel(db_session, me["address"])
        recorder = _Recorder()
        with patch("auth.verify_identity_signature", side_effect=recorder):
            assert _erase(client, token, me["address"], "dm", bob["address"]).status_code == 200
        # The erase approval, then the carrier's redaction.
        assert len(recorder.keys) >= 2
        assert set(recorder.keys) == {SENTINEL}

    def test_a_multisig_approval(self, client, db_session, user1, user2):
        token, _ = user1
        signer_token, signer = user2
        wf = _create_workflow(client, token, [signer["address"]]).json()
        _store_sentinel(db_session, signer["address"])
        recorder = _Recorder()
        with patch("auth.verify_identity_signature", side_effect=recorder):
            resp = client.post(
                f"/multisig/workflow/{wf['id']}/sign",
                json={"signature": "c2ln"},
                headers=auth_header(signer_token),
            )
        assert resp.status_code == 200, resp.text
        assert recorder.keys == [SENTINEL]
