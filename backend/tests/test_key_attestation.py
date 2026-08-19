"""Encryption-key attestation (audit M-1).

At login a client may send a self-signature by its identity key over its own
ML-KEM key. The server verifies it (never stores a bad one) and serves it back
to peers, who verify it client-side before encrypting to that key. These tests
cover storage, rejection, backfill, key-change replacement, and one real
ML-DSA-44 round-trip through the endpoint (liboqs, no mocks).
"""

import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth as auth_module
from conftest import (
    TEST_USER_ADDRESS,
    TEST_ENCRYPTION_KEY,
    auth_header,
    do_login,
    get_nonce,
)

FAKE_ATTESTATION = "aa" * 100


def login_with_attestation(client, address, enc_key, attestation, username=None):
    nonce = get_nonce(client, address)
    body = {
        "address": address,
        "signature": "fake_signature_for_testing",
        "nonce": nonce,
        "encryption_public_key": enc_key,
        "encryption_key_attestation": attestation,
    }
    if username:
        body["username"] = username
    return client.post("/auth/login", json=body)


class TestAttestationStorage:
    def test_stored_on_first_login_and_served_to_peers(self, client, user2):
        resp = login_with_attestation(
            client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, FAKE_ATTESTATION, "AttUser"
        )
        assert resp.status_code == 200
        assert resp.json()["user"]["encryption_key_attestation"] == FAKE_ATTESTATION

        # A peer fetching this user receives the attestation for verification.
        token2, _ = user2
        r = client.post("/users/resolve", json={"address": TEST_USER_ADDRESS},
                        headers=auth_header(token2))
        assert r.status_code == 200
        assert r.json()["encryption_key_attestation"] == FAKE_ATTESTATION

    def test_login_without_attestation_still_works(self, client):
        token, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "NoAtt")
        assert user["encryption_key_attestation"] is None

    def test_backfill_on_existing_account(self, client):
        # Account created without an attestation…
        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "Backfill")
        # …starts sending one later (same key): it gets stored.
        resp = login_with_attestation(
            client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, FAKE_ATTESTATION
        )
        assert resp.status_code == 200
        assert resp.json()["user"]["encryption_key_attestation"] == FAKE_ATTESTATION

    def test_key_change_replaces_attestation(self, client):
        login_with_attestation(
            client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, FAKE_ATTESTATION, "KeySwap"
        )
        # New encryption key + new attestation: the old one signed the old key
        # and must never survive the swap.
        new_key = "1a" * 1184
        new_att = "bb" * 100
        resp = login_with_attestation(client, TEST_USER_ADDRESS, new_key, new_att)
        assert resp.status_code == 200
        assert resp.json()["user"]["encryption_key_attestation"] == new_att

    def test_key_change_without_attestation_clears_stale_one(self, client):
        login_with_attestation(
            client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, FAKE_ATTESTATION, "Stale"
        )
        new_key = "2b" * 1184
        nonce = get_nonce(client, TEST_USER_ADDRESS)
        resp = client.post("/auth/login", json={
            "address": TEST_USER_ADDRESS,
            "signature": "fake_signature_for_testing",
            "nonce": nonce,
            "encryption_public_key": new_key,
        })
        assert resp.status_code == 200
        assert resp.json()["user"]["encryption_key_attestation"] is None


class TestAttestationRejection:
    def test_invalid_attestation_rejected(self, client, monkeypatch):
        monkeypatch.setattr("auth.verify_message_signature", lambda *a, **k: False)
        resp = login_with_attestation(
            client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, FAKE_ATTESTATION, "BadAtt"
        )
        assert resp.status_code == 400
        assert "attestation" in resp.json()["detail"].lower()

    def test_attestation_without_encryption_key_rejected(self, client):
        nonce = get_nonce(client, TEST_USER_ADDRESS)
        resp = client.post("/auth/login", json={
            "address": TEST_USER_ADDRESS,
            "signature": "fake_signature_for_testing",
            "nonce": nonce,
            "encryption_key_attestation": FAKE_ATTESTATION,
        })
        assert resp.status_code == 400


class TestRealCrypto:
    def test_real_mldsa_attestation_roundtrip(self, client, monkeypatch):
        """Full path with real ML-DSA-44 (liboqs): a genuine self-attestation is
        accepted and stored; a signature over a DIFFERENT key is rejected."""
        import oqs

        # Restore a real verifier (conftest mocks it for endpoint tests).
        monkeypatch.setattr("auth.verify_message_signature", _real_verify)

        signer = oqs.Signature(auth_module.SIG_ALG)
        address = signer.generate_keypair().hex()
        enc_key = "3c" * 1184

        att_msg = auth_module.encryption_key_attestation_message(enc_key)
        good_att = signer.sign(att_msg.encode("utf-8")).hex()

        resp = login_with_attestation(client, address, enc_key, good_att, "RealAtt")
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["encryption_key_attestation"] == good_att

        # Same signature presented for a different KEM key must fail.
        other_key = "4d" * 1184
        resp = login_with_attestation(client, address, other_key, good_att)
        assert resp.status_code == 400


def _real_verify(address, message, signature):
    """The genuine liboqs verifier, bypassing the conftest mock."""
    import oqs
    try:
        with oqs.Signature(auth_module.SIG_ALG) as verifier:
            return verifier.verify(message.encode("utf-8"),
                                   bytes.fromhex(signature),
                                   bytes.fromhex(address))
    except Exception:
        return False
