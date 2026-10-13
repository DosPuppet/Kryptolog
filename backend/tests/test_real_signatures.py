"""The signature-gated paths, with real ML-DSA-44 signatures end to end.

Everywhere else conftest stubs the verifier, so a test proves the route's logic
and not that the bytes it verifies are the bytes a client signs (audit
2026-10-12: "signature verification stubbed in most backend tests; only a
handful exercise a real ML-DSA login"). Login and account deletion already have
real-signature tests; these cover the other two places a signature is the
authorization: approving a multisig workflow, and erasing one's messages in a
conversation — including the redaction signatures that erase carries.
"""

import base64
import hashlib
import json

import pytest
from conftest import (
    TEST_ENCRYPTION_KEY,
    TEST_ORIGIN,
    MLDSA44Signer,
    auth_header,
    get_nonce,
    identity_key_of,
    server_deployment,
)

import auth

pytestmark = pytest.mark.real_signatures


def _sign(message: str, signer) -> str:
    return base64.b64encode(signer.sign(message.encode("utf-8"))).decode()


class Identity:
    """A real ML-DSA-44 key pair, logged in for real."""

    def __init__(self, client, username):
        self.signer = MLDSA44Signer()
        self.address = self.signer.address
        nonce = get_nonce(client, self.address)
        resp = client.post(
            "/auth/login",
            json={
                "address": self.address,
                "identity_public_key": identity_key_of(self.address),
                "signature": self.sign(
                    auth._login_message(
                        nonce,
                        encryption_public_key=TEST_ENCRYPTION_KEY,
                        origin=TEST_ORIGIN,
                        deployment=server_deployment(),
                    )
                ),
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
                "encryption_public_key": TEST_ENCRYPTION_KEY,
                "encryption_key_attestation": self.sign(
                    auth.encryption_key_attestation_message(TEST_ENCRYPTION_KEY)
                ),
                "username": username,
            },
        )
        assert resp.status_code == 200, resp.text
        self.token = resp.json()["access_token"]

    def sign(self, message: str) -> str:
        return _sign(message, self.signer)

    @property
    def headers(self):
        return auth_header(self.token)


@pytest.fixture
def people(client):
    return [Identity(client, "RealAlice"), Identity(client, "RealBob")]


class TestMultisigApproval:
    def _workflow(self, client, owner, signer):
        resp = client.post(
            "/multisig/workflow",
            json={
                "name": "Real",
                "secret_data": {
                    "name": "S",
                    "type": "standard",
                    "encrypted_data": "Y2lwaGVydGV4dA==",
                    "encrypted_key": "a2V5",
                },
                "signers": [signer.address],
                "recipients": [],
                "signer_keys": {signer.address: "a2V5"},
                "recipient_keys": {},
                "threshold": 1,
            },
            headers=owner.headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _approval(self, wf, ciphertext="Y2lwaGVydGV4dA=="):
        digest = hashlib.sha256(ciphertext.encode("utf-8")).hexdigest()
        return auth.multisig_approval_message(wf["id"], wf["secret_id"], digest)

    def test_a_genuine_approval_completes_the_workflow(self, client, people):
        alice, bob = people
        wf = self._workflow(client, alice, bob)
        resp = client.post(
            f"/multisig/workflow/{wf['id']}/sign",
            json={"signature": bob.sign(self._approval(wf))},
            headers=bob.headers,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "completed"

    @pytest.mark.parametrize("forgery", ["other key", "other ciphertext"])
    def test_an_approval_of_anything_else_is_refused(self, client, people, forgery):
        alice, bob = people
        wf = self._workflow(client, alice, bob)
        signature = (
            alice.sign(self._approval(wf))  # the owner signing for the signer
            if forgery == "other key"
            else bob.sign(self._approval(wf, ciphertext="c29tZXRoaW5nIGVsc2U="))
        )
        resp = client.post(
            f"/multisig/workflow/{wf['id']}/sign",
            json={"signature": signature},
            headers=bob.headers,
        )
        assert resp.status_code in (400, 401, 403), resp.text
        detail = client.get(f"/multisig/workflow/{wf['id']}", headers=alice.headers).json()
        assert detail["status"] == "pending"


class TestConversationErase:
    def _carrier(self, client, sender, recipient):
        payload = {
            "v": 1,
            "sid": "real-sid-1",
            "ts": 1760264400000,
            "seq": 0,
            "ct": "Y3Q=",
            "sig": base64.b64encode(b"\x00" * 2420).decode(),
            "keys": {
                "recip": {
                    "v": 3,
                    "alg": "MLKEM768-HKDF-A256GCM",
                    "kem": "a",
                    "iv": "b",
                    "encKey": "c",
                },
                "sender": {
                    "v": 3,
                    "alg": "MLKEM768-HKDF-A256GCM",
                    "kem": "d",
                    "iv": "e",
                    "encKey": "f",
                },
            },
        }
        resp = client.post(
            "/messages",
            json={"recipient_address": recipient.address, "content": json.dumps(payload)},
            headers=sender.headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["id"]

    def _round(self, client, who, partner, *, redaction_signer=None, erase_for=None):
        rows = client.get(
            f"/conversations/dm/{partner.address}/redactable-messages", headers=who.headers
        ).json()
        redactions = [
            {
                "key": row["key"],
                "signature": (redaction_signer or who).sign(
                    auth.message_signing_body(
                        from_=who.address,
                        conv=row["conv"],
                        gid=row["gid"],
                        sid=row["sid"],
                        ts=row["ts"],
                        seq=row["seq"],
                        ct=None,
                        keys=row["keys"],
                    )
                ),
            }
            for row in rows
        ]
        nonce = get_nonce(client, who.address)
        body = auth.conversation_erase_message(
            nonce,
            "dm",
            (erase_for or partner).address,
            [r["key"] for r in redactions],
            origin=TEST_ORIGIN,
            deployment=server_deployment(),
        )
        return client.post(
            f"/conversations/dm/{partner.address}/erase",
            json={
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
                "signature": who.sign(body),
                "redactions": redactions,
            },
            headers=who.headers,
        )

    def test_genuine_signatures_erase_and_redact(self, client, db_session, people):
        import models

        alice, bob = people
        message_id = self._carrier(client, alice, bob)
        resp = self._round(client, alice, bob)
        assert resp.status_code == 200, resp.text
        assert resp.json()["redacted"] == 1
        db_session.expire_all()
        stored = json.loads(db_session.get(models.Message, message_id).content)
        assert stored["ct"] is None
        # The stored redaction verifies against the author's key, as a reader's
        # client will check it.
        body = auth.message_signing_body(
            from_=alice.address,
            conv=bob.address,
            gid="",
            sid=stored["sid"],
            ts=stored["ts"],
            seq=stored["seq"],
            ct=None,
            keys=stored["keys"],
        )
        assert auth.verify_identity_signature(alice.address, body, stored["sig"])

    def test_an_approval_for_another_conversation_is_refused(self, client, people):
        alice, bob = people
        self._carrier(client, alice, bob)
        carol = Identity(client, "RealCarol")
        resp = self._round(client, alice, bob, erase_for=carol)
        assert resp.status_code == 401, resp.text

    def test_a_redaction_signed_by_someone_else_is_refused(self, client, people):
        alice, bob = people
        self._carrier(client, alice, bob)
        resp = self._round(client, alice, bob, redaction_signer=bob)
        assert resp.status_code == 400, resp.text
