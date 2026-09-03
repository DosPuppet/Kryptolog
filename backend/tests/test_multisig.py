"""Tests for /multisig endpoints — workflow creation, signing, completion."""

import pytest

from conftest import auth_header, do_login, synthetic_address, TEST_ENCRYPTION_KEY


def _create_workflow(client, token, signer_addresses, recipient_addresses=None, threshold=None):
    if recipient_addresses is None:
        recipient_addresses = []
    if threshold is None:
        # Default to N-of-N so existing assertions stay valid.
        threshold = len(signer_addresses)
    signer_keys = {addr: f"enc_key_for_{addr}" for addr in signer_addresses}
    recipient_keys = {addr: f"enc_key_for_{addr}" for addr in recipient_addresses}
    return client.post("/multisig/workflow", json={
        "name": "TestWorkflow",
        "secret_data": {
            "name": "MultisigSecret", "type": "standard",
            "encrypted_data": "encrypted_payload", "encrypted_key": "owner_enc_key",
        },
        "signers": signer_addresses,
        "recipients": recipient_addresses,
        "signer_keys": signer_keys,
        "recipient_keys": recipient_keys,
        "threshold": threshold,
    }, headers=auth_header(token))


class TestCreateWorkflow:
    def test_create_workflow_success(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = _create_workflow(client, token1, [u2["address"]])
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "TestWorkflow"
        assert data["status"] == "pending"
        assert len(data["signers"]) == 1
        assert data["signers"][0]["user_address"] == u2["address"]
        assert data["signers"][0]["has_signed"] is False

    def test_create_workflow_unauthenticated(self, client):
        resp = client.post("/multisig/workflow", json={
            "name": "x",
            "secret_data": {
                "name": "s", "type": "standard",
                "encrypted_data": "d", "encrypted_key": "k",
            },
            "signers": [], "recipients": [],
            "signer_keys": {}, "recipient_keys": {},
        })
        assert resp.status_code == 401


class TestListWorkflows:
    def test_owner_sees_own_workflows(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        _create_workflow(client, token1, [u2["address"]])
        resp = client.get("/multisig/workflows", headers=auth_header(token1))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_signer_sees_workflow(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        _create_workflow(client, token1, [u2["address"]])
        resp = client.get("/multisig/workflows", headers=auth_header(token2))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1


class TestGetWorkflow:
    def test_get_workflow_as_owner(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        create_resp = _create_workflow(client, token1, [u2["address"]])
        wf_id = create_resp.json()["id"]
        resp = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["id"] == wf_id

    def test_get_nonexistent_workflow(self, client, user1):
        token, _ = user1
        resp = client.get("/multisig/workflow/99999", headers=auth_header(token))
        assert resp.status_code == 404


class TestSignWorkflow:
    def test_signer_can_sign(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        create_resp = _create_workflow(client, token1, [u2["address"]])
        wf_id = create_resp.json()["id"]
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "signer_dilithium_signature_data",
        }, headers=auth_header(token2))
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"

    def test_non_signer_cannot_sign(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        create_resp = _create_workflow(client, token1, [u2["address"]])
        wf_id = create_resp.json()["id"]
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig",
        }, headers=auth_header(token1))
        assert resp.status_code == 403

    def test_cannot_sign_twice(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        create_resp = _create_workflow(client, token1, [u2["address"]])
        wf_id = create_resp.json()["id"]
        client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig1",
        }, headers=auth_header(token2))
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig2",
        }, headers=auth_header(token2))
        assert resp.status_code == 400

    def test_multi_signer_workflow_completion(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        create_resp = _create_workflow(client, token1, [u1["address"], u2["address"]])
        wf_id = create_resp.json()["id"]

        resp1 = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_user1",
        }, headers=auth_header(token1))
        assert resp1.status_code == 200
        assert resp1.json()["status"] == "pending"

        resp2 = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_user2",
        }, headers=auth_header(token2))
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "completed"

    def test_sign_rejected_when_signature_invalid(self, client, user1, user2, monkeypatch):
        """M1: the server verifies the approval signature; a bad one is rejected
        and the workflow does not advance. (Overrides the conftest stub.)"""
        token1, _ = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u2["address"]]).json()["id"]

        monkeypatch.setattr("auth.verify_message_signature", lambda *a, **k: False)
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "not_a_real_signature",
        }, headers=auth_header(token2))
        assert resp.status_code == 400
        assert "Invalid approval signature" in resp.json()["detail"]

        # Workflow stays pending and the signer is not marked signed.
        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        assert wf["status"] == "pending"
        assert wf["signers"][0]["has_signed"] is False


RECIPIENT_ADDRESS = synthetic_address("multisig-recipient")


@pytest.fixture()
def recipient_user(client):
    """Recipients must be registered users (FK to users, enforced on Postgres)."""
    do_login(client, RECIPIENT_ADDRESS, TEST_ENCRYPTION_KEY, "Recipient")


class TestRecipientKeyRelease:
    """M1: recipient keys may only be (re)written by the COMPLETING signer."""

    def test_recipient_keys_rejected_on_non_final_sign(self, client, user1, user2, recipient_user):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(
            client, token1, [u1["address"], u2["address"]], [RECIPIENT_ADDRESS]
        ).json()["id"]

        # First of two signers tries to release recipient keys → rejected.
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig1",
            "recipient_keys": {RECIPIENT_ADDRESS: "malicious_overwrite"},
        }, headers=auth_header(token1))
        assert resp.status_code == 400
        assert "final signature" in resp.json()["detail"]

        # The original creation-time recipient key is untouched.
        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        rec = next(r for r in wf["recipients"] if r["user_address"] == RECIPIENT_ADDRESS)
        assert rec["encrypted_key"] == f"enc_key_for_{RECIPIENT_ADDRESS}"

    def test_recipient_keys_accepted_on_final_sign(self, client, user1, user2, recipient_user):
        token1, _ = user1
        token2, u2 = user2
        wf_id = _create_workflow(
            client, token1, [u2["address"]], [RECIPIENT_ADDRESS]
        ).json()["id"]

        # Single signer == the completing signer → may release recipient keys.
        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_final",
            "recipient_keys": {RECIPIENT_ADDRESS: "released_key"},
        }, headers=auth_header(token2))
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"

        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        rec = next(r for r in wf["recipients"] if r["user_address"] == RECIPIENT_ADDRESS)
        assert rec["encrypted_key"] == "released_key"


class TestRecipientAddressNormalization:
    """L-2: the recipient path never lowercased its address keys.

    The signer path normalized its key map at creation; the recipient path did
    not, and the completing-signature lookup matched `user_address == r_addr`
    on the raw value. A client sending a mixed-case address therefore matched
    no row, `if recipient:` was false, and the loop passed in silence — leaving
    a COMPLETED workflow whose recipient holds no key. That state is terminal:
    the secret is released to nobody and a completed workflow can no longer be
    signed or deleted.
    """

    def test_creation_accepts_a_mixed_case_recipient_key(self, client, user1, user2, recipient_user):
        token1, u1 = user1
        _, u2 = user2
        resp = client.post("/multisig/workflow", json={
            "name": "MixedCase",
            "secret_data": {
                "name": "S", "type": "standard",
                "encrypted_data": "d", "encrypted_key": "k",
            },
            "signers": [u2["address"]],
            "recipients": [RECIPIENT_ADDRESS],
            "signer_keys": {u2["address"]: "signer_key"},
            # The client spelled the address in a different case.
            "recipient_keys": {RECIPIENT_ADDRESS.upper(): "creation_key"},
            "threshold": 1,
        }, headers=auth_header(token1))
        assert resp.status_code == 200, resp.text

        wf = client.get(f"/multisig/workflow/{resp.json()['id']}",
                        headers=auth_header(token1)).json()
        rec = next(r for r in wf["recipients"] if r["user_address"] == RECIPIENT_ADDRESS)
        assert rec["encrypted_key"] == "creation_key"

    def test_completing_signature_accepts_a_mixed_case_recipient_key(self, client, user1, user2, recipient_user):
        token1, _ = user1
        token2, u2 = user2
        wf_id = _create_workflow(
            client, token1, [u2["address"]], [RECIPIENT_ADDRESS]
        ).json()["id"]

        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_final",
            "recipient_keys": {RECIPIENT_ADDRESS.upper(): "released_key"},
        }, headers=auth_header(token2))
        assert resp.status_code == 200, resp.text

        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        rec = next(r for r in wf["recipients"] if r["user_address"] == RECIPIENT_ADDRESS)
        assert rec["encrypted_key"] == "released_key"

    def test_refuses_to_complete_when_a_recipient_would_hold_no_key(self, client, user1, user2, recipient_user):
        # Create WITHOUT a recipient key, then try to complete without one.
        token1, _ = user1
        token2, u2 = user2
        created = client.post("/multisig/workflow", json={
            "name": "NoRecipientKey",
            "secret_data": {
                "name": "S", "type": "standard",
                "encrypted_data": "d", "encrypted_key": "k",
            },
            "signers": [u2["address"]],
            "recipients": [RECIPIENT_ADDRESS],
            "signer_keys": {u2["address"]: "signer_key"},
            "recipient_keys": {},
            "threshold": 1,
        }, headers=auth_header(token1))
        assert created.status_code == 200, created.text
        wf_id = created.json()["id"]

        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_final",
        }, headers=auth_header(token2))
        assert resp.status_code == 400, resp.text
        assert "no encrypted key for recipient" in resp.json()["detail"].lower()

        # Refusing leaves the workflow signable. Completing would have left it
        # permanently stuck, which is the whole point of failing here.
        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        assert wf["status"] == "pending"
        assert all(not s["has_signed"] for s in wf["signers"])

        # Supplying the key completes it.
        ok = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_final",
            "recipient_keys": {RECIPIENT_ADDRESS: "late_key"},
        }, headers=auth_header(token2))
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"] == "completed"

    def test_refuses_keys_for_someone_who_is_not_a_recipient(self, client, user1, user2, recipient_user):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(
            client, token1, [u2["address"]], [RECIPIENT_ADDRESS]
        ).json()["id"]

        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "sig_final",
            "recipient_keys": {u1["address"]: "not_a_recipient"},
        }, headers=auth_header(token2))
        assert resp.status_code == 400, resp.text
        assert "not recipients" in resp.json()["detail"]


class TestThreshold:
    """N-of-M: the workflow completes as soon as `threshold` signatures land."""

    def test_two_of_three_completes_at_second_signature(self, client, user1, user2, user3):
        token1, u1 = user1
        token2, u2 = user2
        token3, u3 = user3
        wf_id = _create_workflow(
            client, token1, [u1["address"], u2["address"], u3["address"]], threshold=2
        ).json()["id"]

        # First signature → still pending.
        r1 = client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s1"},
                         headers=auth_header(token1))
        assert r1.status_code == 200
        assert r1.json()["status"] == "pending"

        # Second signature reaches the threshold → completed.
        r2 = client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s2"},
                         headers=auth_header(token2))
        assert r2.status_code == 200
        assert r2.json()["status"] == "completed"

        # The third signer can no longer sign — signing is closed at threshold.
        r3 = client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s3"},
                         headers=auth_header(token3))
        assert r3.status_code == 400
        assert "completed" in r3.json()["detail"]

    def test_threshold_above_signer_count_rejected(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = _create_workflow(client, token1, [u2["address"]], threshold=2)
        assert resp.status_code == 400

    def test_threshold_below_one_rejected(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = _create_workflow(client, token1, [u2["address"]], threshold=0)
        # ge=1 on the field → 422; an explicit <1 guard would be 400. Accept either.
        assert resp.status_code in (400, 422)

    def test_completing_signer_may_release_under_threshold(self, client, user1, user2, user3, recipient_user):
        """Under a 2-of-3 threshold, the 2nd (completing) signer releases keys."""
        token1, u1 = user1
        token2, u2 = user2
        _, u3 = user3
        wf_id = _create_workflow(
            client, token1, [u1["address"], u2["address"], u3["address"]],
            [RECIPIENT_ADDRESS], threshold=2,
        ).json()["id"]

        # Non-completing (1st) signer cannot release.
        r1 = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "s1", "recipient_keys": {RECIPIENT_ADDRESS: "bad"},
        }, headers=auth_header(token1))
        assert r1.status_code == 400

        # Sign for real (no keys), then the 2nd signer completes and releases.
        client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s1"},
                    headers=auth_header(token1))
        r2 = client.post(f"/multisig/workflow/{wf_id}/sign", json={
            "signature": "s2", "recipient_keys": {RECIPIENT_ADDRESS: "released_key"},
        }, headers=auth_header(token2))
        assert r2.status_code == 200
        assert r2.json()["status"] == "completed"
        wf = client.get(f"/multisig/workflow/{wf_id}", headers=auth_header(token1)).json()
        rec = next(r for r in wf["recipients"] if r["user_address"] == RECIPIENT_ADDRESS)
        assert rec["encrypted_key"] == "released_key"


class TestRejectWorkflow:
    def test_signer_can_reject(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u1["address"], u2["address"]]).json()["id"]

        resp = client.post(f"/multisig/workflow/{wf_id}/reject", json={"reason": "nope"},
                           headers=auth_header(token2))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rejected"
        assert data["rejected_by"] == u2["address"]

    def test_sign_blocked_after_reject(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u1["address"], u2["address"]]).json()["id"]
        client.post(f"/multisig/workflow/{wf_id}/reject", json={}, headers=auth_header(token2))

        resp = client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s1"},
                           headers=auth_header(token1))
        assert resp.status_code == 400
        assert "rejected" in resp.json()["detail"]

    def test_non_signer_cannot_reject(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        # Only u2 is a signer; the owner (u1) is not, so u1 cannot reject.
        wf_id = _create_workflow(client, token1, [u2["address"]]).json()["id"]
        resp = client.post(f"/multisig/workflow/{wf_id}/reject", json={},
                           headers=auth_header(token1))
        assert resp.status_code == 403


class TestDeleteWorkflow:
    def test_owner_deletes_rejected_workflow(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u1["address"], u2["address"]]).json()["id"]
        client.post(f"/multisig/workflow/{wf_id}/reject", json={}, headers=auth_header(token2))

        resp = client.delete(f"/multisig/workflow/{wf_id}", headers=auth_header(token1))
        assert resp.status_code == 204
        # Workflow is gone.
        assert client.get(f"/multisig/workflow/{wf_id}",
                          headers=auth_header(token1)).status_code == 404

    def test_non_owner_cannot_delete(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u1["address"], u2["address"]]).json()["id"]
        resp = client.delete(f"/multisig/workflow/{wf_id}", headers=auth_header(token2))
        assert resp.status_code == 403

    def test_cannot_delete_completed_workflow(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        wf_id = _create_workflow(client, token1, [u2["address"]]).json()["id"]
        client.post(f"/multisig/workflow/{wf_id}/sign", json={"signature": "s1"},
                    headers=auth_header(token2))
        resp = client.delete(f"/multisig/workflow/{wf_id}", headers=auth_header(token1))
        assert resp.status_code == 400
