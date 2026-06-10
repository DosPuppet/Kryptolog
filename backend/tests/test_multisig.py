"""Tests for /multisig endpoints — workflow creation, signing, completion."""

from conftest import auth_header


def _create_workflow(client, token, signer_addresses, recipient_addresses=None):
    if recipient_addresses is None:
        recipient_addresses = []
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


RECIPIENT_ADDRESS = "recipient_" + "r" * 100


class TestRecipientKeyRelease:
    """M1: recipient keys may only be (re)written by the COMPLETING signer."""

    def test_recipient_keys_rejected_on_non_final_sign(self, client, user1, user2):
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

    def test_recipient_keys_accepted_on_final_sign(self, client, user1, user2):
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
