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
