"""Tests for /secrets and /documents endpoints — CRUD, sharing, access control."""

from conftest import auth_header


def _create_secret(client, token, name="TestSecret", encrypted_data="enc_data_abc", encrypted_key="enc_key_123"):
    return client.post("/secrets", json={
        "name": name, "type": "standard",
        "encrypted_data": encrypted_data, "encrypted_key": encrypted_key,
    }, headers=auth_header(token))


class TestCreateSecret:
    def test_create_secret_success(self, client, user1):
        token, user = user1
        resp = _create_secret(client, token)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "TestSecret"
        assert data["owner_address"] == user["address"]
        assert data["encrypted_key"] == "enc_key_123"

    def test_create_secret_unauthenticated(self, client):
        resp = client.post("/secrets", json={
            "name": "x", "type": "standard",
            "encrypted_data": "d", "encrypted_key": "k",
        })
        assert resp.status_code == 401


class TestGetSecrets:
    def test_get_own_secrets(self, client, user1):
        token, _ = user1
        _create_secret(client, token, "Secret1")
        _create_secret(client, token, "Secret2")
        resp = client.get("/secrets", headers=auth_header(token))
        assert resp.status_code == 200
        names = [s["name"] for s in resp.json()]
        assert "Secret1" in names
        assert "Secret2" in names

    def test_cannot_see_other_users_secrets(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        _create_secret(client, token1, "PrivateSecret")
        resp = client.get("/secrets", headers=auth_header(token2))
        assert resp.status_code == 200
        names = [s["name"] for s in resp.json()]
        assert "PrivateSecret" not in names


class TestUpdateSecret:
    def test_update_own_secret(self, client, user1):
        token, _ = user1
        create_resp = _create_secret(client, token)
        secret_id = create_resp.json()["id"]
        resp = client.put(f"/secrets/{secret_id}", json={
            "name": "Updated", "type": "standard",
            "encrypted_data": "new_data", "encrypted_key": "new_key",
        }, headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    def test_cannot_update_others_secret(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        resp = client.put(f"/secrets/{secret_id}", json={
            "name": "Hacked", "type": "standard",
            "encrypted_data": "x", "encrypted_key": "y",
        }, headers=auth_header(token2))
        assert resp.status_code == 403


class TestDeleteSecret:
    def test_delete_own_secret(self, client, user1):
        token, _ = user1
        create_resp = _create_secret(client, token)
        secret_id = create_resp.json()["id"]
        resp = client.delete(f"/secrets/{secret_id}", headers=auth_header(token))
        assert resp.status_code == 200
        list_resp = client.get("/secrets", headers=auth_header(token))
        ids = [s["id"] for s in list_resp.json()]
        assert secret_id not in ids

    def test_cannot_delete_others_secret(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        resp = client.delete(f"/secrets/{secret_id}", headers=auth_header(token2))
        assert resp.status_code == 403

    def test_delete_nonexistent_secret(self, client, user1):
        token, _ = user1
        resp = client.delete("/secrets/99999", headers=auth_header(token))
        assert resp.status_code == 404


class TestShareSecret:
    def test_share_secret_with_another_user(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        resp = client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "wrapped_key_for_user2",
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["grantee_address"] == u2["address"]

    def test_shared_secret_visible_in_shared_with_me(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "wrapped_key",
        }, headers=auth_header(token1))
        resp = client.get("/secrets/shared-with-me", headers=auth_header(token2))
        assert resp.status_code == 200
        grant_secret_ids = [g["secret_id"] for g in resp.json()]
        assert secret_id in grant_secret_ids

    def test_cannot_share_others_secret(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        resp = client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "key",
        }, headers=auth_header(token2))
        assert resp.status_code == 403

    def test_share_to_nonexistent_user_fails(self, client, user1):
        token, _ = user1
        create_resp = _create_secret(client, token)
        secret_id = create_resp.json()["id"]
        resp = client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": "nonexistent_user",
            "encrypted_key": "key",
        }, headers=auth_header(token))
        assert resp.status_code == 404


class TestRevokeGrant:
    def test_owner_can_revoke_grant(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        share_resp = client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "key",
        }, headers=auth_header(token1))
        grant_id = share_resp.json()["id"]
        resp = client.delete(f"/secrets/share/{grant_id}", headers=auth_header(token1))
        assert resp.status_code == 200

    def test_grantee_can_revoke_own_grant(self, client, user1, user2):
        token1, _ = user1
        token2, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        share_resp = client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "key",
        }, headers=auth_header(token1))
        grant_id = share_resp.json()["id"]
        resp = client.delete(f"/secrets/share/{grant_id}", headers=auth_header(token2))
        assert resp.status_code == 200


class TestGetSecretAccess:
    def test_owner_can_list_grants(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        client.post("/secrets/share", json={
            "secret_id": secret_id,
            "grantee_address": u2["address"],
            "encrypted_key": "key",
        }, headers=auth_header(token1))
        resp = client.get(f"/secrets/{secret_id}/access", headers=auth_header(token1))
        assert resp.status_code == 200
        assert len(resp.json()) >= 2  # owner grant + shared

    def test_non_owner_cannot_list_grants(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        create_resp = _create_secret(client, token1)
        secret_id = create_resp.json()["id"]
        resp = client.get(f"/secrets/{secret_id}/access", headers=auth_header(token2))
        assert resp.status_code == 403


class TestDocuments:
    def test_create_document(self, client, user1):
        token, user = user1
        resp = client.post("/documents", json={
            "name": "TestDoc", "content_hash": "abc123hash", "signature": "sig_data",
        }, headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "TestDoc"
        assert resp.json()["owner_address"] == user["address"]

    def test_get_own_documents(self, client, user1):
        token, _ = user1
        client.post("/documents", json={
            "name": "Doc1", "content_hash": "h1", "signature": "s1",
        }, headers=auth_header(token))
        resp = client.get("/documents", headers=auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1
