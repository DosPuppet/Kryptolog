import base64
from unittest.mock import patch
from uuid import uuid4

import pytest
from conftest import TEST_USER_ADDRESS_2


# Chunk payloads must be canonical base64 (audit M-2, base64 since L-12):
# FileChunkUpload rejects anything else, and upload_chunk's size accounting
# converts length to bytes, which only means anything for a real encoding.
# These helpers keep the fixtures honest.
def _b64(label: str, byte_len: int = 16) -> str:
    """Deterministic base64 blob, distinct per label, of `byte_len` bytes."""
    raw = (label.encode() * byte_len)[:byte_len]
    return base64.b64encode(raw).decode()


IV_B64 = base64.b64encode(bytes(12)).decode()  # 12-byte AES-GCM IV


def create_test_secret(client, token):
    response = client.post(
        "/secrets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": f"Test Chunk Secret {uuid4()}",
            "type": "file",
            "encrypted_data": '{"file_name":"test.bin","mime_type":"application/octet-stream","total_chunks":2}',
            "encrypted_key": "mock_key",
        },
    )
    assert response.status_code == 200
    return response.json()


class TestFileChunks:
    def test_upload_chunk_success(self, client, user1):
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        # 1. Create a secret
        secret = create_test_secret(client, token)
        secret_id = secret["id"]

        # 2. Upload Chunk 0
        chunk_0 = {
            "secret_id": secret_id,
            "chunk_index": 0,
            "iv": IV_B64,
            "encrypted_data": _b64("c0"),
        }
        res0 = client.post("/secrets/chunks", headers=auth_headers, json=chunk_0)
        assert res0.status_code == 201
        assert res0.json()["chunk_index"] == 0

        # 3. Upload Chunk 1
        chunk_1 = {
            "secret_id": secret_id,
            "chunk_index": 1,
            "iv": IV_B64,
            "encrypted_data": _b64("c1"),
        }
        res1 = client.post("/secrets/chunks", headers=auth_headers, json=chunk_1)
        assert res1.status_code == 201

    def test_bulk_chunk_listing_endpoint_is_gone(self, client, user1):
        """GET /secrets/{id}/chunks was removed (audit H-2).

        It dumped every chunk's full encrypted_data in one unthrottled response
        — ~100 MB of strings for a 50 MB file, against a 500 MB worker. No
        client ever used it; chunks are fetched one at a time by index.
        """
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        secret = create_test_secret(client, token)
        secret_id = secret["id"]
        client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )

        res = client.get(f"/secrets/{secret_id}/chunks", headers=auth_headers)
        assert res.status_code == 404

    def test_duplicate_chunk_index_rejected(self, client, user1):
        """A second upload at an existing index is refused (audit M-2).

        Before uq_file_chunk_secret_index both inserts succeeded and reads
        returned whichever row Postgres listed first, so the same file could
        reassemble differently on each download with no error anywhere.
        """
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        secret = create_test_secret(client, token)
        secret_id = secret["id"]

        first = client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("original"),
            },
        )
        assert first.status_code == 201

        shadow = client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("shadow"),
            },
        )
        assert shadow.status_code == 409

        # The original payload is what a read returns — deterministically.
        res = client.get(f"/secrets/{secret_id}/chunks/0", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["encrypted_data"] == _b64("original")

    @pytest.mark.parametrize(
        "field,value",
        [
            ("encrypted_data", "not_base64_at_all!"),
            ("encrypted_data", "abc"),  # length not a multiple of 4
            ("encrypted_data", ""),  # empty
            ("iv", "z z z"),  # whitespace: atob tolerates it, we must not
            ("iv", "A==="),  # malformed padding
            # Non-canonical: decodes fine under a lenient decoder, but gives a
            # SECOND spelling of the same bytes. A message signature commits to
            # its ciphertext as a string, so a second spelling would be a second
            # validly-signed form of one ciphertext.
            ("iv", "AB=="),
            ("encrypted_data", "AB=="),
        ],
    )
    def test_non_base64_chunk_rejected(self, client, user1, field, value):
        """iv and encrypted_data are base64 on the wire; nothing checked the
        encoding at all before M-2, and "checked" has to mean canonical."""
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        secret = create_test_secret(client, token)
        payload = {
            "secret_id": secret["id"],
            "chunk_index": 0,
            "iv": IV_B64,
            "encrypted_data": _b64("c0"),
        }
        payload[field] = value

        res = client.post("/secrets/chunks", headers=auth_headers, json=payload)
        assert res.status_code == 422

    def test_negative_chunk_index_rejected(self, client, user1):
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}
        secret = create_test_secret(client, token)

        res = client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret["id"],
                "chunk_index": -1,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )
        assert res.status_code == 422

    def test_get_chunk(self, client, user1):
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        secret = create_test_secret(client, token)
        secret_id = secret["id"]

        # Upload
        client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )

        # Get
        res = client.get(f"/secrets/{secret_id}/chunks/0", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["chunk_index"] == 0
        assert data["encrypted_data"] == _b64("c0")

    def test_upload_chunk_not_owner_fails(self, client, user1, user2):
        token1, _ = user1
        token2, _ = user2
        user2_headers = {"Authorization": f"Bearer {token2}"}

        # User 1 creates secret
        secret = create_test_secret(client, token1)
        secret_id = secret["id"]

        # User 2 tries to upload to User 1's secret
        res = client.post(
            "/secrets/chunks",
            headers=user2_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )
        assert res.status_code == 403

    def test_get_chunk_access_control(self, client, user1, user2):
        token1, _ = user1
        auth_headers = {"Authorization": f"Bearer {token1}"}

        token2, _ = user2
        user2_headers = {"Authorization": f"Bearer {token2}"}

        # User 1 creates secret + uploads chunk
        secret = create_test_secret(client, token1)
        secret_id = secret["id"]
        client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )

        # User 2 tries to read
        res = client.get(f"/secrets/{secret_id}/chunks/0", headers=user2_headers)
        assert res.status_code == 403

        # User 1 shares with User 2
        share_res = client.post(
            "/secrets/share",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "grantee_address": TEST_USER_ADDRESS_2,  # the constant itself, not a hand-copy of it
                "encrypted_key": "shared_key",
            },
        )
        assert share_res.status_code == 200

        # User 2 tries again -> Success
        res2 = client.get(f"/secrets/{secret_id}/chunks/0", headers=user2_headers)
        assert res2.status_code == 200
        assert res2.json()["encrypted_data"] == _b64("c0")

    def test_delete_secret_removes_chunks(self, client, user1):
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}

        # Create + Upload
        secret = create_test_secret(client, token)
        secret_id = secret["id"]
        client.post(
            "/secrets/chunks",
            headers=auth_headers,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": _b64("c0"),
            },
        )

        # Verify chunk exists
        res = client.get(f"/secrets/{secret_id}/chunks/0", headers=auth_headers)
        assert res.status_code == 200

        # Delete Secret
        del_res = client.delete(f"/secrets/{secret_id}", headers=auth_headers)
        assert del_res.status_code == 200

        # Verify chunk gone (cascade delete)
        res2 = client.get(f"/secrets/{secret_id}/chunks/0", headers=auth_headers)
        assert res2.status_code == 404

    def test_upload_file_too_large(self, client, user1):
        """Verify that uploading chunks exceeding MAX_TOTAL_FILE_SIZE fails."""
        token, _ = user1
        auth_headers = {"Authorization": f"Bearer {token}"}
        secret = create_test_secret(client, token)
        secret_id = secret["id"]

        # Mock the config limit to be very small (e.g., 10 bytes)
        with patch("config.MAX_TOTAL_FILE_SIZE", 10):
            # 1. Upload small chunk (ok). Base64: 4 chars per 3 bytes, so
            # 8 chars = 6 bytes.
            res1 = client.post(
                "/secrets/chunks",
                headers=auth_headers,
                json={
                    "secret_id": secret_id,
                    "chunk_index": 0,
                    "iv": IV_B64,
                    "encrypted_data": _b64("a", 6),
                },
            )
            assert res1.status_code == 201

            # 2. Upload another chunk that pushes total over 10 bytes.
            # Existing 6 + new 6 = 12 > 10.
            res2 = client.post(
                "/secrets/chunks",
                headers=auth_headers,
                json={
                    "secret_id": secret_id,
                    "chunk_index": 1,
                    "iv": IV_B64,
                    "encrypted_data": _b64("b", 6),
                },
            )
            assert res2.status_code == 413
            assert "too large" in res2.json()["detail"].lower()


class TestMultisigChunkAccess:
    """Tests that multisig signers and recipients can access file chunks."""

    MULTISIG_CHUNK = _b64("multisig")

    def _create_workflow_with_chunk(self, client, token_owner, signer_addr, recipient_addr=None):
        """Helper: create a workflow (which internally creates a secret), then upload chunks to it."""
        auth = {"Authorization": f"Bearer {token_owner}"}

        # Create multisig workflow (this internally creates the secret)
        signers = [signer_addr]
        recipients = [recipient_addr] if recipient_addr else []
        signer_keys = {signer_addr: "enc_key_for_signer"}
        recipient_keys = {recipient_addr: "enc_key_for_recipient"} if recipient_addr else {}

        wf_resp = client.post(
            "/multisig/workflow",
            headers=auth,
            json={
                "name": "TestChunkWorkflow",
                "secret_data": {
                    "name": "MultisigChunked",
                    "type": "file",
                    "encrypted_data": '{"file_name":"test.bin","total_chunks":1}',
                    "encrypted_key": "owner_key",
                },
                "signers": signers,
                "recipients": recipients,
                "signer_keys": signer_keys,
                "recipient_keys": recipient_keys,
                "threshold": len(signers),
            },
        )
        assert wf_resp.status_code == 200
        wf = wf_resp.json()
        secret_id = wf["secret_id"]

        # Upload a chunk to the workflow's secret
        chunk_resp = client.post(
            "/secrets/chunks",
            headers=auth,
            json={
                "secret_id": secret_id,
                "chunk_index": 0,
                "iv": IV_B64,
                "encrypted_data": self.MULTISIG_CHUNK,
            },
        )
        assert chunk_resp.status_code == 201

        return secret_id, wf["id"]

    def test_signer_can_access_chunks(self, client, user1, user2):
        """A multisig signer should be able to download chunks for the secret."""
        token1, _ = user1
        token2, u2 = user2

        secret_id, _ = self._create_workflow_with_chunk(client, token1, u2["address"])

        # Signer reads the chunk
        res = client.get(
            f"/secrets/{secret_id}/chunks/0", headers={"Authorization": f"Bearer {token2}"}
        )
        assert res.status_code == 200
        assert res.json()["encrypted_data"] == self.MULTISIG_CHUNK

    def test_recipient_blocked_before_completion(self, client, user1, user2):
        """A recipient should NOT access chunks while the workflow is still pending."""
        from conftest import TEST_ENCRYPTION_KEY, TEST_USER_ADDRESS_3, do_login

        token1, _ = user1
        _, u2 = user2

        # Create a third user as recipient
        token3, u3 = do_login(client, TEST_USER_ADDRESS_3, TEST_ENCRYPTION_KEY, "Recipient")

        secret_id, wf_id = self._create_workflow_with_chunk(
            client, token1, u2["address"], u3["address"]
        )

        # Recipient tries before signing is complete
        res = client.get(
            f"/secrets/{secret_id}/chunks/0", headers={"Authorization": f"Bearer {token3}"}
        )
        assert res.status_code == 403

    def test_recipient_can_access_after_completion(self, client, user1, user2):
        """After all signers sign, the recipient should be able to access chunks."""
        from conftest import TEST_ENCRYPTION_KEY, TEST_USER_ADDRESS_3, do_login

        token1, _ = user1
        token2, u2 = user2

        # Create a third user as recipient
        token3, u3 = do_login(client, TEST_USER_ADDRESS_3, TEST_ENCRYPTION_KEY, "Recipient")

        secret_id, wf_id = self._create_workflow_with_chunk(
            client, token1, u2["address"], u3["address"]
        )

        # Signer signs -> workflow completes
        sign_res = client.post(
            f"/multisig/workflow/{wf_id}/sign",
            json={
                "signature": "signer_signature_data",
            },
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert sign_res.status_code == 200
        assert sign_res.json()["status"] == "completed"

        # Now recipient can access
        res = client.get(
            f"/secrets/{secret_id}/chunks/0", headers={"Authorization": f"Bearer {token3}"}
        )
        assert res.status_code == 200
        assert res.json()["encrypted_data"] == self.MULTISIG_CHUNK
