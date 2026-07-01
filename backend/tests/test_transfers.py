"""Tests for the device-to-device key transfer relay (/transfers)."""
import models
from conftest import (
    TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY,
    do_login, auth_header,
)

BLOB = '{"salt":"00","iv":"11","data":"deadbeef"}'


class TestCreateTransfer:
    def test_requires_auth(self, client):
        assert client.post("/transfers", json={"ciphertext": BLOB}).status_code == 401

    def test_create_returns_id_and_expiry(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        resp = client.post("/transfers", json={"ciphertext": BLOB}, headers=auth_header(token))
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["id"] and isinstance(data["id"], str)
        assert data["expires_at"]


class TestClaimTransfer:
    def test_claim_returns_ciphertext_without_auth(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        tid = client.post("/transfers", json={"ciphertext": BLOB}, headers=auth_header(token)).json()["id"]
        # Target device has no auth — claim by id only.
        resp = client.get(f"/transfers/{tid}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["ciphertext"] == BLOB

    def test_claim_is_single_use(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        tid = client.post("/transfers", json={"ciphertext": BLOB}, headers=auth_header(token)).json()["id"]
        assert client.get(f"/transfers/{tid}").status_code == 200
        # Second claim fails — the row was consumed.
        assert client.get(f"/transfers/{tid}").status_code == 404

    def test_unknown_id_is_404(self, client):
        assert client.get("/transfers/does-not-exist").status_code == 404

    def test_expired_transfer_is_404(self, client, db_session):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        tid = client.post("/transfers", json={"ciphertext": BLOB}, headers=auth_header(token)).json()["id"]
        # Force-expire the row.
        from datetime import datetime, timezone, timedelta
        row = db_session.query(models.KeyTransfer).filter(models.KeyTransfer.id == tid).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db_session.commit()
        assert client.get(f"/transfers/{tid}").status_code == 404
