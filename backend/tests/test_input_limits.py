"""Input bounds (audit KRY-010).

These are DoS bounds, not format validation — they cap how much a caller can
push through a field. The cryptographic format checks live in
security/crypto_validation.py and are covered by test_crypto_validation.py.
"""
import pytest

import schemas
from conftest import TEST_ENCRYPTION_KEY, TEST_USER_ADDRESS, auth_header, do_login


class TestBoundsAreSane:
    def test_address_bound_fits_a_real_address_with_headroom(self):
        """An ML-DSA-44 address is 2624 hex chars; the bound must admit it."""
        from security.crypto_validation import ML_DSA_44_PUBLIC_KEY_HEX_LEN
        assert schemas.MAX_ADDRESS_LEN >= ML_DSA_44_PUBLIC_KEY_HEX_LEN
        # ...but nothing like the old 20 000-char ceiling.
        assert schemas.MAX_ADDRESS_LEN < 20_000

    def test_display_name_bound_is_not_absurd(self):
        """Was 500 000 — half a megabyte for a sidebar label."""
        assert schemas.MAX_DISPLAY_NAME_LEN <= 10_000

    def test_secret_blob_bound_is_unchanged(self):
        """The payload field keeps its own (large) bound — it is not a name."""
        assert schemas.MAX_SECRET_BLOB_LEN == 500_000


class TestOversizedInputRejected:
    def test_oversized_address_is_rejected(self, client):
        r = client.post("/auth/login", json={
            "address": "a" * (schemas.MAX_ADDRESS_LEN + 1),
            "signature": "sig",
            "nonce": "n",
        })
        assert r.status_code == 422

    def test_oversized_group_name_is_rejected(self, client, user2):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2
        r = client.post("/groups", json={
            "name": "x" * (schemas.MAX_DISPLAY_NAME_LEN + 1),
            "member_addresses": [member["address"]],
        }, headers=auth_header(token))
        assert r.status_code == 422

    def test_oversized_push_endpoint_is_rejected(self, client):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        r = client.post("/notifications/subscribe", json={
            "endpoint": "https://push.example.com/" + "a" * 5000,
            "p256dh": "k", "auth": "a",
        }, headers=auth_header(token))
        # 422 from the schema bound, or 400 from the SSRF guard — either is a
        # refusal, and both are correct.
        assert r.status_code in (400, 422)


class TestValidInputStillAccepted:
    def test_normal_group_name_works(self, client, user2):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2
        r = client.post("/groups",
                        json={"name": "Engineering",
                              "member_addresses": [member["address"]]},
                        headers=auth_header(token))
        assert r.status_code in (200, 201), r.text

    def test_real_length_address_is_accepted(self, client):
        """A full 2624-char ML-DSA address must not be caught by the new bound."""
        addr = "ab" * 1312
        token, user = do_login(client, addr, TEST_ENCRYPTION_KEY, "RealLen")
        assert user["address"] == addr.lower()
