"""Per-user storage quota (audit 2026-10-12 K-09).

Without one, anyone who could register — and signup was open by default — could
fill the database disk: 50 MB per secret, secrets without limit. The quotas are
small here so the tests are fast; the race test is the one that matters, since
a count-then-insert ceiling is no ceiling under concurrent uploads.
"""

import base64

import pytest
from conftest import TEST_ENCRYPTION_KEY, TEST_USER_ADDRESS, auth_header, do_login
from test_concurrency import _run_concurrently

from security import quota


def _secret(name="n", data="d"):
    return {"name": name, "type": "standard", "encrypted_data": data, "encrypted_key": "k"}


def _chunk(secret_id, index, raw_len):
    return {
        "secret_id": secret_id,
        "chunk_index": index,
        "iv": base64.b64encode(bytes(12)).decode(),
        "encrypted_data": base64.b64encode(b"\x01" * raw_len).decode(),
    }


@pytest.fixture
def owner(client):
    token, _ = do_login(client, TEST_USER_ADDRESS, encryption_key=TEST_ENCRYPTION_KEY)
    return auth_header(token)


def test_the_secret_count_is_capped(client, owner, monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_QUOTA_SECRETS", "2")
    assert client.post("/secrets", json=_secret(), headers=owner).status_code == 200
    assert client.post("/secrets", json=_secret(), headers=owner).status_code == 200
    r = client.post("/secrets", json=_secret(), headers=owner)
    assert r.status_code == 413
    assert "quota" in r.json()["detail"].lower()


def test_inline_content_counts_against_the_byte_quota(client, owner, monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_QUOTA_BYTES", "1000")
    assert client.post("/secrets", json=_secret(data="x" * 600), headers=owner).status_code == 200
    r = client.post("/secrets", json=_secret(data="x" * 600), headers=owner)
    assert r.status_code == 413


def test_chunks_count_against_the_byte_quota(client, owner, monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_QUOTA_BYTES", "3000")
    sid = client.post("/secrets", json=_secret(), headers=owner).json()["id"]
    assert (
        client.post("/secrets/chunks", json=_chunk(sid, 0, 1500), headers=owner).status_code == 201
    )
    r = client.post("/secrets/chunks", json=_chunk(sid, 1, 1500), headers=owner)
    assert r.status_code == 413


def test_an_edit_counts_only_its_growth(client, owner, monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_QUOTA_BYTES", "1000")
    sid = client.post("/secrets", json=_secret(data="x" * 800), headers=owner).json()["id"]
    # Same size: allowed even though 800 + 800 would be over the quota.
    assert (
        client.put(f"/secrets/{sid}", json=_secret(data="y" * 800), headers=owner).status_code
        == 200
    )
    r = client.put(f"/secrets/{sid}", json=_secret(data="y" * 1200), headers=owner)
    assert r.status_code == 413


def test_concurrent_uploads_cannot_overrun_the_quota(client, owner, monkeypatch):
    """The point of the row lock: every upload sees room for itself alone
    under a count-then-insert check, and all of them land."""
    from dependencies import limiter

    limiter.enabled = False
    try:
        chunk_chars = len(_chunk(0, 0, 3000)["encrypted_data"])  # 4000
        monkeypatch.setenv("KRYPTOLOG_QUOTA_BYTES", str(chunk_chars * 3 + 100))
        sid = client.post("/secrets", json=_secret(), headers=owner).json()["id"]

        results = _run_concurrently(
            lambda c, i: (
                c.post("/secrets/chunks", json=_chunk(sid, i, 3000), headers=owner).status_code
            ),
            count=12,
        )
        assert results.count(201) == 3, results
        assert set(results) == {201, 413}, results
    finally:
        limiter.enabled = True


def test_defaults_are_generous_but_finite(monkeypatch):
    monkeypatch.delenv("KRYPTOLOG_QUOTA_SECRETS", raising=False)
    monkeypatch.delenv("KRYPTOLOG_QUOTA_BYTES", raising=False)
    assert 100 <= quota.max_secrets_per_user() <= 100_000
    assert 50 * 1024 * 1024 <= quota.max_stored_chars_per_user() <= 100 * 1024**3
