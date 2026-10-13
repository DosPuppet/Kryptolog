"""
Server-side signature gate (crypto-core 4: composite ML-DSA-65 + Ed25519).

Covers:
  * The server JWT path: create_access_token -> decode_access_token round-trip,
    tamper rejection, wrong-secret rejection, and the HS256 header. (JWTs are
    classical HS256 via PyJWT; only the signed bodies below need the hybrid.)
  * The login-challenge verifier and the generic identity verifier, against
    REAL composite signatures over the exact bodies the server rebuilds.

The primitive itself — sizes, the draft's vectors, noble <-> OpenSSL interop in
both directions, the Ed25519 edges, the startup guard — is pinned by
tests/test_hybrid_primitives.py. This file used to carry the ML-DSA-44 half of
that, with tests/fixtures/pqc_interop.json, both gone with crypto-core 4.0.0.
"""

import base64
import hashlib
import json

import jwt
from conftest import CompositeSigner

import auth


def _sig_b64(raw: bytes) -> str:
    """A signature as the clients send it: base64 since the L-12 cutover.
    Public keys stay hex — they are identifiers, not payloads."""
    return base64.b64encode(raw).decode()


def test_jwt_roundtrip_and_header(monkeypatch):
    monkeypatch.setattr(auth, "_JWT_SECRET", "a" * 64)

    token = auth.create_access_token({"sub": "alice", "user_id": 42})
    assert token and token.count(".") == 2

    payload = auth.decode_access_token(token)
    assert payload["sub"] == "alice"
    assert payload["user_id"] == 42

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS256" and header["typ"] == "JWT"


def test_jwt_tampered_payload_rejected(monkeypatch):
    monkeypatch.setattr(auth, "_JWT_SECRET", "b" * 64)

    token = auth.create_access_token({"sub": "bob", "user_id": 1})
    h, _p, s = token.split(".")
    # Re-sign? No — keep the original signature but swap the payload. HS256 binds
    # the signature to the payload, so verification must fail.
    forged = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "user_id": 0, "exp": 9999999999}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    assert auth.decode_access_token(f"{h}.{forged}.{s}") is None


def test_jwt_wrong_secret_rejected(monkeypatch):
    monkeypatch.setattr(auth, "_JWT_SECRET", "c" * 64)
    token = auth.create_access_token({"sub": "carol", "user_id": 9})

    # decode under a different secret -> verification must fail
    monkeypatch.setattr(auth, "_JWT_SECRET", "d" * 64)
    assert auth.decode_access_token(token) is None


def test_jwt_expired_rejected(monkeypatch):
    monkeypatch.setattr(auth, "_JWT_SECRET", "e" * 64)
    from datetime import timedelta

    token = auth.create_access_token({"sub": "dave"}, expires_delta=timedelta(seconds=-1))
    assert auth.decode_access_token(token) is None


# What every login names (crypto-core 3.0.0, audit 2026-10-12 K-02).
SERVER = {"origin": "https://kryptolog.example", "deployment": "dep-1"}


def _verify(pk_hex, sig_b64, nonce, enc_key=None, **server):
    return auth.verify_pqc_signature(
        pk_hex, sig_b64, nonce=nonce, encryption_public_key=enc_key, **{**SERVER, **server}
    )


def test_login_challenge_real_verification():
    """The login-challenge verifier accepts a genuine composite client
    signature over the exact login message, and rejects a bad nonce.

    Calls verify_pqc_signature directly: the autouse conftest fixture stubs the
    higher-level verify_signature, but the PQC primitive underneath is real."""
    nonce = auth.generate_nonce()
    message = auth._login_message(nonce, **SERVER).encode("utf-8")
    client = CompositeSigner()
    pk_hex, sig_b64 = client.identity_public_key, _sig_b64(client.sign(message))

    assert _verify(pk_hex, sig_b64, nonce) is True
    # signature over a different nonce must not verify
    assert _verify(pk_hex, sig_b64, "00" * 16) is False
    # garbage signature must not raise, just fail
    assert _verify(pk_hex, "not-base64!", nonce) is False


def test_login_challenge_names_the_server():
    """K-02: a signature made for another site, or for another Kryptolog
    deployment, is not a login here — the body names both."""
    nonce = auth.generate_nonce()
    message = auth._login_message(nonce, **SERVER).encode("utf-8")
    client = CompositeSigner()
    pk_hex, sig_b64 = client.identity_public_key, _sig_b64(client.sign(message))
    assert _verify(pk_hex, sig_b64, nonce) is True
    assert _verify(pk_hex, sig_b64, nonce, origin="https://evil.example") is False
    assert _verify(pk_hex, sig_b64, nonce, deployment="other") is False


def test_login_challenge_binds_encryption_key():
    """M-2: when an encryption key is supplied it is folded into the
    signed challenge, so a signature is valid only for the exact key it covers —
    a network attacker can't substitute a different KEM key at login."""
    nonce = auth.generate_nonce()
    enc_key = "ab" * 1216
    message = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER).encode("utf-8")
    client = CompositeSigner()
    pk_hex, sig_b64 = client.identity_public_key, _sig_b64(client.sign(message))

    # Valid only with the exact bound key.
    assert _verify(pk_hex, sig_b64, nonce, enc_key) is True
    # Substituting a different encryption key fails (the binding holds).
    assert _verify(pk_hex, sig_b64, nonce, "cd" * 1216) is False
    # Dropping the key (downgrade attempt) also fails — the signature covers it.
    assert _verify(pk_hex, sig_b64, nonce, None) is False


def test_login_challenge_is_domain_separated():
    """H1: the login challenge is wrapped under the `login` domain tag, so the
    signed bytes are disjoint from any content-signing operation (multisig /
    document approval). The wrapper is fixed by code, never by content."""
    nonce = "deadbeef" * 4
    enc_key = "cd" * 1216
    msg = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER)
    assert msg.startswith("Kryptolog Signed Message v1\ncontext=login\nSign in to Kryptolog\n")
    assert f"\nnonce={nonce}\n" in msg
    assert msg.endswith(f"\nencryption-key={enc_key}")


def test_content_signature_cannot_be_replayed_as_login():
    """H1 regression / the actual attack: a signature a victim produced while
    approving attacker-chosen *content* must NOT verify as a login challenge,
    even when the attacker set that content equal to the raw login body."""
    nonce = auth.generate_nonce()
    enc_key = "ef" * 1216

    # The login body without its domain header — what an attacker would coerce
    # a victim into signing as raw or content-wrapped multisig content.
    full = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER)
    raw_login_body = full.split("\ncontext=login\n", 1)[1]
    content_wrapped = f"Kryptolog Signed Message v1\ncontext=content\n{raw_login_body}"

    client = CompositeSigner()
    sig_raw = _sig_b64(client.sign(raw_login_body.encode("utf-8")))
    sig_content = _sig_b64(client.sign(content_wrapped.encode("utf-8")))
    pk_hex = client.identity_public_key

    # Neither harvested signature is accepted as a login for this nonce+key.
    assert _verify(pk_hex, sig_raw, nonce, enc_key) is False
    assert _verify(pk_hex, sig_content, nonce, enc_key) is False

    # Sanity: a signature over the properly domain-separated challenge (what
    # the real client builds) still verifies — we didn't break login.
    client2 = CompositeSigner()
    good_sig = _sig_b64(client2.sign(full.encode("utf-8")))
    assert _verify(client2.identity_public_key, good_sig, nonce, enc_key) is True


def test_multisig_approval_message_is_domain_separated():
    """M1: the multisig approval is bound to workflow + secret + ciphertext hash
    and namespaced under `multisig-approval`, disjoint from login and content."""
    msg = auth.multisig_approval_message(7, 42, "ab" * 48)
    assert msg.startswith("Kryptolog Signed Message v1\ncontext=multisig-approval\n")
    assert "workflow=7" in msg and "secret=42" in msg and f"ct={'ab' * 48}" in msg
    # Disjoint from a login message and a content message over the same body.
    body = "workflow=7\nsecret=42\nct=" + "ab" * 48
    assert msg != auth._domain_separate("login", body)
    assert msg != auth._domain_separate("content", body)


# Captured at import time, before the autouse conftest fixture can stub it —
# this unit test exercises the REAL verifier (the endpoint tests use the stub).
_real_verify_identity_signature = auth.verify_identity_signature


def test_verify_identity_signature_pqc():
    """M1: the generic verifier accepts a real composite signature over the exact
    multisig approval message and rejects tampering, wrong key, and bad hex —
    this is what the /sign endpoint relies on to gate `has_signed`."""
    verify = _real_verify_identity_signature
    ct_hash = hashlib_sha384_hex("encrypted_payload")
    msg = auth.multisig_approval_message(1, 1, ct_hash)
    signer = CompositeSigner()
    pk_hex, sig_b64 = signer.identity_public_key, _sig_b64(signer.sign(msg.encode("utf-8")))

    assert verify(pk_hex, msg, sig_b64) is True
    # Wrong message (e.g. a different ciphertext hash) → reject.
    other = auth.multisig_approval_message(1, 1, hashlib_sha384_hex("tampered"))
    assert verify(pk_hex, other, sig_b64) is False
    # Wrong signer key → reject.
    other_pk = CompositeSigner().identity_public_key
    assert verify(other_pk, msg, sig_b64) is False
    # Malformed signature → false, not an exception.
    assert verify(pk_hex, msg, "not-base64!") is False


def hashlib_sha384_hex(s: str) -> str:
    return hashlib.sha384(s.encode("utf-8")).hexdigest()
