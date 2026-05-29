"""
PQC migration test gate (server side, liboqs ML-DSA-44).

Covers:
  * FIPS 204 size conformance for ML-DSA-44.
  * liboqs sign -> verify round-trip and tamper rejection.
  * Cross-library interop: a signature produced by @noble/post-quantum in the
    browser/extension MUST verify under liboqs here (committed fixture).
  * The server JWT path: create_access_token -> decode_access_token round-trip,
    tamper rejection, and the ML-DSA-44 header.
  * The login-challenge verifier verify_signature against a real client key.

The matching browser/extension half lives in frontend/src/test/pqc.test.js,
which verifies the liboqs-produced fixture under noble. Together they prove the
noble <-> liboqs ML-DSA-44 encodings are wire-compatible (the one thing the
migration plan says to prove, not assume).

Full NIST KAT coverage is provided upstream by each library's own CI
(liboqs runs the reference KATs at build time; noble ships ACVP vectors).
This gate pins the integration: sizes, interop, round-trips, and a
deterministic seeded-keygen regression anchor.
"""

import json
import os

import oqs
import pytest

import auth

SIG_ALG = "ML-DSA-44"
FIXTURE = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "fixtures", "pqc_interop.json")


@pytest.fixture(scope="module")
def vec():
    with open(FIXTURE) as f:
        return json.load(f)


def test_ml_dsa_sizes_match_fips204():
    d = oqs.Signature(SIG_ALG).details
    assert d["length_public_key"] == 1312
    assert d["length_secret_key"] == 2560
    assert d["length_signature"] == 2420


def test_liboqs_roundtrip_and_tamper():
    signer = oqs.Signature(SIG_ALG)
    pk = signer.generate_keypair()
    msg = b"round-trip message"
    sig = signer.sign(msg)
    assert oqs.Signature(SIG_ALG).verify(msg, sig, pk) is True
    # tampered message must fail
    assert oqs.Signature(SIG_ALG).verify(b"round-trip messagX", sig, pk) is False
    # tampered signature must fail
    bad = bytearray(sig); bad[0] ^= 0x01
    assert oqs.Signature(SIG_ALG).verify(msg, bytes(bad), pk) is False


def test_interop_noble_signature_verifies_under_liboqs(vec):
    """noble (browser/extension) -> liboqs (server). The critical wire path."""
    pk = bytes.fromhex(vec["noble_dsa_publicKey"])
    sig = bytes.fromhex(vec["noble_dsa_signature"])
    msg = bytes.fromhex(vec["message"])
    assert oqs.Signature(SIG_ALG).verify(msg, sig, pk) is True
    # wrong message must not verify against the noble signature
    assert oqs.Signature(SIG_ALG).verify(msg + b"!", sig, pk) is False


def test_noble_seeded_keygen_pin_sizes(vec):
    """Encoding regression anchor: the committed seeded-keygen public keys keep
    the FIPS sizes (full byte-pin lives in the Node half which owns the seed)."""
    assert len(bytes.fromhex(vec["noble_dsa_publicKey"])) == 1312
    assert len(bytes.fromhex(vec["noble_kem_publicKey"])) == 1184


def test_jwt_roundtrip_and_header(monkeypatch):
    # use a real, freshly generated server key for this test
    with oqs.Signature(SIG_ALG) as s:
        pk = s.generate_keypair()
        sk = s.export_secret_key()
    monkeypatch.setattr(auth, "_SERVER_SECRET_KEY", sk)
    monkeypatch.setattr(auth, "_SERVER_PUBLIC_KEY", pk)

    token = auth.create_access_token({"sub": "alice", "user_id": 42})
    assert token and token.count(".") == 2

    payload = auth.decode_access_token(token)
    assert payload["sub"] == "alice"
    assert payload["user_id"] == 42

    header = json.loads(auth.b64url_decode(token.split(".")[0]))
    assert header["alg"] == SIG_ALG and header["typ"] == "JWT"


def test_jwt_tampered_payload_rejected(monkeypatch):
    with oqs.Signature(SIG_ALG) as s:
        pk = s.generate_keypair()
        sk = s.export_secret_key()
    monkeypatch.setattr(auth, "_SERVER_SECRET_KEY", sk)
    monkeypatch.setattr(auth, "_SERVER_PUBLIC_KEY", pk)

    token = auth.create_access_token({"sub": "bob", "user_id": 1})
    h, _p, s = token.split(".")
    forged = auth.b64url_encode(json.dumps({"sub": "admin", "user_id": 0, "exp": 9999999999}).encode())
    assert auth.decode_access_token(f"{h}.{forged}.{s}") is None


def test_jwt_wrong_key_rejected(monkeypatch):
    with oqs.Signature(SIG_ALG) as s:
        pk = s.generate_keypair(); sk = s.export_secret_key()
    monkeypatch.setattr(auth, "_SERVER_SECRET_KEY", sk)
    monkeypatch.setattr(auth, "_SERVER_PUBLIC_KEY", pk)
    token = auth.create_access_token({"sub": "carol", "user_id": 9})

    # swap to a different public key -> verification must fail
    with oqs.Signature(SIG_ALG) as s2:
        other_pk = s2.generate_keypair()
    monkeypatch.setattr(auth, "_SERVER_PUBLIC_KEY", other_pk)
    assert auth.decode_access_token(token) is None


def test_login_challenge_real_verification():
    """The PQC login-challenge verifier accepts a genuine ML-DSA-44 client
    signature over the exact login message, and rejects a bad nonce.

    Calls verify_pqc_signature directly: the autouse conftest fixture stubs the
    higher-level verify_signature, but the PQC primitive underneath is real."""
    nonce = auth.generate_nonce()
    message = f"Sign in to Secure Log App with nonce: {nonce}".encode("utf-8")
    with oqs.Signature(SIG_ALG) as client:
        pk = client.generate_keypair()
        sig = client.sign(message)
    pk_hex, sig_hex = pk.hex(), sig.hex()

    assert auth.verify_pqc_signature(pk_hex, nonce, sig_hex) is True
    # signature over a different nonce must not verify
    assert auth.verify_pqc_signature(pk_hex, "00" * 16, sig_hex) is False
    # garbage signature must not raise, just fail
    assert auth.verify_pqc_signature(pk_hex, nonce, "not-hex") is False
