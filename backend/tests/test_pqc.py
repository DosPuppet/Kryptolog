"""
PQC migration test gate (server side, pyca/cryptography ML-DSA-44).

Covers:
  * FIPS 204 size conformance for ML-DSA-44.
  * The server's verifier (`auth._verify_ml_dsa44`) on a round-trip and on
    tampering.
  * Cross-library interop: a signature produced by @noble/post-quantum in the
    browser/extension MUST verify here (committed fixture), and both libraries
    derive the SAME public key from the same 32-byte seed.
  * The server JWT path: create_access_token -> decode_access_token round-trip,
    tamper rejection, wrong-secret rejection, and the HS256 header. (JWTs are
    classical HS256 via PyJWT; only the login challenge below needs PQC.)
  * The login-challenge verifier verify_signature against a real client key.

The matching browser/extension half lives in frontend/src/test/pqc.test.js,
which verifies the OpenSSL-produced fixture signature under noble. Together they
prove the noble <-> OpenSSL ML-DSA-44 encodings are wire-compatible (the one
thing the migration plan says to prove, not assume).

The same-seed check is stronger than it was under liboqs, which derived its key
from the seed differently and so could only be compared signature by signature:
OpenSSL and noble both implement FIPS 204 KeyGen_internal(xi) directly, so any
divergence in key expansion or encoding shows up as different bytes here.

Full NIST KAT coverage is provided upstream by each library's own CI (OpenSSL
runs the ACVP vectors; noble ships them). This gate pins the integration:
sizes, interop, round-trips, and a deterministic seeded-keygen anchor.
"""

import base64
import hashlib
import json
import os

import jwt
import pytest
from conftest import MLDSA44Signer
from cryptography.hazmat.primitives.asymmetric import mldsa

import auth
from security.crypto_validation import ML_DSA_44_PUBLIC_KEY_HEX_LEN

FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "fixtures", "pqc_interop.json"
)


def _sig_b64(raw: bytes) -> str:
    """A signature as the clients send it: base64 since the L-12 cutover.
    Public keys stay hex — they are identifiers, not payloads."""
    return base64.b64encode(raw).decode()


@pytest.fixture(scope="module")
def vec():
    with open(FIXTURE) as f:
        return json.load(f)


def test_ml_dsa_sizes_match_fips204():
    key = mldsa.MLDSA44PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    assert len(public) == 1312
    assert len(public) * 2 == ML_DSA_44_PUBLIC_KEY_HEX_LEN
    assert len(key.sign(b"size")) == 2420
    # pyca keeps the 32-byte seed, not the 2 560-byte expanded key noble stores.
    assert len(key.private_bytes_raw()) == 32


def test_server_verifier_roundtrip_and_tamper():
    signer = MLDSA44Signer()
    pk = bytes.fromhex(signer.address)
    msg = b"round-trip message"
    sig = signer.sign(msg)
    assert auth._verify_ml_dsa44(pk, msg, sig) is True
    # tampered message must fail
    assert auth._verify_ml_dsa44(pk, b"round-trip messagX", sig) is False
    # tampered signature must fail
    bad = bytearray(sig)
    bad[0] ^= 0x01
    assert auth._verify_ml_dsa44(pk, msg, bytes(bad)) is False


def test_a_signature_under_a_context_is_not_a_signature_without_one():
    """The server verifies with the EMPTY FIPS 204 context, which is what noble
    signs with by default. Were the two ever to disagree, every login would
    fail — this pins that the context is part of what is verified at all."""
    key = mldsa.MLDSA44PrivateKey.generate()
    pk = key.public_key().public_bytes_raw()
    assert auth._verify_ml_dsa44(pk, b"m", key.sign(b"m", context=b"ctx")) is False


def test_interop_noble_signature_verifies_on_the_server(vec):
    """noble (browser/extension) -> OpenSSL (server). The critical wire path."""
    pk = bytes.fromhex(vec["noble_dsa_publicKey"])
    sig = bytes.fromhex(vec["noble_dsa_signature"])
    msg = bytes.fromhex(vec["message"])
    assert auth._verify_ml_dsa44(pk, msg, sig) is True
    # wrong message must not verify against the noble signature
    assert auth._verify_ml_dsa44(pk, msg + b"!", sig) is False


def test_interop_openssl_signature_in_the_fixture_is_genuine(vec):
    """The OpenSSL half of the fixture, which the Node side verifies under
    noble, must itself verify here — otherwise that test proves nothing."""
    pk = bytes.fromhex(vec["noble_dsa_publicKey"])
    sig = bytes.fromhex(vec["openssl_dsa_signature"])
    assert auth._verify_ml_dsa44(pk, bytes.fromhex(vec["message"]), sig) is True


def test_same_seed_same_public_key_as_noble(vec):
    """FIPS 204 KeyGen(xi): one seed is one key in every conforming library.
    Pins both the committed fixture and crypto-core's own golden seeded key
    (byte-compat.test.js, `new Uint8Array(32).fill(7)`)."""

    def public_from_seed(seed: bytes) -> bytes:
        key = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed)
        return key.public_key().public_bytes_raw()

    assert public_from_seed(bytes.fromhex(vec["ml_dsa_seed"])).hex() == vec["noble_dsa_publicKey"]
    assert (
        hashlib.sha256(public_from_seed(bytes([7] * 32))).hexdigest()
        == "86c769d3b468de487eb9a09f242f7fa0b997a07ef4ded49627e7bf9539f28b62"
    )


def test_the_server_refuses_to_start_without_ml_dsa():
    """What `build_liboqs.sh --check` used to do in serve.sh: a cryptography
    built against an OpenSSL without ML-DSA (< 3.5) must stop the import, not
    fail every login at runtime. Simulated in a subprocess, since `auth` is
    already imported here and reloading it would reset its module state."""
    import subprocess
    import sys

    code = (
        "from cryptography.exceptions import UnsupportedAlgorithm\n"
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "def refuse(*a):\n"
        "    raise UnsupportedAlgorithm('no ML-DSA in this OpenSSL')\n"
        "mldsa.MLDSA44PrivateKey.generate = staticmethod(refuse)\n"
        "import auth\n"
    )
    backend = os.path.join(os.path.dirname(__file__), "..")
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=backend, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "cryptography lacks ML-DSA-44" in result.stderr


def test_noble_seeded_keygen_pin_sizes(vec):
    """Encoding regression anchor: the committed seeded-keygen public keys keep
    the FIPS sizes (full byte-pin lives in the Node half which owns the seed)."""
    assert len(bytes.fromhex(vec["noble_dsa_publicKey"])) == 1312
    assert len(bytes.fromhex(vec["noble_kem_publicKey"])) == 1184


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


# What every 3.0.0 login names (crypto-core 3.0.0, audit 2026-10-12 K-02).
SERVER = {"origin": "https://kryptolog.example", "deployment": "dep-1"}


def _verify(pk_hex, sig_b64, nonce, enc_key=None, **server):
    return auth.verify_pqc_signature(
        pk_hex, sig_b64, nonce=nonce, encryption_public_key=enc_key, **{**SERVER, **server}
    )


def test_login_challenge_real_verification():
    """The PQC login-challenge verifier accepts a genuine ML-DSA-44 client
    signature over the exact login message, and rejects a bad nonce.

    Calls verify_pqc_signature directly: the autouse conftest fixture stubs the
    higher-level verify_signature, but the PQC primitive underneath is real."""
    nonce = auth.generate_nonce()
    message = auth._login_message(nonce, **SERVER).encode("utf-8")
    client = MLDSA44Signer()
    pk_hex, sig_b64 = client.address, _sig_b64(client.sign(message))

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
    client = MLDSA44Signer()
    pk_hex, sig_b64 = client.address, _sig_b64(client.sign(message))
    assert _verify(pk_hex, sig_b64, nonce) is True
    assert _verify(pk_hex, sig_b64, nonce, origin="https://evil.example") is False
    assert _verify(pk_hex, sig_b64, nonce, deployment="other") is False


def test_login_challenge_binds_encryption_key():
    """M-2: when an encryption (ML-KEM) key is supplied it is folded into the
    signed challenge, so a signature is valid only for the exact key it covers —
    a network attacker can't substitute a different KEM key at login."""
    nonce = auth.generate_nonce()
    enc_key = "ab" * 1184
    message = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER).encode("utf-8")
    client = MLDSA44Signer()
    pk_hex, sig_b64 = client.address, _sig_b64(client.sign(message))

    # Valid only with the exact bound key.
    assert _verify(pk_hex, sig_b64, nonce, enc_key) is True
    # Substituting a different encryption key fails (the binding holds).
    assert _verify(pk_hex, sig_b64, nonce, "cd" * 1184) is False
    # Dropping the key (downgrade attempt) also fails — the signature covers it.
    assert _verify(pk_hex, sig_b64, nonce, None) is False


def test_login_challenge_is_domain_separated():
    """H1: the login challenge is wrapped under the `login` domain tag, so the
    signed bytes are disjoint from any content-signing operation (multisig /
    document approval). The wrapper is fixed by code, never by content."""
    nonce = "deadbeef" * 4
    enc_key = "cd" * 1184
    msg = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER)
    assert msg.startswith("Kryptolog Signed Message v1\ncontext=login\nSign in to Kryptolog\n")
    assert f"\nnonce={nonce}\n" in msg
    assert msg.endswith(f"\nencryption-key={enc_key}")


def test_content_signature_cannot_be_replayed_as_login():
    """H1 regression / the actual attack: a signature a victim produced while
    approving attacker-chosen *content* must NOT verify as a login challenge,
    even when the attacker set that content equal to the raw login body."""
    nonce = auth.generate_nonce()
    enc_key = "ef" * 1184

    # The login body without its domain header — what an attacker would coerce
    # a victim into signing as raw or content-wrapped multisig content.
    full = auth._login_message(nonce, encryption_public_key=enc_key, **SERVER)
    raw_login_body = full.split("\ncontext=login\n", 1)[1]
    content_wrapped = f"Kryptolog Signed Message v1\ncontext=content\n{raw_login_body}"

    client = MLDSA44Signer()
    sig_raw = _sig_b64(client.sign(raw_login_body.encode("utf-8")))
    sig_content = _sig_b64(client.sign(content_wrapped.encode("utf-8")))
    pk_hex = client.address

    # Neither harvested signature is accepted as a login for this nonce+key.
    assert _verify(pk_hex, sig_raw, nonce, enc_key) is False
    assert _verify(pk_hex, sig_content, nonce, enc_key) is False

    # Sanity: a signature over the properly domain-separated challenge (what
    # the real client builds) still verifies — we didn't break login.
    client2 = MLDSA44Signer()
    good_sig = _sig_b64(client2.sign(full.encode("utf-8")))
    assert _verify(client2.address, good_sig, nonce, enc_key) is True


def test_multisig_approval_message_is_domain_separated():
    """M1: the multisig approval is bound to workflow + secret + ciphertext hash
    and namespaced under `multisig-approval`, disjoint from login and content."""
    msg = auth.multisig_approval_message(7, 42, "ab" * 32)
    assert msg.startswith("Kryptolog Signed Message v1\ncontext=multisig-approval\n")
    assert "workflow=7" in msg and "secret=42" in msg and f"ct={'ab' * 32}" in msg
    # Disjoint from a login message and a content message over the same body.
    body = "workflow=7\nsecret=42\nct=" + "ab" * 32
    assert msg != auth._domain_separate("login", body)
    assert msg != auth._domain_separate("content", body)


# Captured at import time, before the autouse conftest fixture can stub it —
# this unit test exercises the REAL verifier (the endpoint tests use the stub).
_real_verify_identity_signature = auth.verify_identity_signature


def test_verify_identity_signature_pqc():
    """M1: the generic verifier accepts a real ML-DSA-44 signature over the exact
    multisig approval message and rejects tampering, wrong key, and bad hex —
    this is what the /sign endpoint relies on to gate `has_signed`."""
    verify = _real_verify_identity_signature
    ct_hash = hashlib_sha256_hex("encrypted_payload")
    msg = auth.multisig_approval_message(1, 1, ct_hash)
    signer = MLDSA44Signer()
    pk_hex, sig_b64 = signer.address, _sig_b64(signer.sign(msg.encode("utf-8")))

    assert verify(pk_hex, msg, sig_b64) is True
    # Wrong message (e.g. a different ciphertext hash) → reject.
    other = auth.multisig_approval_message(1, 1, hashlib_sha256_hex("tampered"))
    assert verify(pk_hex, other, sig_b64) is False
    # Wrong signer key → reject.
    other_pk = MLDSA44Signer().address
    assert verify(other_pk, msg, sig_b64) is False
    # Malformed signature → false, not an exception.
    assert verify(pk_hex, msg, "not-base64!") is False


def hashlib_sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
