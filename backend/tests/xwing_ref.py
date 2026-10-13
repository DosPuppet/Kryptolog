"""X-Wing (draft-connolly-cfrg-xwing-kem-10), written from the draft for the
test suite only.

The server never runs a KEM: every encapsulation and decapsulation is a
client's, in @noble/post-quantum. This exists so the draft's vectors and what
noble produces are checked against a SECOND implementation on a different
library — OpenSSL's ML-KEM-768 and X25519 — the way the composite signature
is checked against OpenSSL's ML-DSA-65 and Ed25519 (audit 2026-10-12 K-10).
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# The draft's domain-separation label, the six bytes \.//^\ .
LABEL = bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])
_ML_KEM_PK = 1184
_ML_KEM_CT = 1088


def _expand(secret_key: bytes):
    """The 32-byte secret key is a seed: SHAKE256 to 96 bytes, the first 64
    of them ML-KEM's (d || z) seed, the last 32 the X25519 secret."""
    assert len(secret_key) == 32
    expanded = hashlib.shake_256(secret_key).digest(96)
    return (
        MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
        X25519PrivateKey.from_private_bytes(expanded[64:]),
    )


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


def public_key(secret_key: bytes) -> bytes:
    ml, x = _expand(secret_key)
    return ml.public_key().public_bytes_raw() + x.public_key().public_bytes_raw()


def decapsulate(cipher_text: bytes, secret_key: bytes) -> bytes:
    ml, x = _expand(secret_key)
    ct_m, ct_x = cipher_text[:_ML_KEM_CT], cipher_text[_ML_KEM_CT:]
    ss_x = x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    return _combine(ml.decapsulate(ct_m), ss_x, ct_x, x.public_key().public_bytes_raw())


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """`(cipher_text, shared_secret)`. OpenSSL draws ML-KEM's coins itself —
    pyca exposes no derandomized encapsulation — so this cannot reproduce the
    draft's encapsulation vectors; decapsulation of them is what pins it."""
    pk_m, pk_x = public_key[:_ML_KEM_PK], public_key[_ML_KEM_PK:]
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    ephemeral = X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    ss_x = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk_x))
    return ct_m + ct_x, _combine(ss_m, ss_x, ct_x, pk_x)
