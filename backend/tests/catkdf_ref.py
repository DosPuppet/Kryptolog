"""ETSI TS 103 744 V1.2.2 CatKDF, parameter set HKDFwSHA384_P384_ML-KEM-768,
static recipient keys (§8.2.2) — written from the standard for the test suite
only (it replaced xwing_ref.py, crypto-core 5.0.0).

The server never runs a KEM: every encapsulation and decapsulation is a
client's, in @noble/post-quantum and @noble/curves. This exists so the
standard's known-answer test and what noble produces are checked against a
SECOND implementation on a different library — OpenSSL's ML-KEM-768, P-384 and
HKDF (lot 12c). The composition must match crypto-core's kem.js exactly:

    secret key   P-384 scalar (48) || ML-KEM-768 seed d||z (64)
    public key   P1 = P-384 point, SEC1 uncompressed (97) || P2 = ML-KEM ek (1184)
    ciphertext   R1 = ephemeral P-384 point (97)          || R2 = ML-KEM ct (1088)
    key          CatKDF(k1 = ECDH x (48), k2 = ML-KEM secret (32),
                        MA = m_format(cid, "", P1, P2), MB = m_format(cid, "", R1, R2),
                        info = "Kryptolog/<suite>/AES-GCM/v5", label = "", 32)
"""

import hashlib
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUITE = "HKDFwSHA384_P384_ML-KEM-768_CatKDF"
CID = bytes([0x22, 0x21])
INFO = f"Kryptolog/{SUITE}/AES-GCM/v5".encode()
_POINT = 97
_SCALAR = 48


def _length_prefixed(*values: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(v)) + v for v in values)


def etsi_message(cid: bytes, *values: bytes) -> bytes:
    """Annex C m_format: cid || [len]32 || val1 || [len]32 || val2 ..."""
    return cid + _length_prefixed(*values)


def etsi_context_sha384(*values: bytes) -> bytes:
    """§7.2.3 cahb_f with SHA-384."""
    return hashlib.sha384(_length_prefixed(*values)).digest()


def catkdf(*, k1, k2, ma, mb, info=b"", label=b"", psk=b"", length) -> bytes:
    """§8.2.3 with the §7.4.2 mapping: HKDF(psk||k1||k2, salt=label,
    info=cahb_f(info, MA, MB), length). pyca takes salt=None for "absent",
    which RFC 5869 makes HashLen zeros — the same HMAC key as an empty one."""
    return HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=label or None,
        info=etsi_context_sha384(info, ma, mb),
    ).derive(psk + k1 + k2)


def _point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def _halves(secret_key: bytes):
    assert len(secret_key) == _SCALAR + 64
    scalar = ec.derive_private_key(int.from_bytes(secret_key[:_SCALAR], "big"), ec.SECP384R1())
    return scalar, MLKEM768PrivateKey.from_seed_bytes(secret_key[_SCALAR:])


def _peer(point: bytes) -> ec.EllipticCurvePublicKey:
    assert len(point) == _POINT and point[0] == 0x04
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), point)


def _key(p1, p2, r1, r2, k1, k2) -> bytes:
    return catkdf(
        k1=k1,
        k2=k2,
        ma=etsi_message(CID, b"", p1, p2),
        mb=etsi_message(CID, b"", r1, r2),
        info=INFO,
        length=32,
    )


def public_key(secret_key: bytes) -> bytes:
    scalar, ml = _halves(secret_key)
    return _point(scalar.public_key()) + ml.public_key().public_bytes_raw()


def decapsulate(cipher_text: bytes, secret_key: bytes) -> bytes:
    scalar, ml = _halves(secret_key)
    r1, r2 = cipher_text[:_POINT], cipher_text[_POINT:]
    k1 = scalar.exchange(ec.ECDH(), _peer(r1))  # the fixed-length x coordinate
    k2 = ml.decapsulate(r2)
    return _key(_point(scalar.public_key()), ml.public_key().public_bytes_raw(), r1, r2, k1, k2)


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """`(cipher_text, key)`. OpenSSL draws both halves' randomness itself, so
    this cannot reproduce noble's ciphertexts; decapsulating them is what pins
    the two against each other."""
    p1, p2 = public_key[:_POINT], public_key[_POINT:]
    ephemeral = ec.generate_private_key(ec.SECP384R1())
    k1 = ephemeral.exchange(ec.ECDH(), _peer(p1))
    k2, r2 = MLKEM768PublicKey.from_public_bytes(p2).encapsulate()
    r1 = _point(ephemeral.public_key())
    return r1 + r2, _key(p1, p2, r1, r2, k1, k2)
