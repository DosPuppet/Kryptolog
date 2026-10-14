"""Format validation for key material, addresses and signatures (crypto-core 5).

KRY-011: capability checks were written as `len(key) < 500`, which a run of
600 arbitrary characters satisfies. The real security boundary is elsewhere
(signature verification in auth.py), so this was never directly exploitable —
but a length floor is a poor proxy for "this is a public key", it makes the
invariant unauditable, and it lets malformed keys reach storage where they
surface later as confusing failures. Every check here is exact.

crypto-core 5.0.0 is hybrid throughout (audit 2026-10-12 K-10), and every
component is in the ECCG Agreed Cryptographic Mechanisms v2 (lot 12):
    identity key    composite ML-DSA-65 + ECDSA-P384        2049 bytes -> 4098 hex
    address         SHA-384 of the identity key               48 bytes ->   96 hex
    encryption key  CatKDF, P-384 point || ML-KEM-768 key   1281 bytes -> 2562 hex
    key id          SHA-384 of the encryption key, cut        16 bytes ->   32 hex
    signature       composite (DER half varies)        3317..3413 bytes -> <= 4552 base64

Unlike their 4.x predecessors, both kinds of key can be checked for BEING
keys, and are: P-384 has cofactor 1, so a point is valid iff it is on the
curve (no subgroup to test — the pure-Python Ed25519 subgroup check this
module used to lean on is gone with Ed25519), and ML-KEM-768's encapsulation
key has FIPS 203's modulus check, which OpenSSL runs when the key is loaded.

Two encodings, on purpose (audit L-12). Keys, key ids and addresses are
IDENTIFIERS — an address is a primary key and a URL path segment, and the
project normalizes addresses to lowercase everywhere, which would not survive
a case-sensitive encoding. Signatures are opaque payloads and are base64 with
the rest of them.

These are the only places the server answers "what is an address" and "what
does a key look like"; identity.js and pqc.js in crypto-core are the client's
half and the two must agree (tests/fixtures/hybrid_interop.json pins a golden
address).
"""

import base64
import hashlib
import json
import re

from cryptography.hazmat.primitives.asymmetric import ec, mlkem

# The suites in use, by registry id — the names crypto-core's pqc.js spells
# SIGNATURE_ALG and KEM_ALG. Both are in the prefixes below, so a change of
# either changes every address and key id, deliberately.
FORMAT_VERSION = 5
SIGNATURE_ALG = "MLDSA65-ECDSA-P384-SHA512"
KEM_ALG = "HKDFwSHA384_P384_ML-KEM-768_CatKDF"
# What a KEM envelope's `alg` says: the suite, then the AEAD (crypto-core's
# KEM_ENVELOPE_ALG).
KEM_ENVELOPE_ALG = f"{KEM_ALG}-A256GCM"

# Byte lengths.
_ML_DSA_65_PUBLIC_KEY_BYTES = 1952
_ML_DSA_65_SIGNATURE_BYTES = 3309
P384_POINT_BYTES = 97  # SEC1 uncompressed: 0x04 || x || y
_ML_KEM_768_KEY_BYTES = 1184
IDENTITY_KEY_BYTES = _ML_DSA_65_PUBLIC_KEY_BYTES + P384_POINT_BYTES
ENCRYPTION_KEY_BYTES = 97 + _ML_KEM_768_KEY_BYTES  # P-384 point || ML-KEM-768 encapsulation key
# A composite signature: ML-DSA-65 then a DER Ecdsa-Sig-Value of 8..104 bytes.
SIGNATURE_MIN_BYTES = _ML_DSA_65_SIGNATURE_BYTES + 8
SIGNATURE_MAX_BYTES = _ML_DSA_65_SIGNATURE_BYTES + 104
ADDRESS_BYTES = 48
KEY_ID_BYTES = 16

# Hex lengths for the identifiers.
IDENTITY_KEY_HEX_LEN = IDENTITY_KEY_BYTES * 2
ENCRYPTION_KEY_HEX_LEN = ENCRYPTION_KEY_BYTES * 2
ADDRESS_HEX_LEN = ADDRESS_BYTES * 2
KEY_ID_HEX_LEN = KEY_ID_BYTES * 2
# Base64 length for the largest signature: 4 chars per 3 bytes, padded.
SIGNATURE_MAX_B64_LEN = ((SIGNATURE_MAX_BYTES + 2) // 3) * 4


def _lowercase_hex(length: int) -> re.Pattern:
    # One spelling only: lowercase, no whitespace (which `bytes.fromhex`
    # skips). An identifier with two spellings is the L-12 defect again.
    return re.compile(rf"^[0-9a-f]{{{length}}}$")


_ADDRESS_RE = _lowercase_hex(ADDRESS_HEX_LEN)
_IDENTITY_KEY_RE = _lowercase_hex(IDENTITY_KEY_HEX_LEN)
_ENCRYPTION_KEY_RE = _lowercase_hex(ENCRYPTION_KEY_HEX_LEN)
_KEY_ID_RE = _lowercase_hex(KEY_ID_HEX_LEN)


def is_hex(value: str) -> bool:
    """True if `value` is non-empty, even-length, pure hex."""
    if not value or len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def is_b64(value: str | None) -> bool:
    """True if `value` is non-empty, padded, CANONICAL standard base64.

    Canonical matters beyond tidiness, and it is why this is not just a
    `b64decode(validate=True)` call: that accepts a value whose unused trailing
    bits are set, so the same bytes have more than one valid spelling. A message
    signature commits to its ciphertext in STRING form, so a second spelling
    would be a second validly-signed form of one ciphertext. Mirrors fromB64()
    in packages/crypto-core/src/encoding.js — the two must agree.
    """
    if not value or not isinstance(value, str):
        return False
    if len(value) % 4 != 0 or not _B64_RE.match(value):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return False
    # Re-encoding is the cheapest exact canonical-form check in Python.
    return base64.b64encode(decoded).decode() == value


def is_valid_b64_of_length(value: str | None, b64_len: int) -> bool:
    """True if `value` is canonical base64 of exactly `b64_len` characters."""
    if not value or not isinstance(value, str):
        return False
    if len(value) != b64_len:
        return False
    return is_b64(value)


def is_valid_signature(value: str | None) -> bool:
    """True if `value` is canonical base64 of a composite signature's size.

    By decoded BYTES, not characters: base64 pads to a multiple of four, so a
    check on the length alone would accept a signature with a byte appended.
    The size varies with the DER half (crypto-core 5.0.0); whether the bytes
    ARE a signature is verification's question, not this one's.
    """
    if not isinstance(value, str) or len(value) > SIGNATURE_MAX_B64_LEN or not is_b64(value):
        return False
    return SIGNATURE_MIN_BYTES <= len(base64.b64decode(value)) <= SIGNATURE_MAX_BYTES


def is_valid_p384_point(point: bytes) -> bool:
    """True if `point` is a SEC1 UNCOMPRESSED P-384 point on the curve. The
    compressed form is refused although OpenSSL would decode it: the clients
    write one encoding, and an identifier with two is the L-12 defect again.
    The point at infinity has no uncompressed encoding."""
    if len(point) != P384_POINT_BYTES or point[0] != 0x04:
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), point)
    except ValueError:
        return False
    return True


def is_valid_encryption_key(value: str | None) -> bool:
    """True if `value` is a lowercase-hex CatKDF key, P-384 point || ML-KEM-768
    encapsulation key, with a point on the curve and an encapsulation key that
    passes FIPS 203's modulus check.

    The attestation still decides WHOSE key it is; this decides that it IS a
    key, which X-Wing's structural check could not (its X25519 half accepted
    any 32 bytes) — a malformed key no longer reaches the directory, where
    every sender would fail on it one at a time.
    """
    if not isinstance(value, str) or not _ENCRYPTION_KEY_RE.match(value):
        return False
    raw = bytes.fromhex(value)
    if not is_valid_p384_point(raw[:P384_POINT_BYTES]):
        return False
    try:
        # OpenSSL runs the modulus check on load (its message on failure talks
        # about the LENGTH, misleadingly; test_hybrid_primitives pins the case).
        mlkem.MLKEM768PublicKey.from_public_bytes(raw[P384_POINT_BYTES:])
    except ValueError:
        return False
    return True


# --- Encryption key ids (crypto-core 5.0.0) ---
# Byte-identical to crypto-core's encryptionKeyId: the first 16 bytes of
# SHA-384 over the key under a prefix naming the format and the suite. Every
# KEM envelope carries the id of the key it was sealed to, which is what lets
# an account keep retired keys and read with the right one.
_KEY_ID_DOMAIN = f"Kryptolog encryption key id v{FORMAT_VERSION}\nalg={KEM_ALG}\n".encode()


def encryption_key_id(encryption_public_key: str) -> str:
    """The id of an encryption public key (lowercase hex). Raises ValueError
    for anything that is not one's hex spelling."""
    if not isinstance(encryption_public_key, str) or not _ENCRYPTION_KEY_RE.match(
        encryption_public_key
    ):
        raise ValueError(
            f"an encryption public key is {ENCRYPTION_KEY_HEX_LEN} lowercase hex characters"
        )
    digest = hashlib.sha384(_KEY_ID_DOMAIN + bytes.fromhex(encryption_public_key)).hexdigest()
    return digest[:KEY_ID_HEX_LEN]


def is_valid_key_id(value: str | None) -> bool:
    """True if `value` is shaped like a key id: 32 lowercase hex characters."""
    return isinstance(value, str) and _KEY_ID_RE.match(value) is not None


# --- Addresses and the keys they name (crypto-core 3.3.0 seam, 5.0.0 meaning) -

# The address of a composite identity key: SHA-384 under a prefix that names
# the version and the algorithm. Byte-identical to crypto-core's addressOf.
_ADDRESS_DOMAIN = f"Kryptolog address v{FORMAT_VERSION}\nalg={SIGNATURE_ALG}\n".encode()


def is_valid_address(value: str | None) -> bool:
    """True if `value` is shaped like an address: 96 lowercase hex characters."""
    return isinstance(value, str) and _ADDRESS_RE.match(value) is not None


def address_of(identity_public_key: str) -> str:
    """The address an identity public key (lowercase hex) is known by. Raises
    ValueError for anything that is not one."""
    if not isinstance(identity_public_key, str) or not _IDENTITY_KEY_RE.match(identity_public_key):
        raise ValueError(
            f"an identity public key is {IDENTITY_KEY_HEX_LEN} lowercase hex characters"
        )
    return hashlib.sha384(_ADDRESS_DOMAIN + bytes.fromhex(identity_public_key)).hexdigest()


def identity_binds_address(identity_public_key: str | None, address: str | None) -> bool:
    """Is `identity_public_key` the key `address` names? Never raises."""
    try:
        return is_valid_address(address) and address_of(identity_public_key) == address
    except ValueError:
        return False


def is_valid_identity_key(value: str | None) -> bool:
    """True if `value` is a lowercase-hex composite ML-DSA-65 + ECDSA-P384 key
    whose P-384 half is a point on the curve.

    Checked where a key enters — the login route — so every stored key
    satisfies it. Nothing to check in the ML-DSA-65 half beyond its length:
    FIPS 204's pkDecode cannot fail on 1952 bytes (rho is any 32 bytes, t1 any
    packed 10-bit values), and OpenSSL accepts every such key.
    """
    if not isinstance(value, str) or not _IDENTITY_KEY_RE.match(value):
        return False
    return is_valid_p384_point(bytes.fromhex(value)[_ML_DSA_65_PUBLIC_KEY_BYTES:])


# A key held for someone, sealed by crypto-core's kemSeal, in either of the two
# shapes the clients store: a wrapped session key {v, alg, kid, kem, iv,
# encKey} — 32 key bytes plus the 16-byte tag — or a KEM message envelope
# {v, alg, kid, kem, iv, content} around a content key (what a secret's grant
# and a workflow's signer and recipient rows hold). The CatKDF ciphertext and
# the IV have exact sizes either way.
_KEM_ENVELOPE_FIELDS = {"v", "alg", "kid", "kem", "iv"}
_KEM_ENVELOPE_SIZES = {"kem": 97 + 1088, "iv": 12}
_WRAPPED_SESSION_KEY_BYTES = 32 + 16


def is_wrapped_key_for(value: str | None, kid: str | None) -> bool:
    """True if `value` is a current-format KEM envelope sealed to the key `kid`.

    The server cannot open one — that is the point — so this is the whole of
    what it can check: the shape, the format, and that the envelope NAMES the
    key it should. One that lies about its kid fails its AES-GCM tag for the
    holder, who is the only one it hurts.
    """
    if not isinstance(value, str) or not is_valid_key_id(kid):
        return False
    try:
        wrap = json.loads(value)
    except ValueError:
        return False
    if not isinstance(wrap, dict):
        return False
    extra = set(wrap) - _KEM_ENVELOPE_FIELDS
    if not _KEM_ENVELOPE_FIELDS <= set(wrap) or extra not in ({"encKey"}, {"content"}):
        return False
    if wrap["v"] != FORMAT_VERSION or wrap["alg"] != KEM_ENVELOPE_ALG or wrap["kid"] != kid:
        return False
    for field, size in _KEM_ENVELOPE_SIZES.items():
        if not is_b64(wrap[field]) or len(base64.b64decode(wrap[field])) != size:
            return False
    (field,) = extra
    if not is_b64(wrap[field]):
        return False
    sealed = len(base64.b64decode(wrap[field]))
    return sealed == _WRAPPED_SESSION_KEY_BYTES if field == "encKey" else sealed > 16


def wrapped_key_id(value: str | None) -> str | None:
    """The kid a stored wrapped key names, or None for anything unreadable."""
    try:
        wrap = json.loads(value) if isinstance(value, str) else None
    except ValueError:
        return None
    kid = wrap.get("kid") if isinstance(wrap, dict) else None
    return kid if is_valid_key_id(kid) else None
