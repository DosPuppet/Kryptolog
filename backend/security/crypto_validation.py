"""Format validation for key material, addresses and signatures (crypto-core 4).

KRY-011: capability checks were written as `len(key) < 500`, which a run of
600 arbitrary characters satisfies. The real security boundary is elsewhere
(signature verification in auth.py), so this was never directly exploitable —
but a length floor is a poor proxy for "this is a public key", it makes the
invariant unauditable, and it lets malformed keys reach storage where they
surface later as confusing failures. Every check here is exact.

crypto-core 4.0.0 is hybrid throughout (audit 2026-10-12 K-10):
    identity key    composite ML-DSA-65 + Ed25519   1984 bytes -> 3968 hex
    address         SHA-384 of the identity key       48 bytes ->   96 hex
    encryption key  X-Wing (ML-KEM-768 + X25519)    1216 bytes -> 2432 hex
    signature       composite                       3373 bytes -> 4500 base64

Two encodings, on purpose (audit L-12). Keys and addresses are IDENTIFIERS —
an address is a primary key and a URL path segment, and the project
normalizes addresses to lowercase everywhere, which would not survive a
case-sensitive encoding. Signatures are opaque payloads and are base64 with
the rest of them.

These are the only places the server answers "what is an address" and "what
does a key look like"; identity.js in crypto-core is the client's half and
the two must agree (tests/fixtures/hybrid_interop.json pins a golden address).
"""

import base64
import hashlib
import re

from security.ed25519_subgroup import in_prime_order_subgroup

# Byte lengths.
_ML_DSA_65_PUBLIC_KEY_BYTES = 1952
IDENTITY_KEY_BYTES = _ML_DSA_65_PUBLIC_KEY_BYTES + 32
ENCRYPTION_KEY_BYTES = 1216
SIGNATURE_BYTES = 3309 + 64
ADDRESS_BYTES = 48

# Hex lengths for the identifiers.
IDENTITY_KEY_HEX_LEN = IDENTITY_KEY_BYTES * 2
ENCRYPTION_KEY_HEX_LEN = ENCRYPTION_KEY_BYTES * 2
ADDRESS_HEX_LEN = ADDRESS_BYTES * 2
# Base64 length for the payload: 4 chars per 3 bytes, padded.
SIGNATURE_B64_LEN = ((SIGNATURE_BYTES + 2) // 3) * 4


def _lowercase_hex(length: int) -> re.Pattern:
    # One spelling only: lowercase, no whitespace (which `bytes.fromhex`
    # skips). An identifier with two spellings is the L-12 defect again.
    return re.compile(rf"^[0-9a-f]{{{length}}}$")


_ADDRESS_RE = _lowercase_hex(ADDRESS_HEX_LEN)
_IDENTITY_KEY_RE = _lowercase_hex(IDENTITY_KEY_HEX_LEN)
_ENCRYPTION_KEY_RE = _lowercase_hex(ENCRYPTION_KEY_HEX_LEN)


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
    """True if `value` is canonical base64 of exactly one composite signature.

    By decoded BYTES, not characters: base64 pads to a multiple of four, so
    3 373 and 3 374 bytes both spell 4 500 characters, and a check on the
    length alone accepts a signature with a byte appended.
    """
    return (
        is_valid_b64_of_length(value, SIGNATURE_B64_LEN)
        and len(base64.b64decode(value)) == SIGNATURE_BYTES
    )


def is_valid_encryption_key(value: str | None) -> bool:
    """True if `value` is a lowercase-hex X-Wing public key.

    Structural only — and that is the ceiling, not an omission. Its ML-KEM-768
    half has one cheap validity predicate, the FIPS 203 modulus check, and 1184
    bytes of `AA` pass it; any 32 bytes are an X25519 key. What binds a key to
    an identity is the key attestation, which the login route verifies.
    """
    return isinstance(value, str) and _ENCRYPTION_KEY_RE.match(value) is not None


# --- Addresses and the keys they name (crypto-core 3.3.0 seam, 4.0.0 meaning) -

# The address of a composite identity key: SHA-384 under a prefix that names
# the version and the algorithm. Byte-identical to crypto-core's addressOf.
_ADDRESS_DOMAIN = b"Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n"


def is_valid_address(value: str | None) -> bool:
    """True if `value` is shaped like an address: 96 lowercase hex characters."""
    return isinstance(value, str) and _ADDRESS_RE.match(value) is not None


def address_of(identity_public_key: str) -> str:
    """The address an identity public key (lowercase hex) is known by. Raises
    ValueError for anything that is not one."""
    if not isinstance(identity_public_key, str) or not _IDENTITY_KEY_RE.match(identity_public_key):
        raise ValueError("an identity public key is 3968 lowercase hex characters")
    return hashlib.sha384(_ADDRESS_DOMAIN + bytes.fromhex(identity_public_key)).hexdigest()


def identity_binds_address(identity_public_key: str | None, address: str | None) -> bool:
    """Is `identity_public_key` the key `address` names? Never raises."""
    try:
        return is_valid_address(address) and address_of(identity_public_key) == address
    except ValueError:
        return False


def is_valid_identity_key(value: str | None) -> bool:
    """True if `value` is a lowercase-hex composite key whose Ed25519 half is
    a point of order exactly L.

    The second condition is what lets the server verify with OpenSSL alone:
    with such a key, OpenSSL's cofactorless Ed25519 rule and the clients'
    stricter one accept the same signatures (see security/ed25519_subgroup.py).
    Checked once, where a key enters — the login route — so every stored key
    satisfies it.
    """
    if not isinstance(value, str) or not _IDENTITY_KEY_RE.match(value):
        return False
    # Nothing to check in the ML-DSA-65 half beyond its length: FIPS 204's
    # pkDecode cannot fail on 1952 bytes (rho is any 32 bytes, t1 any packed
    # 10-bit values), and OpenSSL accepts every such key.
    return in_prime_order_subgroup(bytes.fromhex(value)[_ML_DSA_65_PUBLIC_KEY_BYTES:])
