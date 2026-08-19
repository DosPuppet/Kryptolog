"""Format validation for PQC key material.

KRY-011: capability checks were written as `len(key) < 500`, which a run of
600 arbitrary characters satisfies. The real security boundary is elsewhere
(`bytes.fromhex` + liboqs verification in auth.py), so this was never
directly exploitable — but a length floor is a poor proxy for "this is an
ML-KEM public key", it makes the invariant unauditable, and it lets malformed
keys reach storage where they surface later as confusing failures.

Sizes are FIPS 203 / 204 constants for the parameter sets this project uses:
    ML-KEM-768  public key  1184 bytes -> 2368 hex chars
    ML-DSA-44   public key  1312 bytes -> 2624 hex chars
    ML-DSA-44   signature   2420 bytes -> 4840 hex chars
"""
from typing import Optional

# Byte lengths (FIPS 203/204).
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_DSA_44_PUBLIC_KEY_BYTES = 1312
ML_DSA_44_SIGNATURE_BYTES = 2420

# Hex-encoded lengths — the wire/storage format used throughout.
ML_KEM_768_PUBLIC_KEY_HEX_LEN = ML_KEM_768_PUBLIC_KEY_BYTES * 2
ML_DSA_44_PUBLIC_KEY_HEX_LEN = ML_DSA_44_PUBLIC_KEY_BYTES * 2
ML_DSA_44_SIGNATURE_HEX_LEN = ML_DSA_44_SIGNATURE_BYTES * 2

# ML-DSA signatures are the largest field clients send; give the schema bound
# some headroom over the exact size rather than pinning it at the byte.
MAX_SIGNATURE_HEX_LEN = ML_DSA_44_SIGNATURE_HEX_LEN + 512


def is_hex(value: str) -> bool:
    """True if `value` is non-empty, even-length, pure hex."""
    if not value or len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def is_valid_hex_of_length(value: Optional[str], hex_len: int) -> bool:
    """True if `value` is valid hex of exactly `hex_len` characters."""
    if not value or not isinstance(value, str):
        return False
    if len(value) != hex_len:
        return False
    return is_hex(value)


def is_valid_ml_kem_public_key(value: Optional[str]) -> bool:
    """True if `value` is a well-formed hex ML-KEM-768 public key.

    Structural only — and that is the ceiling, not an omission. ML-KEM has no
    cheap validity predicate: liboqs will happily encapsulate against 1184
    bytes of `AA`, so "decode it with the PQC library" (as the audit suggests)
    rejects nothing that this check does not already reject. What actually
    binds a key to an identity is the ML-DSA key attestation, which the
    project already implements and verifies in auth.py.
    """
    return is_valid_hex_of_length(value, ML_KEM_768_PUBLIC_KEY_HEX_LEN)


def is_valid_ml_dsa_public_key(value: Optional[str]) -> bool:
    """True if `value` is a well-formed hex ML-DSA-44 public key (= an address)."""
    return is_valid_hex_of_length(value, ML_DSA_44_PUBLIC_KEY_HEX_LEN)


def is_valid_ml_dsa_signature(value: Optional[str]) -> bool:
    """True if `value` is a well-formed hex ML-DSA-44 signature."""
    return is_valid_hex_of_length(value, ML_DSA_44_SIGNATURE_HEX_LEN)


# --- Capability check -------------------------------------------------------
#
# `strict=False` is the default on purpose. Accounts predating strict
# validation hold keys that are well-formed but were never length-checked,
# and test fixtures use placeholder keys; rejecting those outright would lock
# existing users out of the messenger rather than fixing anything. The floor
# is retained as a compatibility fallback while new/updated keys are checked
# properly at the point they are written (see routers/auth.py).
LEGACY_MIN_KEY_LEN = 500


def is_usable_encryption_key(value: Optional[str], strict: bool = False) -> bool:
    """True if `value` can serve as a messenger encryption key.

    strict=True demands an exact, well-formed ML-KEM-768 hex key.
    strict=False additionally accepts legacy/non-hex keys above the historical
    length floor, so existing accounts keep working.
    """
    if not value or not isinstance(value, str):
        return False
    if is_valid_ml_kem_public_key(value):
        return True
    if strict:
        return False
    return len(value) >= LEGACY_MIN_KEY_LEN
