"""Format validation for PQC key material (KRY-011)."""
import pytest

from security.crypto_validation import (
    LEGACY_MIN_KEY_LEN,
    ML_KEM_768_PUBLIC_KEY_HEX_LEN,
    ML_DSA_44_PUBLIC_KEY_HEX_LEN,
    is_hex,
    is_usable_encryption_key,
    is_valid_ml_dsa_public_key,
    is_valid_ml_dsa_signature,
    is_valid_ml_kem_public_key,
)

VALID_KEM_KEY = "ab" * 1184
VALID_DSA_KEY = "cd" * 1312
VALID_DSA_SIG = "ef" * 2420


class TestConstants:
    def test_sizes_match_fips_parameter_sets(self):
        assert ML_KEM_768_PUBLIC_KEY_HEX_LEN == 2368
        assert ML_DSA_44_PUBLIC_KEY_HEX_LEN == 2624


class TestHex:
    @pytest.mark.parametrize("value,expected", [
        ("abcd", True),
        ("ABCD", True),
        ("abc", False),       # odd length
        ("zzzz", False),      # not hex
        ("", False),
        ("ab cd", False),
    ])
    def test_is_hex(self, value, expected):
        assert is_hex(value) is expected


class TestKeyValidation:
    def test_accepts_well_formed_keys(self):
        assert is_valid_ml_kem_public_key(VALID_KEM_KEY)
        assert is_valid_ml_dsa_public_key(VALID_DSA_KEY)
        assert is_valid_ml_dsa_signature(VALID_DSA_SIG)

    @pytest.mark.parametrize("value", [
        None, "", "ab" * 100,          # too short
        "ab" * 2000,                   # too long
        "zz" * 1184,                   # right length, not hex
        "enc_pub_key_" + "c" * 600,    # the old placeholder format
    ])
    def test_rejects_malformed_kem_keys(self, value):
        assert not is_valid_ml_kem_public_key(value)

    def test_length_floor_alone_is_insufficient(self):
        """The audit's point: 600 arbitrary chars cleared the old `< 500` check."""
        bogus = "enc_pub_key_" + "c" * 600
        assert len(bogus) > LEGACY_MIN_KEY_LEN      # would have passed before
        assert not is_valid_ml_kem_public_key(bogus)  # rejected now


class TestUsableEncryptionKey:
    def test_well_formed_key_is_usable_either_way(self):
        assert is_usable_encryption_key(VALID_KEM_KEY)
        assert is_usable_encryption_key(VALID_KEM_KEY, strict=True)

    def test_legacy_key_usable_only_in_non_strict_mode(self):
        """Accounts predating strict validation must not be locked out."""
        legacy = "legacy_key_" + "c" * 600
        assert is_usable_encryption_key(legacy) is True
        assert is_usable_encryption_key(legacy, strict=True) is False

    @pytest.mark.parametrize("value", [None, "", "short"])
    def test_missing_or_tiny_keys_are_never_usable(self, value):
        assert is_usable_encryption_key(value) is False
        assert is_usable_encryption_key(value, strict=True) is False
