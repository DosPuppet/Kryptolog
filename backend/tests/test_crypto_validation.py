"""Format validation for key material, addresses and signatures (KRY-011,
crypto-core 4.0.0)."""

import base64
import hashlib

import pytest
from conftest import identity_key_of, synthetic_address

from security.crypto_validation import (
    ADDRESS_HEX_LEN,
    ENCRYPTION_KEY_HEX_LEN,
    IDENTITY_KEY_HEX_LEN,
    SIGNATURE_B64_LEN,
    address_of,
    identity_binds_address,
    is_hex,
    is_valid_address,
    is_valid_encryption_key,
    is_valid_identity_key,
    is_valid_signature,
)

VALID_ENCRYPTION_KEY = "ab" * 1216
# A signature is an opaque payload: base64 since the L-12 cutover, while keys
# and addresses stay hex because they are identifiers.
VALID_SIGNATURE = base64.b64encode(bytes([0xEF]) * 3373).decode()


class TestConstants:
    def test_sizes_match_the_parameter_sets(self):
        assert IDENTITY_KEY_HEX_LEN == 3968  # ML-DSA-65 (1952) + Ed25519 (32)
        assert ENCRYPTION_KEY_HEX_LEN == 2432  # X-Wing
        assert ADDRESS_HEX_LEN == 96  # SHA-384
        assert SIGNATURE_B64_LEN == 4500  # ML-DSA-65 (3309) + Ed25519 (64)


class TestHex:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("abcd", True),
            ("ABCD", True),
            ("abc", False),  # odd length
            ("zzzz", False),  # not hex
            ("", False),
            ("ab cd", False),
        ],
    )
    def test_is_hex(self, value, expected):
        assert is_hex(value) is expected


class TestKeyValidation:
    def test_accepts_well_formed_values(self):
        assert is_valid_encryption_key(VALID_ENCRYPTION_KEY)
        assert is_valid_signature(VALID_SIGNATURE)
        assert is_valid_address(synthetic_address("valid"))

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "ab" * 100,  # too short
            "ab" * 2000,  # too long
            "zz" * 1216,  # right length, not hex
            "AB" * 1216,  # right length, not one spelling
            "ab" * 1184,  # a 3.x ML-KEM-768 key
            "enc_pub_key_" + "c" * 600,  # the old placeholder format
        ],
    )
    def test_rejects_malformed_encryption_keys(self, value):
        assert not is_valid_encryption_key(value)

    def test_length_floor_alone_is_insufficient(self):
        """The audit's point: 600 arbitrary chars cleared the old `< 500` check,
        and the lenient mode that kept that floor alive went with 4.0.0."""
        assert not is_valid_encryption_key("enc_pub_key_" + "c" * 600)

    @pytest.mark.parametrize(
        "value", [None, "", "ab" * 47, "ab" * 49, "AB" * 48, "zz" * 48, "cd" * 1312]
    )
    def test_rejects_what_is_not_an_address(self, value):
        # The last one is a 3.x address: an ML-DSA-44 key.
        assert not is_valid_address(value)

    def test_a_signature_is_exactly_one_composite(self):
        assert not is_valid_signature(base64.b64encode(bytes(2420)).decode())  # ML-DSA-44
        assert not is_valid_signature(base64.b64encode(bytes(3374)).decode())


class TestAddressOf:
    def test_is_sha384_of_the_key_under_its_domain(self):
        key = identity_key_of(synthetic_address("hash"))
        expected = hashlib.sha384(
            b"Kryptolog address v4\nalg=MLDSA65-Ed25519-SHA512\n" + bytes.fromhex(key)
        ).hexdigest()
        assert address_of(key) == expected

    def test_refuses_what_is_not_an_identity_key(self):
        key = identity_key_of(synthetic_address("refuse"))
        for bad in (key.upper(), key[:-2], "ab" * 1312, None):
            with pytest.raises(ValueError):
                address_of(bad)

    def test_binding(self):
        a, b = synthetic_address("bind-a"), synthetic_address("bind-b")
        assert identity_binds_address(identity_key_of(a), a)
        assert not identity_binds_address(identity_key_of(a), b)
        assert not identity_binds_address(identity_key_of(a), a.upper())
        assert not identity_binds_address(None, a)
        assert not identity_binds_address(identity_key_of(a), None)


class TestIdentityKey:
    def test_a_synthetic_key_is_a_valid_one(self):
        assert is_valid_identity_key(identity_key_of(synthetic_address("valid-key")))

    def test_an_ed25519_half_that_is_not_a_point_is_refused(self):
        key = identity_key_of(synthetic_address("not-a-point"))
        # y = 2 has no x on the curve.
        assert not is_valid_identity_key(key[:-64] + "02" + "00" * 31)
