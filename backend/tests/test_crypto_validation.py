"""Format validation for key material, addresses and signatures (KRY-011,
crypto-core 5.0.0)."""

import base64
import hashlib

import pytest
from conftest import identity_key_of, synthetic_address, synthetic_encryption_key

from security.crypto_validation import (
    ADDRESS_HEX_LEN,
    ENCRYPTION_KEY_HEX_LEN,
    IDENTITY_KEY_HEX_LEN,
    KEY_ID_HEX_LEN,
    SIGNATURE_MAX_B64_LEN,
    address_of,
    encryption_key_id,
    identity_binds_address,
    is_hex,
    is_valid_address,
    is_valid_encryption_key,
    is_valid_identity_key,
    is_valid_key_id,
    is_valid_signature,
)

VALID_ENCRYPTION_KEY = synthetic_encryption_key("validation")
# A signature is an opaque payload: base64 since the L-12 cutover, while keys
# and addresses stay hex because they are identifiers.
VALID_SIGNATURE = base64.b64encode(bytes([0xEF]) * 3411).decode()


class TestConstants:
    def test_sizes_match_the_parameter_sets(self):
        assert IDENTITY_KEY_HEX_LEN == 4098  # ML-DSA-65 (1952) + P-384 point (97)
        assert ENCRYPTION_KEY_HEX_LEN == 2562  # P-384 point (97) + ML-KEM-768 (1184)
        assert ADDRESS_HEX_LEN == 96  # SHA-384
        assert KEY_ID_HEX_LEN == 32  # SHA-384, cut to 128 bits
        assert SIGNATURE_MAX_B64_LEN == 4552  # ML-DSA-65 (3309) + DER ECDSA (<= 104)


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
            "zz" * 1281,  # right length, not hex
            VALID_ENCRYPTION_KEY.upper(),  # right length, not one spelling
            "ab" * 1281,  # right length, hex — and no point on the curve
            "ab" * 1184,  # a 3.x ML-KEM-768 key
            "ab" * 1216,  # a 4.x X-Wing key
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

    def test_a_signature_is_the_size_of_one_composite(self):
        """3 317..3 413 bytes: ML-DSA-65 plus a DER ECDSA half, whose size varies."""
        for size in (3317, 3380, 3413):
            assert is_valid_signature(base64.b64encode(bytes(size)).decode())
        assert not is_valid_signature(base64.b64encode(bytes(2420)).decode())  # ML-DSA-44
        assert not is_valid_signature(base64.b64encode(bytes(3316)).decode())
        assert not is_valid_signature(base64.b64encode(bytes(3414)).decode())
        # 4.x's fixed 3 373-byte Ed25519 composite is within the range: the
        # verifier, not the format check, is what refuses it.
        assert is_valid_signature(base64.b64encode(bytes(3373)).decode())
        assert not is_valid_signature(VALID_SIGNATURE + "=")


class TestKeyId:
    def test_is_sha384_of_the_key_under_its_domain_cut_to_128_bits(self):
        expected = hashlib.sha384(
            b"Kryptolog encryption key id v5\nalg=HKDFwSHA384_P384_ML-KEM-768_CatKDF\n"
            + bytes.fromhex(VALID_ENCRYPTION_KEY)
        ).hexdigest()[:32]
        assert encryption_key_id(VALID_ENCRYPTION_KEY) == expected
        assert is_valid_key_id(expected)

    def test_refuses_what_is_not_a_key_or_an_id(self):
        for bad in (VALID_ENCRYPTION_KEY.upper(), VALID_ENCRYPTION_KEY[:-2], None):
            with pytest.raises(ValueError):
                encryption_key_id(bad)
        for bad in (None, "", "ab" * 15, "ab" * 17, "AB" * 16, "zz" * 16):
            assert not is_valid_key_id(bad)


class TestAddressOf:
    def test_is_sha384_of_the_key_under_its_domain(self):
        key = identity_key_of(synthetic_address("hash"))
        expected = hashlib.sha384(
            b"Kryptolog address v5\nalg=MLDSA65-ECDSA-P384-SHA512\n" + bytes.fromhex(key)
        ).hexdigest()
        assert address_of(key) == expected

    def test_refuses_what_is_not_an_identity_key(self):
        key = identity_key_of(synthetic_address("refuse"))
        # Also a 3.x key (ML-DSA-44) and a 4.x one (ML-DSA-65 + Ed25519).
        for bad in (key.upper(), key[:-2], "ab" * 1312, "ab" * 1984, None):
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

    def test_a_p384_half_that_is_not_a_point_is_refused(self):
        key = identity_key_of(synthetic_address("not-a-point"))
        # One coordinate bit flipped: off the curve.
        raw = bytearray.fromhex(key)
        raw[1952 + 40] ^= 1
        assert not is_valid_identity_key(raw.hex())
        # The compressed prefix on the uncompressed form.
        raw = bytearray.fromhex(key)
        raw[1952] = 0x02
        assert not is_valid_identity_key(raw.hex())
