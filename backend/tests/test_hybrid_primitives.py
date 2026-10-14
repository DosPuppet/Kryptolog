"""The hybrid primitives of crypto-core 5, server side (audit 2026-10-12 K-10, lot 12).

Composite ML-DSA-65 + ECDSA-P384 (draft-ietf-lamps-pq-composite-sigs-19) and
ETSI TS 103 744 CatKDF over P-384 + ML-KEM-768, checked from three directions
so that no single library is the one that is right:

  * the specifications' own vectors, copied verbatim into tests/fixtures/ —
    crypto-core's test/hybrid.test.js runs the same files through noble;
  * tests/fixtures/hybrid_interop.json: what noble produced, checked here by
    OpenSSL, and what OpenSSL produced, checked there by noble;
  * the rules the clients add to the draft — low-S, canonical DER, SEC1
    uncompressed points — which the server must apply identically.

The server only ever VERIFIES composite signatures. The KEM belongs to the
clients and runs here through the test-only catkdf_ref.py.
"""

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys

import catkdf_ref
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

import auth
from security.crypto_validation import (
    ENCRYPTION_KEY_HEX_LEN,
    IDENTITY_KEY_HEX_LEN,
    address_of,
    is_valid_encryption_key,
    is_valid_identity_key,
    is_valid_p384_point,
)

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures"
ML_SIG = 3309


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _flip(data: bytes, at: int) -> bytes:
    copy = bytearray(data)
    copy[at] ^= 1
    return bytes(copy)


P384_N = ec.SECP384R1().group_order


def _point(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


class TestSeededKeyPin:
    """One 80-byte secret is one composite key in both libraries. The digest
    was computed by noble and checked here by OpenSSL, and crypto-core's
    byte-compat suite pins the same literal — so either library drifting
    fails a test."""

    def test_fill_7_names_the_pinned_key(self):
        seed = bytes([7] * 80)
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[:32]).public_key().public_bytes_raw()
        scalar = ec.derive_private_key(int.from_bytes(seed[32:], "big"), ec.SECP384R1())
        assert hashlib.sha384(ml + _point(scalar.public_key())).hexdigest() == (
            "92ec842aeaf614676e560b807ae045e9359acb0920e437cbd2eb1472"
            "da20664dccb6d778274f25ed0dbe551f52c0c84d"
        )


class TestCompositeP384DraftVector:
    """id-MLDSA65-ECDSA-P384-SHA512 (lot 12b/12c). Upstream's ECDSA is
    randomized, so M' is pinned by VERIFYING its signatures."""

    V = _load("composite_mldsa65_ecdsa_p384_vectors.json")
    m, ctx = base64.b64decode(V["m"]), base64.b64decode(V["ctx"])
    pk, sk = base64.b64decode(V["pk"]), base64.b64decode(V["sk"])
    s, s_ctx = base64.b64decode(V["s"]), base64.b64decode(V["sWithContext"])

    @staticmethod
    def _with_ecdsa(sig: bytes, der: bytes) -> bytes:
        return sig[:ML_SIG] + der

    def test_sizes(self):
        assert len(self.pk) == auth.COMPOSITE_P384_PUBLIC_KEY_BYTES == 2049
        assert auth.COMPOSITE_P384_SIGNATURE_MAX_BYTES == 3413
        assert IDENTITY_KEY_HEX_LEN == 4098

    def test_openssl_derives_the_published_key(self):
        # The draft's sk is mldsa65Seed || ECPrivateKey (RFC 5915): the scalar
        # sits at offset 7 of the DER.
        assert self.sk[32:39].hex() == "303e0201010430"
        scalar = int.from_bytes(self.sk[39:87], "big")
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(self.sk[:32]).public_key().public_bytes_raw()
        assert ml + _point(ec.derive_private_key(scalar, ec.SECP384R1()).public_key()) == self.pk

    def test_the_low_s_signature_verifies_under_its_own_context_only(self):
        assert auth._verify_composite_p384(self.pk, self.m, self.s) is True
        assert auth._verify_composite_p384(self.pk, self.m, self.s, self.ctx) is False
        assert auth._verify_composite_p384(self.pk, self.m + b".", self.s) is False

    def test_the_drafts_high_s_signature_is_refused_and_its_twin_accepted(self):
        """Valid under the draft — OpenSSL alone accepts it — refused for its s
        only: the same r with n - s verifies, which also pins M' with a ctx."""
        r, s = decode_dss_signature(self.s_ctx[ML_SIG:])
        assert s > P384_N // 2
        m = auth._composite_message(self.m, self.ctx, auth._COMPOSITE_P384_LABEL)
        point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), self.pk[1952:])
        point.verify(self.s_ctx[ML_SIG:], m, ec.ECDSA(auth.hashes.SHA384()))  # OpenSSL: valid
        assert auth._verify_composite_p384(self.pk, self.m, self.s_ctx, self.ctx) is False
        twin = self._with_ecdsa(self.s_ctx, encode_dss_signature(r, P384_N - s))
        assert auth._verify_composite_p384(self.pk, self.m, twin, self.ctx) is True

    def test_making_a_valid_signature_high_s_is_a_refusal(self):
        r, s = decode_dss_signature(self.s[ML_SIG:])
        high = self._with_ecdsa(self.s, encode_dss_signature(r, P384_N - s))
        assert auth._verify_composite_p384(self.pk, self.m, high) is False

    def test_non_canonical_der_is_refused(self):
        der = self.s[ML_SIG:]
        r_len = der[3]
        padded = bytes([0x30, der[1] + 1, 0x02, r_len + 1, 0x00]) + der[4:]
        long_form = bytes([0x30, 0x81, der[1]]) + der[2:]
        for bad in (padded, long_form, der + b"\x00"):
            assert (
                auth._verify_composite_p384(self.pk, self.m, self._with_ecdsa(self.s, bad)) is False
            )

    def test_both_halves_are_needed(self):
        assert auth._verify_composite_p384(self.pk, self.m, _flip(self.s, 10)) is False
        assert auth._verify_composite_p384(self.pk, self.m, _flip(self.s, ML_SIG + 20)) is False
        assert auth._verify_composite_p384(_flip(self.pk, 10), self.m, self.s) is False

    def test_wrong_shapes_are_refused_not_raised(self):
        assert auth._verify_composite_p384(self.pk, self.m, self.s[: ML_SIG + 7]) is False
        assert auth._verify_composite_p384(self.pk, self.m, bytes(ML_SIG + 105)) is False
        assert auth._verify_composite_p384(self.pk[1:], self.m, self.s) is False
        compressed = bytearray(self.pk)
        compressed[1952] = 0x02
        assert auth._verify_composite_p384(bytes(compressed), self.m, self.s) is False

    def test_the_registry_names_the_one_in_use(self):
        assert auth.SIG_ALG == "MLDSA65-ECDSA-P384-SHA512"
        assert auth.SIGNATURE_VERIFIERS == {auth.SIG_ALG: auth._verify_composite_p384}


class TestEtsiCatKdfVector:
    """ETSI TS 103 744 V1.2.2's own known-answer test (cid 2221), under OpenSSL:
    crypto-core's hybrid suite runs the same file through noble."""

    V = _load("etsi_catkdf_vectors.json")

    def _hex(self, name):
        return bytes.fromhex(self.V[name])

    def test_ecdh_and_ml_kem_give_the_standards_k1_and_k2(self):
        a = ec.derive_private_key(
            int.from_bytes(self._hex("ecdh_private_a"), "big"), ec.SECP384R1()
        )
        assert _point(a.public_key())[1:] == self._hex("pa1")  # the harness drops the 0x04
        b = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), self._hex("ecdh_public_b"))
        assert a.exchange(ec.ECDH(), b) == self._hex("k1")
        ml = mlkem.MLKEM768PrivateKey.from_seed_bytes(self._hex("mlkem_keygen_seed"))
        assert ml.public_key().public_bytes_raw() == self._hex("pa2")
        assert ml.decapsulate(self._hex("pb2")) == self._hex("k2")

    def test_catkdf_gives_the_standards_key_material(self):
        label = bytes(x ^ y for x, y in zip(self._hex("labelA"), self._hex("labelB"), strict=True))
        km = catkdf_ref.catkdf(
            k1=self._hex("k1"),
            k2=self._hex("k2"),
            ma=catkdf_ref.etsi_message(
                self._hex("cid"), self._hex("labelA"), self._hex("pa1"), self._hex("pa2")
            ),
            mb=catkdf_ref.etsi_message(
                self._hex("cid"), self._hex("labelB"), self._hex("pb1"), self._hex("pb2")
            ),
            info=self.V["info"].encode(),
            label=label,
            length=24,
        )
        assert km.hex() == self.V["key_material"]

    def test_decapsulating_the_vectors_ciphertext_is_catkdf_over_its_k1_and_k2(self):
        sk = self._hex("ecdh_private_a") + self._hex("mlkem_keygen_seed")
        ct = self._hex("ecdh_public_b") + self._hex("pb2")
        expected = catkdf_ref.catkdf(
            k1=self._hex("k1"),
            k2=self._hex("k2"),
            ma=catkdf_ref.etsi_message(
                b"\x22\x21", b"", b"\x04" + self._hex("pa1"), self._hex("pa2")
            ),
            mb=catkdf_ref.etsi_message(
                b"\x22\x21", b"", self._hex("ecdh_public_b"), self._hex("pb2")
            ),
            info=b"Kryptolog/HKDFwSHA384_P384_ML-KEM-768_CatKDF/AES-GCM/v5",
            length=32,
        )
        assert catkdf_ref.decapsulate(ct, sk) == expected

    def test_round_trip(self):
        sk = bytes(range(0x30, 0x30 + 48)) + bytes(range(0x70, 0x70 + 64))
        ct, key = catkdf_ref.encapsulate(catkdf_ref.public_key(sk))
        assert len(ct) == 1185
        assert catkdf_ref.decapsulate(ct, sk) == key


class TestKeyChecks:
    """The validators the login route uses since 5.0.0 — unlike X-Wing's and
    Ed25519's, both check that the key IS one."""

    V = _load("hybrid_interop.json")

    def test_sizes(self):
        assert ENCRYPTION_KEY_HEX_LEN == 2562

    def test_real_keys_pass(self):
        assert is_valid_encryption_key(self.V["catkdf_public_key"]) is True
        assert is_valid_identity_key(self.V["p384_composite_public_key"]) is True

    def test_an_off_curve_point_is_refused_in_either_key(self):
        cat = bytearray.fromhex(self.V["catkdf_public_key"])
        cat[40] ^= 1
        assert is_valid_encryption_key(cat.hex()) is False
        ident = bytearray.fromhex(self.V["p384_composite_public_key"])
        ident[1952 + 40] ^= 1
        assert is_valid_identity_key(ident.hex()) is False

    def test_a_compressed_or_absent_point_is_refused(self):
        point = bytes.fromhex(self.V["catkdf_public_key"])[:97]
        assert is_valid_p384_point(point) is True
        assert is_valid_p384_point(b"\x02" + point[1:]) is False
        assert is_valid_p384_point(b"\x00" * 97) is False
        assert is_valid_p384_point(point[:49]) is False

    def test_an_ml_kem_key_failing_the_modulus_check_is_refused(self):
        """FIPS 203's one cheap validity predicate, which OpenSSL runs on load —
        and reports as a LENGTH error, which is why the probe is pinned here."""
        raw = bytearray.fromhex(self.V["catkdf_public_key"])
        raw[97], raw[98] = 0xFF, 0xFF  # a 12-bit coefficient of 4095 > q
        with pytest.raises(ValueError):
            mlkem.MLKEM768PublicKey.from_public_bytes(bytes(raw[97:]))
        assert is_valid_encryption_key(raw.hex()) is False

    def test_malformed_strings_are_refused(self):
        key = self.V["catkdf_public_key"]
        for bad in (None, key[:-2], key.upper(), "zz" + key[2:], key + "00"):
            assert is_valid_encryption_key(bad) is False
        ident = self.V["p384_composite_public_key"]
        for bad in (None, ident[:-2], ident.upper(), "ab" * 1984):  # the last a 4.x key
            assert is_valid_identity_key(bad) is False


class TestNobleOpenSSLInterop:
    """noble -> OpenSSL here, OpenSSL -> noble in crypto-core's hybrid suite."""

    V = _load("hybrid_interop.json")

    def test_the_golden_address(self):
        """The address both languages give the same composite key — the one
        identifier every row, URL and signed body carries (crypto-core 5.0.0)."""
        assert address_of(self.V["p384_composite_public_key"]) == self.V["p384_composite_address"]

    def test_same_secret_same_catkdf_key(self):
        sk = bytes.fromhex(self.V["catkdf_secret_key"])
        assert catkdf_ref.public_key(sk).hex() == self.V["catkdf_public_key"]

    def test_openssl_decapsulates_what_noble_encapsulated(self):
        sk = bytes.fromhex(self.V["catkdf_secret_key"])
        key = catkdf_ref.decapsulate(base64.b64decode(self.V["noble_catkdf_cipher_text"]), sk)
        assert key == base64.b64decode(self.V["noble_catkdf_key"])

    def test_same_seeds_same_p384_composite_key(self):
        sk = bytes.fromhex(self.V["p384_composite_secret_key"])
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(sk[:32]).public_key().public_bytes_raw()
        scalar = ec.derive_private_key(int.from_bytes(sk[32:], "big"), ec.SECP384R1())
        assert (ml + _point(scalar.public_key())).hex() == self.V["p384_composite_public_key"]

    @pytest.mark.parametrize("who", ["noble", "openssl"])
    def test_p384_composite_signature_verifies(self, who):
        pk = bytes.fromhex(self.V["p384_composite_public_key"])
        sig = base64.b64decode(self.V[f"{who}_p384_composite_signature"])
        assert auth._verify_composite_p384(pk, self.V["message"].encode(), sig) is True
        assert auth._verify_composite_p384(pk, b"another message", sig) is False


IMPORT = "from cryptography.hazmat.primitives.asymmetric import ec, mldsa\n"


@pytest.mark.parametrize(
    "name, patch",
    [
        ("ML-DSA-65", f"{IMPORT}mldsa.MLDSA65PrivateKey.generate = staticmethod(refuse)"),
        ("ECDSA P-384", f"{IMPORT}ec.generate_private_key = refuse"),
        # Before anything imports it: once imported, `from ... import mldsa`
        # finds the attribute on the package and never consults sys.modules.
        ("ML-DSA", "sys.modules['cryptography.hazmat.primitives.asymmetric.mldsa'] = None"),
    ],
)
def test_the_server_refuses_to_start_without_each_half(name, patch):
    """test_pqc.py covers ML-DSA-44; a server that cannot verify either half of
    the composite cannot authenticate anybody after the 4.0.0 cutover either.
    The last case is a cryptography too old to have the `mldsa` module at all,
    which must stop with the same message rather than a bare ImportError."""
    code = (
        "import sys\n"
        "from cryptography.exceptions import UnsupportedAlgorithm\n"
        "def refuse(*a):\n"
        "    raise UnsupportedAlgorithm('not in this OpenSSL')\n"
        f"{patch}\n"
        "import auth\n"
    )
    backend = os.path.join(os.path.dirname(__file__), "..")
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=backend, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert f"cryptography lacks {name}:" in result.stderr
