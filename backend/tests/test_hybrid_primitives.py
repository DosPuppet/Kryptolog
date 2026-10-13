"""The hybrid primitives of crypto-core 4, server side (audit 2026-10-12 K-10).

Composite ML-DSA-65 + Ed25519 (draft-ietf-lamps-pq-composite-sigs-19) and
X-Wing (draft-connolly-cfrg-xwing-kem-10), checked from three directions so
that no single library is the one that is right:

  * the specifications' own vectors, copied verbatim into tests/fixtures/ —
    crypto-core's test/hybrid.test.js runs the same files through noble;
  * tests/fixtures/hybrid_interop.json: what noble produced, checked here by
    OpenSSL, and what OpenSSL produced, checked there by noble;
  * the Ed25519 edges where noble's cofactored rule and OpenSSL's cofactorless
    one disagree, and the key check that makes the server's rule the clients'.

The server only ever VERIFIES composite signatures. X-Wing belongs to the
clients and runs here through the test-only xwing_ref.py.
"""

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest
import xwing_ref
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

import auth
from security.crypto_validation import (
    IDENTITY_KEY_HEX_LEN,
    address_of,
    is_valid_identity_key,
)
from security.ed25519_subgroup import in_prime_order_subgroup

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures"
ML_SIG = 3309


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _flip(data: bytes, at: int) -> bytes:
    copy = bytearray(data)
    copy[at] ^= 1
    return bytes(copy)


class TestCompositeDraftVector:
    V = _load("composite_mldsa65_ed25519_vectors.json")
    m, ctx = base64.b64decode(V["m"]), base64.b64decode(V["ctx"])
    pk, sk = base64.b64decode(V["pk"]), base64.b64decode(V["sk"])
    s, s_ctx = base64.b64decode(V["s"]), base64.b64decode(V["sWithContext"])

    def test_sizes(self):
        assert (len(self.pk), len(self.sk), len(self.s)) == (1984, 64, 3373)
        assert auth.COMPOSITE_PUBLIC_KEY_BYTES == 1984
        assert auth.COMPOSITE_SIGNATURE_BYTES == 3373
        assert IDENTITY_KEY_HEX_LEN == 3968

    def test_openssl_derives_the_published_key_from_the_published_seeds(self):
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(self.sk[:32]).public_key()
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(self.sk[32:]).public_key()
        assert ml.public_bytes_raw() + ed.public_bytes_raw() == self.pk

    def test_both_published_signatures_verify_each_under_its_own_context_only(self):
        assert auth._verify_composite(self.pk, self.m, self.s) is True
        assert auth._verify_composite(self.pk, self.m, self.s_ctx, self.ctx) is True
        assert auth._verify_composite(self.pk, self.m, self.s, self.ctx) is False
        assert auth._verify_composite(self.pk, self.m, self.s_ctx) is False
        assert auth._verify_composite(self.pk, self.m + b".", self.s) is False

    def test_m_prime_is_the_drafts_byte_for_byte(self):
        """The Ed25519 half is deterministic, so re-producing upstream's pins the
        prefix, label, context byte and digest — a mistake the verifier made
        too would still pass the verification test above."""
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(self.sk[32:])
        assert ed.sign(auth._composite_message(self.m)) == self.s[ML_SIG:]
        assert ed.sign(auth._composite_message(self.m, self.ctx)) == self.s_ctx[ML_SIG:]

    def test_both_halves_are_needed(self):
        assert auth._verify_composite(self.pk, self.m, _flip(self.s, 10)) is False
        assert auth._verify_composite(self.pk, self.m, _flip(self.s, ML_SIG + 10)) is False
        assert auth._verify_composite(_flip(self.pk, 10), self.m, self.s) is False
        assert auth._verify_composite(_flip(self.pk, 1960), self.m, self.s) is False

    def test_wrong_lengths_are_refused_not_raised(self):
        assert auth._verify_composite(self.pk, self.m, self.s[1:]) is False
        assert auth._verify_composite(self.pk, self.m, self.s + b"\x00") is False
        assert auth._verify_composite(self.pk[1:], self.m, self.s) is False
        # A whole ML-DSA-65 key with a 33-byte tail: without the length check
        # that half verifies and the Ed25519 parse RAISES instead of refusing.
        assert auth._verify_composite(self.pk + b"\x00", self.m, self.s) is False
        with pytest.raises(ValueError, match="255"):
            auth._composite_message(self.m, bytes(256))


class TestSeededKeyPin:
    """One 64-byte seed is one composite key in both libraries. The digest was
    computed here, by OpenSSL, and crypto-core's byte-compat suite pins the
    same literal under noble — so either library drifting fails a test."""

    def test_fill_7_names_the_pinned_key(self):
        seed = bytes([7] * 64)
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[:32]).public_key().public_bytes_raw()
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(seed[32:]).public_key().public_bytes_raw()
        assert hashlib.sha384(ml + ed).hexdigest() == (
            "96a33b461c1decb225cef1504b886bfb752de6bc7620a8a1"
            "f94d493278c91ad2fe0374c97882b3bbc913b8d760482fec"
        )


class TestXWingDraftVectors:
    V = _load("xwing_vectors.json")["vectors"]

    @pytest.mark.parametrize("i", range(3))
    def test_seed_to_key_and_ciphertext_to_secret(self, i):
        v = {k: bytes.fromhex(x) for k, x in self.V[i].items()}
        assert v["sk"] == v["seed"]  # the secret key IS the seed
        assert xwing_ref.public_key(v["seed"]) == v["pk"]
        assert xwing_ref.decapsulate(v["ct"], v["sk"]) == v["ss"]

    def test_round_trip(self):
        sk = bytes(range(32))
        ct, ss = xwing_ref.encapsulate(xwing_ref.public_key(sk))
        assert len(ct) == 1120
        assert xwing_ref.decapsulate(ct, sk) == ss


class TestNobleOpenSSLInterop:
    """noble -> OpenSSL here; OpenSSL -> noble in crypto-core's hybrid suite."""

    V = _load("hybrid_interop.json")

    def test_same_seeds_same_composite_key(self):
        sk = bytes.fromhex(self.V["composite_secret_key"])
        ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(sk[:32]).public_key().public_bytes_raw()
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(sk[32:]).public_key().public_bytes_raw()
        assert (ml + ed).hex() == self.V["composite_public_key"]

    @pytest.mark.parametrize("who", ["noble", "openssl"])
    def test_composite_signature_verifies(self, who):
        pk = bytes.fromhex(self.V["composite_public_key"])
        sig = base64.b64decode(self.V[f"{who}_composite_signature"])
        assert auth._verify_composite(pk, self.V["message"].encode(), sig) is True
        assert auth._verify_composite(pk, b"another message", sig) is False

    def test_openssl_decapsulates_what_noble_encapsulated(self):
        sk = bytes.fromhex(self.V["xwing_secret_key"])
        assert xwing_ref.public_key(sk).hex() == self.V["xwing_public_key"]
        ct = base64.b64decode(self.V["noble_xwing_cipher_text"])
        ss = xwing_ref.decapsulate(ct, sk)
        assert ss == base64.b64decode(self.V["noble_xwing_shared_secret"])

    def test_the_golden_address(self):
        """The address both languages give the same composite key — the one
        identifier every row, URL and signed body carries (crypto-core 4.0.0)."""
        assert address_of(self.V["composite_public_key"]) == self.V["composite_address"]

    def test_the_identity_key_passes_the_entry_check(self):
        assert is_valid_identity_key(self.V["composite_public_key"]) is True


class TestEd25519Edges:
    """Signatures only a key's owner can build, on which the two libraries'
    Ed25519 rules disagree. The clients refuse all four (crypto-core's hybrid
    suite). OpenSSL refuses three; the fourth signature it accepts, but its key
    never gets in, which makes the server's rule — key check where the key
    enters, OpenSSL on every verification after — refuse all four too."""

    V = _load("hybrid_interop.json")
    OPENSSL_ACCEPTS = {
        "mixed_order_R": False,
        "mixed_order_A_odd_k": False,
        "mixed_order_A_even_k": True,  # [k]T = 0 for an even k: cofactorless holds
        "small_order_A": False,
    }

    @pytest.mark.parametrize("edge", sorted(OPENSSL_ACCEPTS))
    def test_openssl_on_its_own(self, edge):
        e = self.V["ed25519_edges"][edge]
        verdict = auth._verify_composite(
            bytes.fromhex(e["public_key"]),
            self.V["message"].encode(),
            base64.b64decode(e["signature"]),
        )
        assert verdict is self.OPENSSL_ACCEPTS[edge]

    @pytest.mark.parametrize("edge", sorted(OPENSSL_ACCEPTS))
    def test_the_servers_rule_refuses_every_one(self, edge):
        e = self.V["ed25519_edges"][edge]
        accepted = is_valid_identity_key(e["public_key"]) and auth._verify_composite(
            bytes.fromhex(e["public_key"]),
            self.V["message"].encode(),
            base64.b64decode(e["signature"]),
        )
        assert not accepted

    def test_only_keys_with_a_torsion_component_fail_the_entry_check(self):
        edges = self.V["ed25519_edges"]
        # mixed_order_R carries its torsion in the SIGNATURE, under an honest key.
        assert is_valid_identity_key(edges["mixed_order_R"]["public_key"]) is True
        for edge in ("mixed_order_A_odd_k", "mixed_order_A_even_k", "small_order_A"):
            assert is_valid_identity_key(edges[edge]["public_key"]) is False

    @pytest.mark.parametrize(
        "name", ["honest", "mixed_order", "small_order", "identity", "non_canonical", "off_curve"]
    )
    def test_prime_order_subgroup_agrees_with_noble(self, name):
        point = self.V["prime_order_points"][name]
        assert (
            in_prime_order_subgroup(bytes.fromhex(point["point"]))
            is point["in_prime_order_subgroup"]
        )

    def test_the_entry_check_refuses_malformed_keys(self):
        key = self.V["composite_public_key"]
        assert is_valid_identity_key(None) is False
        assert is_valid_identity_key(key[:-2]) is False
        assert is_valid_identity_key(key.upper()) is False  # identifiers are lowercase
        assert is_valid_identity_key("zz" + key[2:]) is False


IMPORT = "from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa\n"


@pytest.mark.parametrize(
    "name, patch",
    [
        ("ML-DSA-65", f"{IMPORT}mldsa.MLDSA65PrivateKey.generate = staticmethod(refuse)"),
        ("Ed25519", f"{IMPORT}ed25519.Ed25519PrivateKey.generate = staticmethod(refuse)"),
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
