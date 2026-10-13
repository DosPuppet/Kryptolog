"""The signed bodies both sides must build identically, byte for byte.

A signature is over a STRING. If the client and the server spell that string
even slightly differently, every signature of that kind fails — and the failure
says nothing about why, because a wrong message and a forged signature are
indistinguishable to a verifier.

Three of the four bodies here already lived in crypto-core and were pinned on
the producing side. The login challenge did not: the SPA rebuilt it inline
(PQCContext.jsx) while the server built it in auth.py, with no shared source, no
cross-language fixture, and no test that could fail on a mismatch — conftest
stubs the verifier, so a typo in either copy passed the entire suite and broke
every login.

The vectors live in a fixture read by BOTH languages
(packages/crypto-core/test/byte-compat.test.js reads the same file), so neither
side gets to be the definition of correct.
"""

import base64
import hashlib
import json
import pathlib

import pytest
from conftest import TEST_ORIGIN, MLDSA44Signer, get_nonce, server_deployment

import auth

FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "signed_bodies.json"


def _vectors() -> dict:
    assert FIXTURE.exists(), f"the shared fixture moved or was deleted: {FIXTURE}"
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestSignedBodiesMatchTheSharedFixture:
    def test_login_challenge(self):
        v = _vectors()
        assert (
            auth._login_message(v["nonce"], origin=v["origin"], deployment=v["deployment"])
            == v["bodies"]["login"]
        )

    def test_login_challenge_with_the_encryption_key_bound_in(self):
        """The ML-KEM key is folded into the challenge (audit M-2), so the
        identity's signature authorizes that key."""
        v = _vectors()
        assert (
            auth._login_message(
                v["nonce"],
                encryption_public_key=v["mlkem_public_key"],
                origin=v["origin"],
                deployment=v["deployment"],
            )
            == v["bodies"]["login_with_encryption_key"]
        )

    def test_key_attestation(self):
        v = _vectors()
        assert (
            auth.encryption_key_attestation_message(v["mlkem_public_key"])
            == v["bodies"]["key_attestation"]
        )

    def test_multisig_approval(self):
        v = _vectors()
        assert (
            auth.multisig_approval_message(v["workflow_id"], v["secret_id"], v["ciphertext_sha256"])
            == v["bodies"]["multisig_approval"]
        )

    def test_message_body(self):
        """The newest mirror, and the one with the most room to drift: it
        digests a canonical JSON rendering of the key envelope, and Python and
        JS disagree about JSON given half a chance (non-ASCII escaping, sort
        order, number formatting)."""
        v = _vectors()
        assert (
            auth.message_signing_body(
                from_=v["message_from"],
                conv=v["message_conv"],
                gid=v["message_gid"],
                sid=v["message_sid"],
                ts=v["message_ts"],
                seq=v["message_seq"],
                ct=v["message_ct"],
                keys=v["message_keys"],
            )
            == v["bodies"]["message"]
        )

    def test_author_redacted_message_body(self):
        v = _vectors()
        assert (
            auth.message_signing_body(
                from_=v["message_from"],
                conv=v["message_conv"],
                gid=v["message_gid"],
                sid=v["message_sid"],
                ts=v["message_ts"],
                seq=v["message_seq"],
                ct=None,
                keys=v["message_keys"],
            )
            == v["bodies"]["message_redacted"]
        )

    def test_account_deletion(self):
        v = _vectors()
        assert (
            auth.account_deletion_message(
                v["nonce"],
                v["deletion_mode"],
                v["redaction_keys"],
                origin=v["origin"],
                deployment=v["deployment"],
            )
            == v["bodies"]["account_deletion"]
        )

    @pytest.mark.parametrize(
        ("kind", "key_field"), [("dm", "erase_partner"), ("group", "erase_group")]
    )
    def test_conversation_erase(self, kind, key_field):
        """crypto-core 3.1.0, additive (audit 2026-09-11 M-6)."""
        v = _vectors()
        assert (
            auth.conversation_erase_message(
                v["nonce"],
                kind,
                v[key_field],
                v["redaction_keys"],
                origin=v["origin"],
                deployment=v["deployment"],
            )
            == v["bodies"][f"conversation_erase_{kind}"]
        )

    def test_a_conversation_erase_names_its_conversation_and_nothing_else_spells_it(self):
        v = _vectors()
        common = dict(origin=v["origin"], deployment=v["deployment"])
        dm = auth.conversation_erase_message(v["nonce"], "dm", "ab", ["dm:1"], **common)
        assert dm != auth.conversation_erase_message(v["nonce"], "dm", "ac", ["dm:1"], **common)
        assert dm != auth.conversation_erase_message(v["nonce"], "group", "ab", ["dm:1"], **common)
        for kind, conversation in (
            ("dm", "AB"),
            ("dm", "ab\nnonce=00"),
            ("group", "x y"),
            ("x", "ab"),
        ):
            with pytest.raises(auth.NonCanonicalSignedBody):
                auth.conversation_erase_message(v["nonce"], kind, conversation, [], **common)

    def test_the_redaction_set_is_order_independent_and_namespaced(self):
        """Namespaced ids, and a sort both languages spell the same way.

        "dm:2" vs "dm:10" order differently under a numeric and a lexicographic
        comparison, and group:10 collides with dm:10 on the bare id — the
        fixture carries all three so one vector covers both traps.
        """
        v = _vectors()
        expected = v["bodies"]["account_deletion"]
        assert (
            auth.account_deletion_message(
                v["nonce"],
                v["deletion_mode"],
                list(reversed(v["redaction_keys"])),
                origin=v["origin"],
                deployment=v["deployment"],
            )
            == expected
        )
        assert (
            auth.account_deletion_message(
                v["nonce"],
                "leave",
                v["redaction_keys"],
                origin=v["origin"],
                deployment=v["deployment"],
            )
            != expected
        )
        # Stripping the namespace collapses two distinct rows into one.
        stripped = [k.split(":", 1)[1] for k in v["redaction_keys"]]
        assert (
            auth.account_deletion_message(
                v["nonce"],
                v["deletion_mode"],
                stripped,
                origin=v["origin"],
                deployment=v["deployment"],
            )
            != expected
        )


class TestTheVectorsAreWhatWeThinkTheyAre:
    """Guards the fixture itself. Asserting agreement with a file that both
    sides could regenerate would pass for any value, including a broken one."""

    def test_every_body_is_domain_separated(self):
        v = _vectors()
        for name, body in v["bodies"].items():
            assert body.startswith("Kryptolog Signed Message v1\ncontext="), name

    def test_the_contexts_are_disjoint(self):
        """H1: a signature minted for one purpose cannot be replayed as
        another, which holds only if the context lines actually differ."""
        v = _vectors()
        contexts = {body.split("\n")[1] for body in v["bodies"].values()}
        # login and login_with_encryption_key share the login context.
        assert contexts == {
            "context=login",
            "context=key-attestation",
            "context=multisig-approval",
            "context=message",
            "context=account-deletion",
            "context=conversation-erase",
        }

    def test_a_redaction_differs_from_the_live_message_in_its_last_line_only(self):
        """The redacted form keeps the author, conversation, gid, sid and key
        envelope and drops only the ciphertext — that is what lets the partner
        keep decrypting their own replies under the same session."""
        v = _vectors()
        live, redacted = v["bodies"]["message"], v["bodies"]["message_redacted"]
        assert live.rsplit("\n", 1)[0] == redacted.rsplit("\n", 1)[0]
        assert redacted.endswith("\nredacted=1")
        assert live.endswith("\nct=AAAAAAAAAAAAAAAA.3q2+7w==")

    def test_no_ciphertext_value_can_spell_a_redaction(self):
        """If one could, a single signature would be valid for two different
        messages, and a server could pass a live message off as author-redacted.
        """
        v = _vectors()
        common = dict(
            from_=v["message_from"],
            conv=v["message_conv"],
            gid=v["message_gid"],
            sid=v["message_sid"],
            ts=v["message_ts"],
            seq=v["message_seq"],
            keys=v["message_keys"],
        )
        redacted = auth.message_signing_body(ct=None, **common)
        for ct in ("null", "None", "redacted=1", "", "1"):
            assert auth.message_signing_body(ct=ct, **common) != redacted

    def test_a_body_with_no_session_id_is_refused_rather_than_spelled(self):
        """The one field of a signed body that comes straight out of a
        client-written payload, and the two languages disagree about a missing
        one: Python renders `sid=None`, JS renders `sid=null`. Neither side can
        verify the other's, and nothing says why — so this refuses instead,
        the same way check_envelope_shape refuses a digest it cannot promise
        to reproduce (audit 2026-09-12 M-2c).
        """
        v = _vectors()
        common = dict(
            from_=v["message_from"],
            conv=v["message_conv"],
            gid=v["message_gid"],
            ts=v["message_ts"],
            seq=v["message_seq"],
            keys=v["message_keys"],
            ct=None,
        )
        for missing in (None, "", 0):
            with pytest.raises(auth.NonCanonicalSignedBody):
                auth.message_signing_body(sid=missing, **common)
        # The real one still builds, unchanged.
        assert (
            auth.message_signing_body(sid=v["message_sid"], **common)
            == (v["bodies"]["message_redacted"])
        )

    def test_the_key_envelope_digest_is_independently_reproducible(self):
        """Guards the fixture: agreement with a file both sides regenerate would
        pass for any value, including a broken one."""
        v = _vectors()
        # Built by hand, sorted by hand: alg < encKey < iv < kem < v. The
        # integer `v` (crypto-core 3.0.0) is the case worth pinning — Python and
        # JS agree on an int's spelling, and on nothing about a bool's.
        canon = (
            "{"
            + ",".join(
                f'"{name}":{{"alg":"{e["alg"]}","encKey":"{e["encKey"]}",'
                f'"iv":"{e["iv"]}","kem":"{e["kem"]}","v":{e["v"]}}}'
                for name, e in sorted(v["message_keys"].items())
            )
            + "}"
        )
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert f"keysh={digest}" in v["bodies"]["message"]

    def test_binding_the_encryption_key_changes_the_bytes(self):
        v = _vectors()
        assert v["bodies"]["login"] != v["bodies"]["login_with_encryption_key"]
        assert v["bodies"]["login_with_encryption_key"].startswith(v["bodies"]["login"])


class TestARealLoginSignatureThroughTheEndpoint:
    """The one path nothing covered: a genuine ML-DSA-44 login signature,
    verified by the server, through POST /auth/login.

    conftest patches both verifiers autouse, so every other endpoint test logs
    in with the literal string "fake_signature_for_testing". That is the right
    default — those tests are about authorization, not crypto — but it meant the
    login challenge had no end-to-end coverage at all, while being the one
    string the client rebuilt from its own copy. These use the
    `real_signatures` marker to run against the actual verifiers.
    """

    @staticmethod
    def _sign(message: str, signer) -> str:
        # Base64 since the L-12 cutover, matching what crypto-core's
        # signMessage produces in the browser.
        return base64.b64encode(signer.sign(message.encode("utf-8"))).decode()

    @pytest.mark.real_signatures
    def test_a_genuine_signature_over_the_shared_body_logs_in(self, client):
        v = _vectors()
        enc_key = v["mlkem_public_key"]

        signer = MLDSA44Signer()
        address = signer.address
        nonce = get_nonce(client, address)
        # Built the way the SPA builds it: crypto-core's loginChallengeBody
        # is pinned against auth._login_message by the fixture tests above,
        # so signing the server's form is signing the client's form.
        signature = self._sign(
            auth._login_message(
                nonce,
                encryption_public_key=enc_key,
                origin=TEST_ORIGIN,
                deployment=server_deployment(),
            ),
            signer,
        )
        attestation = self._sign(auth.encryption_key_attestation_message(enc_key), signer)

        resp = client.post(
            "/auth/login",
            json={
                "address": address,
                "signature": signature,
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
                "encryption_public_key": enc_key,
                "encryption_key_attestation": attestation,
                "username": "RealLogin",
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["address"] == address.lower()

    @pytest.mark.real_signatures
    def test_a_signature_over_a_different_nonce_is_refused(self, client):
        """The replay case. Without it, a verifier that accepted anything would
        pass the test above just as happily.

        The submitted nonce is the real one the server just issued — signing a
        stale nonce and submitting THAT is caught earlier, by the nonce lookup,
        which would prove nothing about the signature.
        """
        signer = MLDSA44Signer()
        address = signer.address
        nonce = get_nonce(client, address)
        signature = self._sign(
            auth._login_message("a" * 32, origin=TEST_ORIGIN, deployment=server_deployment()),
            signer,
        )

        resp = client.post(
            "/auth/login",
            json={
                "address": address,
                "signature": signature,
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
            },
        )
        assert resp.status_code == 401, resp.text

    @pytest.mark.real_signatures
    def test_a_login_signature_without_the_encryption_key_bound_is_refused(self, client):
        """M-2: signing the bare challenge must not authorize an ML-KEM key, or
        a network attacker could attach one of their own to the login."""
        v = _vectors()
        signer = MLDSA44Signer()
        address = signer.address
        nonce = get_nonce(client, address)
        signature = self._sign(
            auth._login_message(nonce, origin=TEST_ORIGIN, deployment=server_deployment()),
            signer,
        )

        resp = client.post(
            "/auth/login",
            json={
                "address": address,
                "signature": signature,
                "nonce": nonce,
                "origin": TEST_ORIGIN,
                "deployment": server_deployment(),
                "encryption_public_key": v["mlkem_public_key"],
                "encryption_key_attestation": "fake_attestation_for_testing",
            },
        )
        assert resp.status_code == 401, resp.text

    @pytest.mark.real_signatures
    @pytest.mark.parametrize(
        "signed_for",
        [{"origin": "https://evil.example"}, {"deployment": "another-server"}],
        ids=["another-origin", "another-deployment"],
    )
    def test_a_genuine_signature_made_for_another_server_is_refused(
        self, client, signed_for, monkeypatch
    ):
        """K-02, with real crypto. The relay: a site that obtained a valid
        signature over a challenge naming ITSELF (or another deployment)
        submits it here, honestly reporting what it signed. The signature
        verifies; the server must still refuse, because it names someone else.

        With the allowlist production requires: in development an empty one
        accepts any origin, which is why this sets it."""
        monkeypatch.setenv("ALLOWED_ORIGINS", TEST_ORIGIN)
        server = {"origin": TEST_ORIGIN, "deployment": server_deployment(), **signed_for}
        signer = MLDSA44Signer()
        address = signer.address
        nonce = get_nonce(client, address)
        signature = self._sign(auth._login_message(nonce, **server), signer)

        resp = client.post(
            "/auth/login",
            json={"address": address, "signature": signature, "nonce": nonce, **server},
        )
        assert resp.status_code == 400, resp.text
        assert "signed for another" in resp.json()["detail"]
