"""Deleting your own account, in both modes.

The two modes exist because erasing a user's content and removing a user are
different things when somebody else holds the other half of the conversation:

* **leave** keeps every row and only removes the identity. Reversible.
* **erase** removes the user's content too, and blocks the key forever.

Most of what is worth testing here is what erase does NOT delete, and why. A DM
session key is wrapped for both sides and embedded in the FIRST message under
that sid, and the partner's own replies reuse that sid carrying `keys: null`.
Delete the opener and the partner loses their *own authored history* on the
next reload — silently, because a message that cannot be decrypted looks the
same as one that was never readable. So those messages are redacted under a
signature the author produced, not deleted.
"""

import base64
import json
import pathlib
import re

import pytest
from conftest import (
    TEST_ENCRYPTION_KEY,
    auth_header,
    do_login,
    get_nonce,
    synthetic_address,
)

import account_deletion
import auth
import models
import schemas
from utils.clock import utcnow_naive

# Right shape, wrong content: the schema checks the exact base64 length of an
# ML-DSA-44 signature, while conftest patches the verifier itself to True for
# every test without the real_signatures marker.
DUMMY_SIG = base64.b64encode(b"\x00" * 2420).decode()


def _wrapped(tag):
    return {"kem": f"kem-{tag}", "iv": f"iv-{tag}", "encKey": f"key-{tag}"}


def _dm_content(sid, *, with_keys=True, ct="cipher"):
    """A DM payload. `with_keys` marks it as the epoch opener — the one that
    carries the session key both sides need."""
    payload = {"v": 1, "sid": sid, "ct": ct, "sig": DUMMY_SIG}
    payload["keys"] = (
        {"recip": _wrapped("recip"), "sender": _wrapped("sender")} if with_keys else None
    )
    return json.dumps(payload)


def _group_content(sid, channel_id, addresses, *, with_keys=True, ct="cipher"):
    payload = {"v": 2, "sid": sid, "gid": channel_id, "ct": ct, "sig": DUMMY_SIG}
    payload["keys"] = {a: _wrapped(a[:8]) for a in addresses} if with_keys else None
    return json.dumps(payload)


def _send_dm(client, token, recipient, content):
    resp = client.post(
        "/messages",
        json={"recipient_address": recipient, "content": content},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _create_group(client, token, members, name="Team"):
    resp = client.post(
        "/groups",
        json={"name": name, "member_addresses": members},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _manifest(client, token, want=100):
    """The manifest, paged to `want` rows the way the SPA reads one round."""
    rows, page = [], 100
    while len(rows) < want:
        resp = client.get(
            "/account/redactable-messages",
            params={"limit": page, "offset": len(rows)},
            headers=auth_header(token),
        )
        assert resp.status_code == 200, resp.text
        got = resp.json()
        rows += got
        if len(got) < page:
            break
    return rows[:want]


def _delete(client, token, address, mode, redactions=None, signature=DUMMY_SIG):
    nonce = get_nonce(client, address)
    return client.post(
        "/account/delete",
        json={
            "mode": mode,
            "nonce": nonce,
            "signature": signature,
            "redactions": redactions or [],
        },
        headers=auth_header(token),
    )


def _erase(client, token, address, max_rounds=10):
    """Erase, driving the rounds the way the SPA does.

    One request carries at most schemas.MAX_REDACTIONS_PER_DELETE signatures,
    so the server answers 409-with-a-count until every carrier is redacted.
    Nothing in this file needs more than one round; the loop is here so the
    tests exercise the same contract the client does.
    """
    for _ in range(max_rounds):
        redactions = [
            {"key": row["key"], "signature": DUMMY_SIG}
            for row in _manifest(client, token, want=schemas.MAX_REDACTIONS_PER_DELETE)
        ]
        resp = _delete(client, token, address, "erase", redactions)
        if resp.status_code != 409:
            return resp
    raise AssertionError("erase never finished")


class TestLeaveKeepsEverything:
    def test_every_row_survives(self, client, db_session, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        client.post(
            "/secrets",
            json={
                "name": "mine",
                "type": "standard",
                "encrypted_data": "blob",
                "encrypted_key": "key",
            },
            headers=auth_header(token1),
        )
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        channel = _create_group(client, token1, [u1["address"], u2["address"]])
        client.post(
            f"/groups/{channel}/messages",
            json={"content": _group_content("g-1", channel, [u1["address"], u2["address"]])},
            headers=auth_header(token1),
        )

        assert _delete(client, token1, u1["address"], "leave").status_code == 200

        addr = u1["address"]
        assert db_session.query(models.Secret).filter_by(owner_address=addr).count() == 1
        assert db_session.query(models.Message).filter_by(sender_address=addr).count() == 1
        assert db_session.query(models.GroupMessage).filter_by(sender_address=addr).count() == 1
        # ...and the content is untouched, not redacted.
        msg = db_session.query(models.Message).filter_by(sender_address=addr).first()
        assert json.loads(msg.content)["ct"] == "cipher"

    def test_the_identity_is_stripped_but_not_blocked(self, client, db_session, user1):
        token, u1 = user1
        assert _delete(client, token, u1["address"], "leave").status_code == 200

        db_session.expire_all()
        user = db_session.query(models.User).filter_by(address=u1["address"]).one()
        assert user.deleted_at is not None
        assert user.blocked is False
        assert user.username is None
        assert user.encryption_public_key is None
        assert user.encryption_key_attestation is None

    def test_group_membership_goes_and_ownership_is_handed_over(
        self, client, db_session, user1, user2
    ):
        """Leaving still means leaving. A stripped row has no encryption key,
        so the group could not wrap its next session key to them — staying
        would make them a member nobody can reach."""
        token1, u1 = user1
        _, u2 = user2
        channel = _create_group(client, token1, [u1["address"], u2["address"]])

        assert _delete(client, token1, u1["address"], "leave").status_code == 200

        db_session.expire_all()
        members = db_session.query(models.GroupMember).filter_by(channel_id=channel).all()
        assert [m.user_address for m in members] == [u2["address"]]
        assert members[0].role == "owner"
        assert (
            db_session.query(models.GroupChannel).filter_by(id=channel).one().owner_address
            == u2["address"]
        )


class TestTheIdentityDisappears:
    def test_the_session_dies_immediately(self, client, user1):
        token, u1 = user1
        assert _delete(client, token, u1["address"], "leave").status_code == 200
        assert client.get("/users", headers=auth_header(token)).status_code == 401

    def test_the_directory_stops_listing_but_still_resolves(self, client, user1, user2):
        """Both halves of the rule at once. The listing is for PICKING someone,
        so a deleted identity must not appear; the by-address lookups have to
        keep answering, or a message that still names the address renders as an
        unknown stranger instead of a removed user."""
        token1, u1 = user1
        token2, _ = user2
        assert _delete(client, token1, u1["address"], "leave").status_code == 200

        listed = client.get("/users", headers=auth_header(token2)).json()
        assert u1["address"] not in [u["address"] for u in listed]

        resolved = client.get(f"/users/{u1['address']}", headers=auth_header(token2))
        assert resolved.status_code == 200
        assert resolved.json()["deleted"] is True
        assert resolved.json()["username"] is None

    @pytest.mark.parametrize("mode", ["leave", "erase"])
    def test_a_deleted_identity_is_not_a_valid_counterparty(self, client, user1, user2, mode):
        """One table over every endpoint that takes an address, because
        forgetting a single one is the KRY-001 shape: the rule would hold
        everywhere it was remembered and nowhere else."""
        token1, u1 = user1
        token2, u2 = user2
        gone = u1["address"]
        assert _delete(client, token1, gone, mode).status_code == 200

        assert (
            client.post(
                "/messages",
                json={"recipient_address": gone, "content": "hi"},
                headers=auth_header(token2),
            ).status_code
            == 404
        )
        secret = client.post(
            "/secrets",
            json={
                "name": "s",
                "type": "standard",
                "encrypted_data": "b",
                "encrypted_key": "k",
            },
            headers=auth_header(token2),
        ).json()
        assert (
            client.post(
                "/secrets/share",
                json={"secret_id": secret["id"], "grantee_address": gone, "encrypted_key": "k"},
                headers=auth_header(token2),
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/groups",
                json={"name": "g", "member_addresses": [u2["address"], gone]},
                headers=auth_header(token2),
            ).status_code
            == 404
        )
        channel = _create_group(client, token2, [u2["address"]])
        assert (
            client.post(
                f"/groups/{channel}/members",
                json={"user_address": gone},
                headers=auth_header(token2),
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/multisig/workflow",
                json={
                    "name": "w",
                    "secret_data": {
                        "name": "s",
                        "type": "standard",
                        "encrypted_data": "b",
                        "encrypted_key": "k",
                    },
                    "signers": [gone],
                    "recipients": [],
                    "signer_keys": {gone: "k"},
                    "recipient_keys": {},
                    "threshold": 1,
                },
                headers=auth_header(token2),
            ).status_code
            == 400
        )


class TestComingBack:
    def test_leaving_can_be_undone_and_the_data_is_still_there(self, client, db_session, user1):
        token, u1 = user1
        client.post(
            "/secrets",
            json={
                "name": "mine",
                "type": "standard",
                "encrypted_data": "blob",
                "encrypted_key": "key",
            },
            headers=auth_header(token),
        )
        assert _delete(client, token, u1["address"], "leave").status_code == 200

        new_token, revived = do_login(client, u1["address"], TEST_ENCRYPTION_KEY, "BackAgain")
        assert revived["username"] == "BackAgain"
        assert revived["deleted"] is False

        secrets = client.get("/secrets", headers=auth_header(new_token)).json()
        assert [s["name"] for s in secrets] == ["mine"]

    def test_an_erased_key_can_never_register_again(self, client, user1):
        token, u1 = user1
        assert _erase(client, token, u1["address"]).status_code == 200

        nonce = get_nonce(client, u1["address"])
        resp = client.post(
            "/auth/login",
            json={
                "address": u1["address"],
                "signature": "fake_signature_for_testing",
                "nonce": nonce,
                "encryption_public_key": TEST_ENCRYPTION_KEY,
                "username": "Rebirth",
            },
        )
        # 410, not 403: the invite gate answers 403 and the SPA turns that into
        # "enter your invite code", which is advice that cannot possibly work
        # for a key that is blocked forever.
        assert resp.status_code == 410, resp.text
        assert "no longer be used" in resp.json()["detail"]

    def test_a_fresh_key_still_registers(self, client, user1):
        """The other half: the block must name one key, not close the door."""
        token, u1 = user1
        assert _erase(client, token, u1["address"]).status_code == 200
        _, user = do_login(client, synthetic_address("after-erase"), TEST_ENCRYPTION_KEY, "NewOne")
        assert user["username"] == "NewOne"

    def test_the_nonce_endpoint_stays_silent_about_deletion(self, client, user1):
        """It is unauthenticated, so refusing there would answer "was this
        address deleted?" for anybody who asks. The refusal belongs at login,
        which only the key holder reaches."""
        token, u1 = user1
        assert _erase(client, token, u1["address"]).status_code == 200
        assert client.get(f"/auth/nonce/{u1['address']}").status_code == 200


class TestErasingMessages:
    def test_the_epoch_opener_is_redacted_and_the_partner_keeps_their_own(
        self, client, db_session, user1, user2
    ):
        """The test the whole design exists for.

        user1 opens the session, user2 replies under the same sid carrying no
        keys of its own. Erasing user1 must leave the opener's key envelope
        readable, or user2 loses the message user2 wrote.
        """
        token1, u1 = user1
        token2, u2 = user2
        opener = _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        _send_dm(client, token2, u1["address"], _dm_content("sid-1", with_keys=False))

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        row = db_session.query(models.Message).filter_by(id=opener["id"]).one()
        payload = json.loads(row.content)
        assert payload["ct"] is None, "the author's content must be gone"
        assert payload["keys"]["recip"] == _wrapped("recip"), "the partner's key must survive"
        assert payload["sid"] == "sid-1"

        reply = db_session.query(models.Message).filter_by(sender_address=u2["address"]).one()
        assert json.loads(reply.content)["ct"] == "cipher"

    def test_messages_with_no_envelope_are_deleted_outright(self, client, db_session, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        plain = _send_dm(client, token1, u2["address"], _dm_content("sid-1", with_keys=False))

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        assert db_session.query(models.Message).filter_by(id=plain["id"]).first() is None

    def test_unparseable_content_is_kept_rather_than_guessed_at(
        self, client, db_session, user1, user2
    ):
        """Fail safe: a row this cannot read might be carrying the only copy of
        a session key, and deleting it would be unrecoverable."""
        token1, u1 = user1
        _, u2 = user2
        legacy = _send_dm(client, token1, u2["address"], "not json at all")

        assert _erase(client, token1, u1["address"]).status_code == 200
        db_session.expire_all()
        assert db_session.query(models.Message).filter_by(id=legacy["id"]).first() is not None

    def test_group_messages_follow_the_same_rule(self, client, db_session, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        channel = _create_group(client, token1, [u1["address"], u2["address"]])
        members = [u1["address"], u2["address"]]
        opener = client.post(
            f"/groups/{channel}/messages",
            json={"content": _group_content("g-1", channel, members)},
            headers=auth_header(token1),
        ).json()
        plain = client.post(
            f"/groups/{channel}/messages",
            json={"content": _group_content("g-1", channel, members, with_keys=False)},
            headers=auth_header(token1),
        ).json()

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        kept = db_session.query(models.GroupMessage).filter_by(id=opener["id"]).one()
        assert json.loads(kept.content)["ct"] is None
        assert json.loads(kept.content)["keys"][u2["address"]] is not None
        assert db_session.query(models.GroupMessage).filter_by(id=plain["id"]).first() is None

    def test_a_message_sent_after_the_manifest_aborts_the_whole_deletion(
        self, client, db_session, user1, user2
    ):
        """Closes the gap between reading the manifest and committing: a new
        epoch opener would otherwise be DELETED rather than redacted, taking
        the partner's history with it. Fail closed and make the client retry."""
        token1, u1 = user1
        _, u2 = user2
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        redactions = [
            {"key": row["key"], "signature": DUMMY_SIG} for row in _manifest(client, token1)
        ]

        latecomer = _send_dm(client, token1, u2["address"], _dm_content("sid-2"))

        resp = _delete(client, token1, u1["address"], "erase", redactions)
        assert resp.status_code == 409, resp.text

        db_session.expire_all()
        assert db_session.query(models.Message).filter_by(id=latecomer["id"]).first() is not None
        assert (
            db_session.query(models.User).filter_by(address=u1["address"]).one().deleted_at is None
        )

    def test_leaving_may_not_carry_redactions(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        redactions = [
            {"key": row["key"], "signature": DUMMY_SIG} for row in _manifest(client, token1)
        ]
        assert _delete(client, token1, u1["address"], "leave", redactions).status_code == 400

    def test_the_manifest_only_lists_envelope_carriers(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        opener = _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        _send_dm(client, token1, u2["address"], _dm_content("sid-1", with_keys=False))

        manifest = _manifest(client, token1)
        assert [row["id"] for row in manifest] == [opener["id"]]
        assert manifest[0]["kind"] == "dm"
        assert manifest[0]["key"] == f"dm:{opener['id']}"
        # conv comes from the delivered row, never from the payload (F-1).
        assert manifest[0]["conv"] == u2["address"]


class TestErasingTheRest:
    def test_secrets_and_grants_go(self, client, db_session, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        secret = client.post(
            "/secrets",
            json={
                "name": "mine",
                "type": "standard",
                "encrypted_data": "blob",
                "encrypted_key": "key",
            },
            headers=auth_header(token1),
        ).json()
        client.post(
            "/secrets/share",
            json={
                "secret_id": secret["id"],
                "grantee_address": u2["address"],
                "encrypted_key": "k",
            },
            headers=auth_header(token1),
        )

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        assert db_session.query(models.Secret).filter_by(id=secret["id"]).first() is None
        assert db_session.query(models.AccessGrant).filter_by(secret_id=secret["id"]).count() == 0

    def test_a_completed_workflow_survives_with_its_secret(self, client, db_session, user1, user2):
        """workflow_is_deletable already refuses to delete a completed workflow
        because the recipients' wrapped keys are their only copy. Account
        deletion must not become a way to retract a release after the fact."""
        token1, u1 = user1
        _, u2 = user2
        resp = client.post(
            "/multisig/workflow",
            json={
                "name": "w",
                "secret_data": {
                    "name": "released",
                    "type": "standard",
                    "encrypted_data": "blob",
                    "encrypted_key": "k",
                },
                "signers": [u1["address"]],
                "recipients": [u2["address"]],
                "signer_keys": {u1["address"]: "k"},
                "recipient_keys": {u2["address"]: "k"},
                "threshold": 1,
            },
            headers=auth_header(token1),
        )
        assert resp.status_code == 200, resp.text
        workflow_id = resp.json()["id"]
        secret_id = resp.json()["secret"]["id"]
        signed = client.post(
            f"/multisig/workflow/{workflow_id}/sign",
            json={"signature": DUMMY_SIG},
            headers=auth_header(token1),
        )
        assert signed.status_code == 200, signed.text

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        assert db_session.query(models.MultisigWorkflow).filter_by(id=workflow_id).first()
        assert db_session.query(models.Secret).filter_by(id=secret_id).first()

    def test_a_pending_workflow_goes_with_its_secret(self, client, db_session, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        resp = client.post(
            "/multisig/workflow",
            json={
                "name": "w",
                "secret_data": {
                    "name": "draft",
                    "type": "standard",
                    "encrypted_data": "blob",
                    "encrypted_key": "k",
                },
                "signers": [u2["address"]],
                "recipients": [],
                "signer_keys": {u2["address"]: "k"},
                "recipient_keys": {},
                "threshold": 1,
            },
            headers=auth_header(token1),
        )
        workflow_id, secret_id = resp.json()["id"], resp.json()["secret"]["id"]

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        assert db_session.query(models.MultisigWorkflow).filter_by(id=workflow_id).first() is None
        assert db_session.query(models.Secret).filter_by(id=secret_id).first() is None

    def test_a_signature_given_on_someone_elses_workflow_survives(
        self, client, db_session, user1, user2
    ):
        """It is the workflow owner's evidence, not the signer's property — and
        removing a signer leaves a quorum that can never be met."""
        token1, u1 = user1
        token2, u2 = user2
        resp = client.post(
            "/multisig/workflow",
            json={
                "name": "theirs",
                "secret_data": {
                    "name": "s",
                    "type": "standard",
                    "encrypted_data": "blob",
                    "encrypted_key": "k",
                },
                "signers": [u1["address"], u2["address"]],
                "recipients": [],
                "signer_keys": {u1["address"]: "k", u2["address"]: "k"},
                "recipient_keys": {},
                "threshold": 2,
            },
            headers=auth_header(token2),
        )
        workflow_id = resp.json()["id"]
        client.post(
            f"/multisig/workflow/{workflow_id}/sign",
            json={"signature": DUMMY_SIG},
            headers=auth_header(token1),
        )

        assert _erase(client, token1, u1["address"]).status_code == 200

        db_session.expire_all()
        signer = (
            db_session.query(models.MultisigWorkflowSigner)
            .filter_by(workflow_id=workflow_id, user_address=u1["address"])
            .one()
        )
        assert signer.has_signed is True
        assert signer.signature == DUMMY_SIG

    def test_invite_codes_survive_without_their_creator(self, client, db_session, user1):
        token, u1 = user1
        db_session.add(
            models.InviteCode(code="HANDED-OUT", created_by=u1["address"], max_uses=1, uses=0)
        )
        db_session.add(
            models.InviteCode(
                code="SPENT", created_by=None, used_by=u1["address"], max_uses=1, uses=1
            )
        )
        db_session.commit()

        assert _erase(client, token, u1["address"]).status_code == 200

        db_session.expire_all()
        handed = db_session.query(models.InviteCode).filter_by(code="HANDED-OUT").one()
        assert handed.created_by is None, "someone is about to redeem this"
        spent = db_session.query(models.InviteCode).filter_by(code="SPENT").one()
        assert spent.used_by is None
        assert spent.uses == 1, "decrementing would hand the access filter's budget back"


class TestAuthorizingTheDeletion:
    @staticmethod
    def _sign(message, signer):
        return base64.b64encode(signer.sign(message.encode("utf-8"))).decode()

    @classmethod
    def _real_login(cls, client, signer, address, username):
        """Log in for real. These tests carry the real_signatures marker, so
        conftest's stubbed verifier is not in play and do_login's literal
        "fake_signature_for_testing" would be refused."""
        nonce = get_nonce(client, address)
        resp = client.post(
            "/auth/login",
            json={
                "address": address,
                "signature": cls._sign(auth._login_message(nonce, TEST_ENCRYPTION_KEY), signer),
                "nonce": nonce,
                "encryption_public_key": TEST_ENCRYPTION_KEY,
                "username": username,
            },
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]

    @pytest.mark.real_signatures
    def test_a_genuine_signature_deletes_and_a_forged_one_does_not(self, client, db_session):
        import oqs

        with oqs.Signature(auth.SIG_ALG) as signer:
            address = signer.generate_keypair().hex()
            token = self._real_login(client, signer, address, "RealDelete")

            nonce = get_nonce(client, address)
            forged = client.post(
                "/account/delete",
                json={
                    "mode": "leave",
                    "nonce": nonce,
                    "signature": DUMMY_SIG,
                    "redactions": [],
                },
                headers=auth_header(token),
            )
            assert forged.status_code == 401, forged.text

            nonce = get_nonce(client, address)
            good = self._sign(auth.account_deletion_message(nonce, "leave", []), signer)
            resp = client.post(
                "/account/delete",
                json={"mode": "leave", "nonce": nonce, "signature": good, "redactions": []},
                headers=auth_header(token),
            )
            assert resp.status_code == 200, resp.text

    @pytest.mark.real_signatures
    def test_a_leave_signature_cannot_be_replayed_as_an_erase(self, client, db_session):
        """The mode is inside the signed body precisely so a relay cannot
        escalate a leave into an erase, destroying data the user asked to
        keep."""
        import oqs

        with oqs.Signature(auth.SIG_ALG) as signer:
            address = signer.generate_keypair().hex()
            token = self._real_login(client, signer, address, "ModeBound")
            nonce = get_nonce(client, address)
            leave_sig = self._sign(auth.account_deletion_message(nonce, "leave", []), signer)

            resp = client.post(
                "/account/delete",
                json={"mode": "erase", "nonce": nonce, "signature": leave_sig, "redactions": []},
                headers=auth_header(token),
            )
            assert resp.status_code == 401, resp.text
            db_session.expire_all()
            assert db_session.query(models.User).filter_by(address=address).one().deleted_at is None

    @pytest.mark.real_signatures
    def test_a_login_signature_over_the_same_nonce_is_refused(self, client):
        """H1: the contexts are disjoint, so a signature minted to log in
        cannot be spent to delete the account it logged into."""
        import oqs

        with oqs.Signature(auth.SIG_ALG) as signer:
            address = signer.generate_keypair().hex()
            token = self._real_login(client, signer, address, "ContextBound")
            nonce = get_nonce(client, address)
            login_sig = self._sign(auth._login_message(nonce, TEST_ENCRYPTION_KEY), signer)

            resp = client.post(
                "/account/delete",
                json={"mode": "leave", "nonce": nonce, "signature": login_sig, "redactions": []},
                headers=auth_header(token),
            )
            assert resp.status_code == 401, resp.text

    @pytest.mark.real_signatures
    def test_a_redaction_signature_is_actually_verified(self, client, db_session):
        """Needs the marker to mean anything: conftest patches the verifier to
        True by default, so without it this endpoint would be tested with no
        verification at all — the exact hole the login challenge sat in."""
        import oqs

        with oqs.Signature(auth.SIG_ALG) as signer:
            address = signer.generate_keypair().hex()
            token = self._real_login(client, signer, address, "Redactor")
            # The partner needs a real login too: under this marker nothing is
            # stubbed, so a synthetic address could never sign its challenge.
            with oqs.Signature(auth.SIG_ALG) as other:
                partner = other.generate_keypair().hex()
                self._real_login(client, other, partner, "Partner")
            _send_dm(client, token, partner, _dm_content("sid-1"))

            manifest = _manifest(client, token)
            assert len(manifest) == 1
            row = manifest[0]

            nonce = get_nonce(client, address)
            deletion_sig = self._sign(
                auth.account_deletion_message(nonce, "erase", [row["key"]]), signer
            )
            bad = client.post(
                "/account/delete",
                json={
                    "mode": "erase",
                    "nonce": nonce,
                    "signature": deletion_sig,
                    "redactions": [{"key": row["key"], "signature": DUMMY_SIG}],
                },
                headers=auth_header(token),
            )
            assert bad.status_code == 400, bad.text
            db_session.expire_all()
            assert db_session.query(models.User).filter_by(address=address).one().deleted_at is None

            nonce = get_nonce(client, address)
            body = auth.message_signing_body(
                from_=address,
                conv=row["conv"],
                gid="",
                sid=row["sid"],
                ct=None,
                keys=row["keys"],
            )
            resp = client.post(
                "/account/delete",
                json={
                    "mode": "erase",
                    "nonce": nonce,
                    "signature": self._sign(
                        auth.account_deletion_message(nonce, "erase", [row["key"]]), signer
                    ),
                    "redactions": [{"key": row["key"], "signature": self._sign(body, signer)}],
                },
                headers=auth_header(token),
            )
            assert resp.status_code == 200, resp.text

    def test_a_replayed_nonce_is_refused(self, client, user1):
        token, u1 = user1
        nonce = get_nonce(client, u1["address"])
        body = {"mode": "leave", "nonce": nonce, "signature": DUMMY_SIG, "redactions": []}
        assert (
            client.post("/account/delete", json=body, headers=auth_header(token)).status_code == 200
        )
        # The account is gone, so this 401s on the token before the nonce even
        # matters — which is itself the point: a deletion is not repeatable.
        assert (
            client.post("/account/delete", json=body, headers=auth_header(token)).status_code == 401
        )

    def test_a_duplicate_redaction_id_is_refused(self, client, user1, user2):
        """Two signatures for one message would make the signed set smaller
        than the list it was built from."""
        token1, u1 = user1
        _, u2 = user2
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))
        row = _manifest(client, token1)[0]
        duplicated = [
            {"key": row["key"], "signature": DUMMY_SIG},
            {"key": row["key"], "signature": DUMMY_SIG},
        ]
        assert _delete(client, token1, u1["address"], "erase", duplicated).status_code == 400


class TestTheRedactionEndpointIsNotAnEditor:
    def test_a_redaction_cannot_rewrite_the_key_envelope(self, client, db_session, user1, user2):
        """M-8's targeted-exclusion attack, executed with a valid signature: if
        the server took `keys` from the request it would be a general-purpose
        rewrite-my-past-messages API. It builds the payload from the stored row
        instead, so there is no field to rewrite."""
        token1, u1 = user1
        _, u2 = user2
        opener = _send_dm(client, token1, u2["address"], _dm_content("sid-1"))

        redactions = [{"key": f"dm:{opener['id']}", "signature": DUMMY_SIG}]
        assert _delete(client, token1, u1["address"], "erase", redactions).status_code == 200

        db_session.expire_all()
        payload = json.loads(
            db_session.query(models.Message).filter_by(id=opener["id"]).one().content
        )
        assert payload["keys"] == {"recip": _wrapped("recip"), "sender": _wrapped("sender")}

    def test_a_redaction_for_someone_elses_message_is_refused(
        self, client, db_session, user1, user2
    ):
        """Ownership is re-attested from the row, not trusted from the id.

        Each round names its own rows now, so this is the check that a caller
        cannot name a row that is not theirs — and "no such message" and "not
        yours" answer identically, so it cannot be used to probe which ids
        exist either.
        """
        token1, u1 = user1
        token2, u2 = user2
        theirs = _send_dm(client, token2, u1["address"], _dm_content("sid-x"))

        resp = _delete(
            client,
            token1,
            u1["address"],
            "erase",
            [{"key": f"dm:{theirs['id']}", "signature": DUMMY_SIG}],
        )
        assert resp.status_code == 400, resp.text
        assert "not one of your messages" in resp.json()["detail"]
        missing = _delete(
            client, token1, u1["address"], "erase", [{"key": "dm:999999", "signature": DUMMY_SIG}]
        )
        assert missing.json()["detail"] == resp.json()["detail"].replace(
            f"dm:{theirs['id']}", "dm:999999"
        )
        db_session.expire_all()
        assert (
            json.loads(db_session.query(models.Message).filter_by(id=theirs["id"]).one().content)[
                "ct"
            ]
            == "cipher"
        )


def test_the_module_refuses_an_unknown_mode(db_session):
    with pytest.raises(ValueError):
        account_deletion.delete_account(db_session, models.User(address="x"), "nuke")


class TestAnEraseIsNotBoundedByOneRequest:
    """`MAX_REDACTIONS_PER_DELETE` bounds a REQUEST, not an account.

    It used to bound both, which made an account permanently un-erasable once
    it passed the cap: over it the request was a 422, and one row short of it a
    409, with no way round either. Erase asks for one signature per session
    epoch the user ever opened and a group mints a fresh one per client per
    page load, so ordinary use reaches this in a couple of years (audit
    2026-09-12 M-2a).

    Seeded straight into the table: the point is the count, and posting a
    thousand messages through a 20/minute endpoint would test the rate limiter.
    """

    def _seed_carriers(self, db_session, sender, recipient, count):
        db_session.bulk_insert_mappings(
            models.Message,
            [
                {
                    "sender_address": sender,
                    "recipient_address": recipient,
                    "content": _dm_content(f"sid-{i}"),
                    "is_read": False,
                    "created_at": utcnow_naive(),
                }
                for i in range(count)
            ],
        )
        db_session.commit()

    def test_a_round_that_leaves_carriers_behind_reports_what_is_left(
        self, client, db_session, user1, user2
    ):
        """The 409 is progress, not a refusal: this round's redactions stand,
        so the next one is strictly smaller and the loop always terminates."""
        token1, u1 = user1
        _, u2 = user2
        over = schemas.MAX_REDACTIONS_PER_DELETE + 1
        self._seed_carriers(db_session, u1["address"], u2["address"], over)

        first = [
            {"key": row["key"], "signature": DUMMY_SIG}
            for row in _manifest(client, token1, want=schemas.MAX_REDACTIONS_PER_DELETE)
        ]
        assert len(first) == schemas.MAX_REDACTIONS_PER_DELETE

        resp = _delete(client, token1, u1["address"], "erase", first)
        assert resp.status_code == 409, resp.text
        body = resp.json()
        assert body["status"] == "redacting"
        assert body["redacted"] == schemas.MAX_REDACTIONS_PER_DELETE
        assert body["remaining"] == 1

        db_session.expire_all()
        # The account is untouched — it is not half-deleted while this runs.
        assert (
            db_session.query(models.User).filter_by(address=u1["address"]).one().deleted_at is None
        )
        # ...and the round's work was kept, so the manifest has shrunk to what
        # is left rather than starting over.
        assert len(_manifest(client, token1, want=over)) == 1

    def test_an_account_past_the_ceiling_still_erases_completely(
        self, client, db_session, user1, user2
    ):
        token1, u1 = user1
        _, u2 = user2
        over = schemas.MAX_REDACTIONS_PER_DELETE + 1
        self._seed_carriers(db_session, u1["address"], u2["address"], over)

        resp = _erase(client, token1, u1["address"])
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"status": "deleted", "redacted": 1, "kept": 0, "remaining": 0}

        db_session.expire_all()
        rows = db_session.query(models.Message).filter_by(sender_address=u1["address"]).all()
        # Every one redacted rather than deleted: each opened an epoch, and the
        # partner's own replies under that sid need the envelope.
        assert len(rows) == over
        assert all(json.loads(r.content)["ct"] is None for r in rows)
        assert all(json.loads(r.content)["keys"] for r in rows)
        assert db_session.query(models.User).filter_by(address=u1["address"]).one().blocked is True

    def test_a_redacted_message_is_not_offered_for_redaction_again(
        self, client, db_session, user1, user2
    ):
        """What makes the rounds terminate. A redacted row KEEPS its envelope,
        so a manifest that asked "does this carry keys?" would list it forever
        and the erase would never reach its fixed point."""
        token1, u1 = user1
        _, u2 = user2
        _send_dm(client, token1, u2["address"], _dm_content("sid-1"))

        assert _erase(client, token1, u1["address"]).status_code == 200
        db_session.expire_all()
        row = db_session.query(models.Message).filter_by(sender_address=u1["address"]).one()
        assert json.loads(row.content)["ct"] is None
        assert json.loads(row.content)["keys"]


class TestWhatAnEraseCannotRedactIsKeptAndCounted:
    """Two shapes cannot be signed for redaction, and each one used to refuse
    the WHOLE erase — permanently, since the account could not be deleted and
    the row could not be fixed (audit 2026-09-12 M-2b/M-2c).

    Both are now kept, like a row that does not parse, and counted back to the
    caller so "delete my content" does not quietly mean "most of it".
    """

    def _raw_dm(self, db_session, sender, recipient, payload):
        row = models.Message(
            sender_address=sender,
            recipient_address=recipient,
            content=json.dumps(payload),
            is_read=False,
        )
        db_session.add(row)
        db_session.commit()
        return row.id

    def test_an_envelope_the_two_languages_would_spell_differently(
        self, client, db_session, user1, user2
    ):
        token1, u1 = user1
        _, u2 = user2
        # One non-ASCII character: Python escapes it by default where JS does
        # not, so the two would hash different bytes. check_envelope_shape
        # refuses to guess — correctly — and that refusal used to be a 400 for
        # the entire deletion.
        odd = {"recip": {"kem": "clé", "iv": "iv", "encKey": "k"}, "sender": _wrapped("s")}
        stuck = self._raw_dm(
            db_session,
            u1["address"],
            u2["address"],
            {"v": 1, "sid": "sid-odd", "keys": odd, "ct": "cipher", "sig": DUMMY_SIG},
        )

        assert [r["id"] for r in _manifest(client, token1)] == []

        resp = _erase(client, token1, u1["address"])
        assert resp.status_code == 200, resp.text
        assert resp.json()["kept"] == 1

        db_session.expire_all()
        kept = db_session.query(models.Message).filter_by(id=stuck).one()
        assert json.loads(kept.content)["ct"] == "cipher"
        assert db_session.query(models.User).filter_by(address=u1["address"]).one().blocked is True

    def test_a_carrier_with_no_session_id(self, client, db_session, user1, user2):
        token1, u1 = user1
        _, u2 = user2
        # `sid=None` in Python against `sid=null` in JS — a silent divergence
        # inside a signature body. No client can adopt a session from such a
        # row either, since the key cache is addressed by (conversation, sid).
        stuck = self._raw_dm(
            db_session,
            u1["address"],
            u2["address"],
            {"v": 1, "keys": {"recip": _wrapped("r")}, "ct": "cipher", "sig": DUMMY_SIG},
        )

        assert [r["id"] for r in _manifest(client, token1)] == []

        resp = _erase(client, token1, u1["address"])
        assert resp.status_code == 200, resp.text
        assert resp.json()["kept"] == 1

        db_session.expire_all()
        assert (
            json.loads(db_session.query(models.Message).filter_by(id=stuck).one().content)["ct"]
            == "cipher"
        )

    def test_naming_one_of_them_in_a_round_is_refused(self, client, db_session, user1, user2):
        """They are excluded from the manifest, so a client asking to redact
        one is working from something other than the manifest. Fail closed
        rather than build a body the signature cannot have covered."""
        token1, u1 = user1
        _, u2 = user2
        stuck = self._raw_dm(
            db_session,
            u1["address"],
            u2["address"],
            {"v": 1, "keys": {"recip": _wrapped("r")}, "ct": "cipher", "sig": DUMMY_SIG},
        )

        resp = _delete(
            client,
            token1,
            u1["address"],
            "erase",
            [{"key": f"dm:{stuck}", "signature": DUMMY_SIG}],
        )
        assert resp.status_code == 400, resp.text
        assert "not a message this erase can redact" in resp.json()["detail"]

    def test_an_unreadable_row_is_counted_too(self, client, db_session, user1, user2):
        """Already the behaviour — `_payload` never guesses at a row it cannot
        read — but it was silent. Deletion is the one operation where the user
        cannot come back and check."""
        token1, u1 = user1
        _, u2 = user2
        row = models.Message(
            sender_address=u1["address"],
            recipient_address=u2["address"],
            content="not json at all",
            is_read=False,
        )
        db_session.add(row)
        db_session.commit()

        assert _erase(client, token1, u1["address"]).json()["kept"] == 1


def test_the_spa_never_asks_for_more_redactions_than_one_request_takes():
    """The client's round size and the server's per-request cap are two
    constants in two languages. The client asking for more would 422 — on
    exactly the large accounts the rounds exist for, and nowhere else, so
    nothing smaller would catch it.
    """
    source = (
        pathlib.Path(__file__).resolve().parents[2] / "frontend/src/context/PQCContext.jsx"
    ).read_text()
    match = re.search(r"const REDACTION_ROUND = (\d+);", source)
    assert match, "REDACTION_ROUND is gone from PQCContext.jsx"
    assert int(match.group(1)) <= schemas.MAX_REDACTIONS_PER_DELETE
