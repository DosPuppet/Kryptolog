"""Deleting a conversation: hide it for me, or erase my side of it (audit 2026-09-11 M-6).

The erase is the account erase scoped to one conversation, so most of what is
tested here is the SCOPE: nothing outside the conversation is touched, nothing
of the other side's is touched, and a signature for one conversation cannot be
used on another.
"""

import json
from unittest.mock import patch

from conftest import TEST_ORIGIN, auth_header, get_nonce, server_deployment
from test_account_deletion import (
    DUMMY_SIG,
    _create_group,
    _delete,
    _dm_content,
    _group_content,
    _send_dm,
)

import models
import schemas


def _manifest(client, token, kind, conversation):
    resp = client.get(
        f"/conversations/{kind}/{conversation}/redactable-messages",
        params={"limit": 100},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _erase_round(client, token, address, kind, conversation, keys, signature=DUMMY_SIG):
    return client.post(
        f"/conversations/{kind}/{conversation}/erase",
        json={
            "nonce": get_nonce(client, address),
            "origin": TEST_ORIGIN,
            "deployment": server_deployment(),
            "signature": signature,
            "redactions": [{"key": k, "signature": DUMMY_SIG} for k in keys],
        },
        headers=auth_header(token),
    )


def _erase(client, token, address, kind, conversation):
    for _ in range(5):
        keys = [row["key"] for row in _manifest(client, token, kind, conversation)]
        resp = _erase_round(client, token, address, kind, conversation, keys)
        if resp.status_code != 409:
            return resp
    raise AssertionError("erase never finished")


def _content(db_session, model, message_id):
    db_session.expire_all()
    row = db_session.get(model, message_id)
    return None if row is None else json.loads(row.content)


class TestEraseADirectConversation:
    def test_only_my_messages_in_that_conversation_are_touched(
        self, client, db_session, user1, user2, user3
    ):
        token, me = user1
        bob_token, bob = user2
        _, carol = user3
        carrier = _send_dm(client, token, bob["address"], _dm_content("s-1"))
        plain = _send_dm(client, token, bob["address"], _dm_content("s-1", with_keys=False))
        elsewhere = _send_dm(client, token, carol["address"], _dm_content("s-2"))
        theirs = _send_dm(client, bob_token, me["address"], _dm_content("s-3"))

        resp = _erase(client, token, me["address"], "dm", bob["address"])
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "status": "erased",
            "redacted": 1,
            "deleted": 1,
            "kept": 0,
            "remaining": 0,
        }

        redacted = _content(db_session, models.Message, carrier["id"])
        assert redacted["ct"] is None and redacted["keys"]  # the key envelope stays
        assert _content(db_session, models.Message, plain["id"]) is None
        assert _content(db_session, models.Message, elsewhere["id"])["ct"] == "cipher"
        assert _content(db_session, models.Message, theirs["id"])["ct"] == "cipher"

    def test_it_takes_another_round_while_a_carrier_is_unredacted(self, client, user1, user2):
        token, me = user1
        _, bob = user2
        _send_dm(client, token, bob["address"], _dm_content("s-1"))
        resp = _erase_round(client, token, me["address"], "dm", bob["address"], [])
        assert resp.status_code == 409
        assert resp.json()["remaining"] == 1

    def test_a_redaction_from_another_conversation_cannot_ride_along(
        self, client, db_session, user1, user2, user3
    ):
        token, me = user1
        _, bob = user2
        _, carol = user3
        other = _send_dm(client, token, carol["address"], _dm_content("s-2"))
        key = f"dm:{other['id']}"

        resp = _erase_round(client, token, me["address"], "dm", bob["address"], [key])
        assert resp.status_code == 400
        assert _content(db_session, models.Message, other["id"])["ct"] == "cipher"

    def test_the_signature_names_this_conversation(self, client, user1, user2):
        """What is verified is the body for the conversation in the PATH, so an
        approval for one conversation cannot be replayed on another."""
        token, me = user1
        _, bob = user2
        seen = []

        def capture(address, message, signature):
            seen.append(message)
            return True

        with patch("auth.verify_identity_signature", side_effect=capture):
            _erase_round(client, token, me["address"], "dm", bob["address"].upper(), [])
        assert seen and seen[0].split("\n")[1] == "context=conversation-erase"
        assert f"\nconversation=dm:{bob['address']}\n" in seen[0]

    def test_a_bad_signature_changes_nothing(self, client, db_session, user1, user2):
        token, me = user1
        _, bob = user2
        carrier = _send_dm(client, token, bob["address"], _dm_content("s-1"))
        with patch("auth.verify_identity_signature", return_value=False):
            resp = _erase_round(
                client, token, me["address"], "dm", bob["address"], [f"dm:{carrier['id']}"]
            )
        assert resp.status_code == 401
        assert _content(db_session, models.Message, carrier["id"])["ct"] == "cipher"


class TestEraseAGroup:
    def test_my_group_messages_go_and_the_others_stay(self, client, db_session, user1, user2):
        token, me = user1
        bob_token, bob = user2
        gid = _create_group(client, token, [bob["address"]])
        members = [me["address"], bob["address"]]

        def post(tok, content):
            resp = client.post(
                f"/groups/{gid}/messages", json={"content": content}, headers=auth_header(tok)
            )
            assert resp.status_code == 200, resp.text
            return resp.json()["id"]

        mine = post(token, _group_content("g-1", gid, members))
        theirs = post(bob_token, _group_content("g-2", gid, members))

        assert _erase(client, token, me["address"], "group", gid).status_code == 200
        assert _content(db_session, models.GroupMessage, mine)["ct"] is None
        assert _content(db_session, models.GroupMessage, theirs)["ct"] == "cipher"


class TestHide:
    def _clear(self, client, token, kind, conversation):
        return client.post(
            f"/conversations/{kind}/{conversation}/clear", headers=auth_header(token)
        )

    def test_the_marker_is_the_newest_message_between_us(self, client, user1, user2, user3):
        token, me = user1
        bob_token, bob = user2
        _, carol = user3
        _send_dm(client, token, bob["address"], _dm_content("s-1"))
        latest = _send_dm(client, bob_token, me["address"], _dm_content("s-2"))
        _send_dm(client, token, carol["address"], _dm_content("s-3"))  # not ours

        resp = self._clear(client, token, "dm", bob["address"])
        assert resp.status_code == 200
        assert resp.json()["cleared_through_id"] == latest["id"]

        # Clearing again moves the marker rather than adding a second one.
        newer = _send_dm(client, bob_token, me["address"], _dm_content("s-4"))
        assert (
            self._clear(client, token, "dm", bob["address"]).json()["cleared_through_id"]
            == newer["id"]
        )
        clears = client.get("/conversations/clears", headers=auth_header(token)).json()
        assert [(c["kind"], c["cleared_through_id"]) for c in clears] == [("dm", newer["id"])]
        # Bob's view of the same conversation is his own business.
        assert client.get("/conversations/clears", headers=auth_header(bob_token)).json() == []

    def test_a_group_is_hidden_only_by_its_members(self, client, user1, user2, user3):
        token, _ = user1
        _, bob = user2
        outsider_token, _ = user3
        gid = _create_group(client, token, [bob["address"]])
        assert self._clear(client, token, "group", gid).status_code == 200
        # The newest id in a channel says how busy it is: not a stranger's business.
        assert self._clear(client, outsider_token, "group", gid).status_code == 404

    def test_an_account_erase_takes_the_markers_with_it(self, client, db_session, user1, user2):
        token, me = user1
        _, bob = user2
        self._clear(client, token, "dm", bob["address"])
        assert _delete(client, token, me["address"], "erase").status_code == 200
        assert (
            db_session.query(models.ConversationClear).filter_by(user_address=me["address"]).count()
            == 0
        )


def test_a_conversation_must_be_one(client, user1):
    token, _ = user1
    assert (
        client.post("/conversations/dm/not-hex/clear", headers=auth_header(token)).status_code
        == 400
    )
    assert (
        client.post("/conversations/group/a%20b/clear", headers=auth_header(token)).status_code
        == 400
    )
    assert (
        client.post("/conversations/mail/ab/clear", headers=auth_header(token)).status_code == 422
    )


def test_one_round_is_bounded_like_the_account_erase():
    field = schemas.ConversationEraseRequest.model_fields["redactions"]
    assert any(
        getattr(m, "max_length", None) == schemas.MAX_REDACTIONS_PER_DELETE for m in field.metadata
    )
