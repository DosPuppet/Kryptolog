"""List-endpoint pagination (audit O-3).

`GET /secrets`, `/secrets/shared-with-me`, `/secrets/{id}/access`,
`/multisig/workflows` and `GET /groups` used to return every row the caller
could see, in one response, with no ceiling a client could not raise. Secrets
and workflows carry their `encrypted_data` inline — 500 KB apiece by schema —
so the response size was set by how much the account happened to hold, against
a worker PM2 restarts at 500 MB.

Rows are inserted directly rather than through the API: these tests need more
rows than the endpoints' own rate limits allow to be created in a minute, and
the creation path is not what is under test.
"""
import uuid
from datetime import datetime, timedelta, timezone

import models
from conftest import (
    TEST_ENCRYPTION_KEY,
    auth_header,
)

# Deliberately more than one default page (50) but less than two, so a full
# walk is exactly two requests and a short second page proves the end.
MANY = 60


def _ids(response):
    assert response.status_code == 200, response.text
    return [row["id"] for row in response.json()]


def _make_secrets(db_session, owner, count, shared_with=None):
    """`count` secrets owned by `owner`, each with the owner's own grant, and
    optionally a grant to a second address."""
    secrets = []
    for i in range(count):
        secret = models.Secret(
            owner_address=owner,
            name=f"secret-{i}",
            type="note",
            encrypted_data="ab" * 8,
        )
        db_session.add(secret)
        db_session.flush()
        db_session.add(models.AccessGrant(
            secret_id=secret.id, grantee_address=owner, encrypted_key="00ff",
        ))
        if shared_with:
            db_session.add(models.AccessGrant(
                secret_id=secret.id, grantee_address=shared_with, encrypted_key="11ee",
            ))
        secrets.append(secret)
    db_session.commit()
    return secrets


class TestSecretListPaging:
    def test_owned_secrets_are_paged_not_dumped(self, client, user1, db_session):
        token, user = user1
        _make_secrets(db_session, user["address"], MANY)

        first = _ids(client.get("/secrets", headers=auth_header(token)))
        assert len(first) == 50, "the default page is unbounded again"

        second = _ids(client.get("/secrets?offset=50", headers=auth_header(token)))
        assert len(second) == MANY - 50

        # A walk must see every row exactly once: the page boundary is only
        # meaningful if the order behind it is deterministic.
        assert not set(first) & set(second), "pages overlap"
        assert len(set(first) | set(second)) == MANY, "a row fell between pages"

    def test_page_size_is_bounded_at_both_ends(self, client, user1, db_session):
        token, user = user1
        _make_secrets(db_session, user["address"], 3)

        # Above the ceiling: refused, not silently clamped — a client asking
        # for 5000 rows is asking for something the endpoint will not do.
        assert client.get("/secrets?limit=101", headers=auth_header(token)).status_code == 422
        # Below the floor. `?limit=-1` reaches PostgreSQL as `LIMIT -1`, a hard
        # error, when only the ceiling is checked (the GET /users precedent).
        assert client.get("/secrets?limit=0", headers=auth_header(token)).status_code == 422
        assert client.get("/secrets?limit=-1", headers=auth_header(token)).status_code == 422
        assert client.get("/secrets?offset=-1", headers=auth_header(token)).status_code == 422

        assert len(_ids(client.get("/secrets?limit=2", headers=auth_header(token)))) == 2

    def test_shared_with_me_is_paged(self, client, user1, user2, db_session):
        _, owner = user1
        token2, grantee = user2
        _make_secrets(db_session, owner["address"], MANY, shared_with=grantee["address"])

        first = _ids(client.get("/secrets/shared-with-me", headers=auth_header(token2)))
        second = _ids(client.get("/secrets/shared-with-me?offset=50", headers=auth_header(token2)))

        assert len(first) == 50
        assert len(second) == MANY - 50
        assert len(set(first) | set(second)) == MANY

    def test_grant_list_is_paged(self, client, user1, db_session):
        """`/secrets/{id}/access` grows with the number of people a secret is
        shared with, which the owner controls but the endpoint did not bound."""
        token, user = user1
        secret = _make_secrets(db_session, user["address"], 1)[0]

        # Grantees must exist: access_grants.grantee_address is an FK.
        for i in range(120):
            addr = f"{i:04x}" * 656  # 2624 hex chars, the address shape
            db_session.add(models.User(address=addr, encryption_public_key=TEST_ENCRYPTION_KEY))
            db_session.flush()
            db_session.add(models.AccessGrant(
                secret_id=secret.id, grantee_address=addr, encrypted_key="22dd",
            ))
        db_session.commit()

        page = client.get(f"/secrets/{secret.id}/access", headers=auth_header(token))
        assert len(_ids(page)) == 100, "grant list is unbounded"
        rest = client.get(f"/secrets/{secret.id}/access?offset=100&limit=200",
                          headers=auth_header(token))
        assert len(_ids(rest)) == 21  # 120 grantees + the owner's own grant


class TestWorkflowListPaging:
    def _workflow(self, db_session, owner, *, status="pending", signer=None, recipient=None):
        secret = models.Secret(owner_address=owner, name="wf-secret", type="note",
                               encrypted_data="ab" * 8)
        db_session.add(secret)
        db_session.flush()
        db_session.add(models.AccessGrant(
            secret_id=secret.id, grantee_address=owner, encrypted_key="00ff"))
        wf = models.MultisigWorkflow(
            name="wf", owner_address=owner, secret_id=secret.id,
            status=status, threshold=1,
        )
        db_session.add(wf)
        db_session.flush()
        if signer:
            db_session.add(models.MultisigWorkflowSigner(
                workflow_id=wf.id, user_address=signer, has_signed=False))
        if recipient:
            db_session.add(models.MultisigWorkflowRecipient(
                workflow_id=wf.id, user_address=recipient, encrypted_key="33cc"))
        db_session.commit()
        return wf

    def test_workflows_are_paged(self, client, user1, db_session):
        token, user = user1
        for _ in range(MANY):
            self._workflow(db_session, user["address"])

        first = _ids(client.get("/multisig/workflows", headers=auth_header(token)))
        second = _ids(client.get("/multisig/workflows?offset=50", headers=auth_header(token)))

        assert len(first) == 50, "workflow list is unbounded"
        assert len(second) == MANY - 50
        assert len(set(first) | set(second)) == MANY

    def test_paging_does_not_widen_who_can_see_what(self, client, user1, user2, db_session):
        """Paging moved the three access rules from a Python merge into one
        SQL filter (audit O-2). The rules must be the same ones: a recipient
        sees a completed workflow and never a pending one, whatever the page.
        """
        _, owner = user1
        token2, other = user2

        visible = {
            self._workflow(db_session, owner["address"], signer=other["address"]).id,
            self._workflow(db_session, owner["address"], status="completed",
                           recipient=other["address"]).id,
        }
        hidden = {
            self._workflow(db_session, owner["address"]).id,
            self._workflow(db_session, owner["address"], recipient=other["address"]).id,
        }

        seen = set(_ids(client.get("/multisig/workflows?limit=1", headers=auth_header(token2))))
        seen |= set(_ids(client.get("/multisig/workflows?limit=1&offset=1",
                                    headers=auth_header(token2))))

        assert seen == visible
        assert not seen & hidden


class TestGroupListPaging:
    def _group(self, db_session, members, last_message_at=None):
        channel = models.GroupChannel(
            id=str(uuid.uuid4()), name="grp", owner_address=members[0],
        )
        db_session.add(channel)
        for i, addr in enumerate(members):
            db_session.add(models.GroupMember(
                channel_id=channel.id, user_address=addr,
                role="owner" if i == 0 else "member",
            ))
        if last_message_at is not None:
            db_session.add(models.GroupMessage(
                channel_id=channel.id, sender_address=members[0],
                content="ab", created_at=last_message_at,
            ))
        db_session.commit()
        return channel.id

    def test_groups_are_paged_in_activity_order(self, client, user1, db_session):
        """The most-recent-activity order had to move from Python into SQL:
        sorting after the fetch would only sort whichever rows the page held,
        so the first page would not be the most recent groups."""
        token, user = user1
        base = datetime.now(timezone.utc).replace(tzinfo=None)
        # Oldest activity first, so the expected order is the reverse.
        ids = [self._group(db_session, [user["address"]],
                           last_message_at=base - timedelta(hours=MANY - i))
               for i in range(MANY)]
        expected = list(reversed(ids))

        first = [row["channel"]["id"] for row in
                 client.get("/groups", headers=auth_header(token)).json()]
        second = [row["channel"]["id"] for row in
                  client.get("/groups?offset=50", headers=auth_header(token)).json()]

        assert len(first) == 50, "group list is unbounded"
        assert first == expected[:50], "the first page is not the most recent groups"
        assert second == expected[50:]

    def test_a_group_with_no_messages_sorts_on_its_creation(self, client, user1, db_session):
        """What the Python sort did, kept: an empty channel falls back to its
        own created_at rather than sinking below every channel that has one."""
        token, user = user1
        base = datetime.now(timezone.utc).replace(tzinfo=None)
        old = self._group(db_session, [user["address"]],
                          last_message_at=base - timedelta(days=2))
        empty = self._group(db_session, [user["address"]])

        order = [row["channel"]["id"] for row in
                 client.get("/groups", headers=auth_header(token)).json()]
        assert order == [empty, old]

    def test_paging_does_not_leak_other_peoples_groups(self, client, user1, user2, db_session):
        _, member = user1
        token2, outsider = user2
        for _ in range(3):
            self._group(db_session, [member["address"]])

        assert client.get("/groups", headers=auth_header(token2)).json() == []


class TestConversationListPaging:
    """`GET /messages/conversations` is not named in O-3, which lists the
    secret, workflow and group endpoints — but it has the same shape: one row
    per person the user has ever messaged, returned in full."""

    def test_conversations_are_paged_most_recent_first(self, client, user1, db_session):
        token, user = user1
        base = datetime.now(timezone.utc).replace(tzinfo=None)

        partners = []
        for i in range(MANY):
            addr = f"{i:04x}" * 656
            db_session.add(models.User(address=addr, encryption_public_key=TEST_ENCRYPTION_KEY))
            db_session.flush()
            db_session.add(models.Message(
                sender_address=addr, recipient_address=user["address"],
                content="ab", created_at=base - timedelta(minutes=MANY - i),
            ))
            partners.append(addr)
        db_session.commit()
        expected = list(reversed(partners))  # newest first

        first = client.get("/messages/conversations", headers=auth_header(token)).json()
        second = client.get("/messages/conversations?offset=50", headers=auth_header(token)).json()

        assert len(first) == 50, "conversation list is unbounded"
        assert [c["user"]["address"] for c in first] == expected[:50]
        assert [c["user"]["address"] for c in second] == expected[50:]

    def test_unread_counts_survive_paging(self, client, user1, user2, db_session):
        """The unread counts used to be loaded for every partner at once; they
        are now scoped to the page, which must not change what they say."""
        token, user = user1
        _, partner = user2
        for _ in range(3):
            db_session.add(models.Message(
                sender_address=partner["address"], recipient_address=user["address"],
                content="ab", is_read=False,
            ))
        db_session.commit()

        rows = client.get("/messages/conversations", headers=auth_header(token)).json()
        assert [r["unread_count"] for r in rows] == [3]
