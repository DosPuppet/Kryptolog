"""The authorization rules exist once (audit O-2).

KRY-001 was not a missing check — it was the *same* check written twice and
then changed once: the listing endpoints filtered expired grants, the
file-chunk path did not. `security/authorization.py` exists so that cannot
happen again, but it only covered secrets; groups and multisig kept
re-deriving their rules at each call site, in three different spellings for
group membership alone.

Two of those rules genuinely have to exist in two forms — a predicate for one
row, a query for a listing that has to filter and page in the database. That
is exactly the shape KRY-001 came in, so the pairs are pinned against each
other here over every configuration a caller can be in. These tests do not
protect against a missing check; they protect against a one-sided edit.
"""

import uuid
from datetime import timedelta

import pytest
from conftest import TEST_ENCRYPTION_KEY, auth_header, synthetic_address

import models
from security import authorization
from utils.clock import utcnow_naive

STATUSES = ("pending", "completed", "rejected")
ROLES = ("owner", "signer", "recipient", "signer+recipient", "stranger")


def _user(db_session, tag):
    address = synthetic_address(tag)
    if not db_session.query(models.User).filter_by(address=address).first():
        db_session.add(models.User(address=address, encryption_public_key=TEST_ENCRYPTION_KEY))
        db_session.commit()
    return address


def _workflow(db_session, owner, *, status, signer=None, recipient=None):
    secret = models.Secret(owner_address=owner, name="s", type="note", encrypted_data="ab")
    db_session.add(secret)
    db_session.flush()
    wf = models.MultisigWorkflow(
        name="wf", owner_address=owner, secret_id=secret.id, status=status, threshold=1
    )
    db_session.add(wf)
    db_session.flush()
    if signer:
        db_session.add(
            models.MultisigWorkflowSigner(workflow_id=wf.id, user_address=signer, has_signed=False)
        )
    if recipient:
        db_session.add(
            models.MultisigWorkflowRecipient(
                workflow_id=wf.id, user_address=recipient, encrypted_key="33cc"
            )
        )
    db_session.commit()
    return wf


class TestOneRuleTwoSpellings:
    """`can_read_workflow` (one row) vs `readable_workflows` (the listing)."""

    def test_the_predicate_and_the_query_agree_everywhere(self, db_session):
        subject = _user(db_session, "drift-subject")
        owner = _user(db_session, "drift-owner")

        workflows = {}
        for status in STATUSES:
            for role in ROLES:
                wf = _workflow(
                    db_session,
                    subject if role == "owner" else owner,
                    status=status,
                    signer=subject if "signer" in role else None,
                    recipient=subject if "recipient" in role else None,
                )
                workflows[wf.id] = (role, status)

        listed = {wf.id for wf in authorization.readable_workflows(db_session, subject).all()}

        for wf in db_session.query(models.MultisigWorkflow).all():
            predicate = authorization.can_read_workflow(db_session, wf, subject)
            assert predicate == (wf.id in listed), (
                f"the endpoint that reads one workflow and the endpoint that "
                f"lists them disagree for a {workflows[wf.id][0]} on a "
                f"{workflows[wf.id][1]} workflow: predicate={predicate}, "
                f"listed={wf.id in listed}"
            )

        # And the rules are the intended ones, not merely two copies of the
        # same mistake: a recipient waits for completion, everyone else does
        # not, and a stranger never gets in.
        assert {workflows[i] for i in listed} == {("owner", s) for s in STATUSES} | {
            ("signer", s) for s in STATUSES
        } | {("signer+recipient", s) for s in STATUSES} | {("recipient", "completed")}

    def test_group_membership_predicate_and_subquery_agree(self, db_session):
        subject = _user(db_session, "drift-member")
        other = _user(db_session, "drift-other")

        joined, not_joined = [], []
        for i in range(4):
            channel = models.GroupChannel(id=str(uuid.uuid4()), name="g", owner_address=other)
            db_session.add(channel)
            db_session.add(
                models.GroupMember(channel_id=channel.id, user_address=other, role="owner")
            )
            if i % 2 == 0:
                db_session.add(
                    models.GroupMember(channel_id=channel.id, user_address=subject, role="member")
                )
                joined.append(channel.id)
            else:
                not_joined.append(channel.id)
        db_session.commit()

        listed = {
            cid
            for (cid,) in db_session.query(models.GroupChannel.id).filter(
                models.GroupChannel.id.in_(authorization.member_channel_ids(db_session, subject))
            )
        }
        assert listed == set(joined)
        for cid in joined + not_joined:
            assert authorization.is_group_member(db_session, cid, subject) == (cid in listed)

    def test_addresses_are_compared_case_insensitively(self, db_session):
        """Addresses are lowercase everywhere, so a mixed-case argument must
        not silently match nothing — a comparison that never matches is an
        authorization decision made by accident."""
        subject = _user(db_session, "drift-case")
        channel = models.GroupChannel(id=str(uuid.uuid4()), name="g", owner_address=subject)
        db_session.add(channel)
        db_session.add(
            models.GroupMember(channel_id=channel.id, user_address=subject, role="owner")
        )
        db_session.commit()

        assert authorization.is_group_member(db_session, channel.id, subject.upper())
        wf = _workflow(db_session, subject, status="pending")
        assert authorization.can_read_workflow(db_session, wf, subject.upper())
        assert authorization.can_delete_workflow(wf, subject.upper())


class TestGroupRoleLadder:
    """Every group endpoint answers the role question the same way.

    One table, so an endpoint that re-derives the rule inline instead of asking
    `security.authorization` shows up here as a row that has to be argued
    about rather than as silence.
    """

    @pytest.fixture()
    def group(self, client, user1, user2, user3, db_session):
        owner_token, owner = user1
        admin_token, admin = user2
        member_token, member = user3

        # A fourth plain member nobody in the table *is*, so "remove someone
        # else" stays a different question from "leave" for all three actors.
        target = synthetic_address("drift-target")
        db_session.add(models.User(address=target, encryption_public_key=TEST_ENCRYPTION_KEY))

        channel = models.GroupChannel(
            id=str(uuid.uuid4()), name="g", owner_address=owner["address"]
        )
        db_session.add(channel)
        for addr, role in (
            (owner["address"], "owner"),
            (admin["address"], "admin"),
            (member["address"], "member"),
            (target, "member"),
        ):
            db_session.add(models.GroupMember(channel_id=channel.id, user_address=addr, role=role))
        db_session.commit()
        return {
            "id": channel.id,
            "target": target,
            "owner": (owner_token, owner["address"]),
            "admin": (admin_token, admin["address"]),
            "member": (member_token, member["address"]),
        }

    def _call(self, client, group, capability, token, actor_address):
        cid = group["id"]
        target = group["target"]
        return {
            "read": lambda: client.get(f"/groups/{cid}", headers=auth_header(token)),
            "post": lambda: client.post(
                f"/groups/{cid}/messages", json={"content": "hi"}, headers=auth_header(token)
            ),
            "history": lambda: client.post(
                f"/groups/{cid}/history", json={"limit": 5, "offset": 0}, headers=auth_header(token)
            ),
            "rename": lambda: client.put(
                f"/groups/{cid}", json={"name": "renamed"}, headers=auth_header(token)
            ),
            "remove_other": lambda: client.delete(
                f"/groups/{cid}/members/{target}", headers=auth_header(token)
            ),
            "leave": lambda: client.delete(
                f"/groups/{cid}/members/{actor_address}", headers=auth_header(token)
            ),
            "set_role": lambda: client.put(
                f"/groups/{cid}/members/{target}/role",
                json={"role": "admin"},
                headers=auth_header(token),
            ),
        }[capability]()

    # capability -> the roles that may use it.
    LADDER = {
        "read": {"owner", "admin", "member"},
        "post": {"owner", "admin", "member"},
        "history": {"owner", "admin", "member"},
        "rename": {"owner", "admin"},
        "remove_other": {"owner", "admin"},
        "leave": {"owner", "admin", "member"},
        "set_role": {"owner"},
    }

    @pytest.mark.parametrize("capability", sorted(LADDER))
    @pytest.mark.parametrize("role", ("owner", "admin", "member"))
    def test_capability_matches_role(self, client, group, capability, role):
        token, address = group[role]
        resp = self._call(client, group, capability, token, address)
        allowed = role in self.LADDER[capability]
        if allowed:
            assert resp.status_code != 403, f"a group {role} was refused {capability}: {resp.text}"
        else:
            assert resp.status_code == 403, (
                f"a group {role} was allowed {capability} (got {resp.status_code})"
            )

    @pytest.mark.parametrize("capability", sorted(LADDER))
    def test_a_non_member_is_refused_everything(self, client, group, capability, db_session):
        outsider_address = synthetic_address("drift-outsider")
        db_session.add(
            models.User(address=outsider_address, encryption_public_key=TEST_ENCRYPTION_KEY)
        )
        db_session.commit()
        from conftest import do_login

        token, _ = do_login(client, outsider_address, TEST_ENCRYPTION_KEY)

        resp = self._call(client, group, capability, token, outsider_address)
        assert resp.status_code in (403, 404), (
            f"a non-member reached {capability}: {resp.status_code} {resp.text}"
        )


class TestGrantExpiryHasOneSpelling:
    """`purge_expired_grants` must delete exactly what `find_live_grant` refuses.

    These are the two halves of one rule, written as complements: the filter
    selects `expires_at IS NULL OR expires_at > now`, the purge deletes
    `expires_at IS NOT NULL AND expires_at <= now`. The routers used to spell
    the second one inline, with a different NULL check and a different "now" —
    KRY-001 in miniature. If either side is edited alone, one of these fails.
    """

    @pytest.mark.parametrize(
        "offset_seconds, expect_live",
        [(None, True), (3600, True), (-3600, False), (-1, False)],
    )
    def test_purge_removes_exactly_the_grants_that_are_not_live(
        self, db_session, offset_seconds, expect_live
    ):
        owner = _user(db_session, f"purge-owner-{offset_seconds}")
        grantee = _user(db_session, f"purge-grantee-{offset_seconds}")

        secret = models.Secret(owner_address=owner, name="s", type="note", encrypted_data="ab")
        db_session.add(secret)
        db_session.flush()

        expires_at = None
        if offset_seconds is not None:
            expires_at = utcnow_naive() + timedelta(seconds=offset_seconds)
        db_session.add(
            models.AccessGrant(
                secret_id=secret.id,
                grantee_address=grantee,
                encrypted_key="k",
                expires_at=expires_at,
            )
        )
        db_session.commit()

        was_live = authorization.find_live_grant(db_session, secret.id, grantee) is not None
        assert was_live is expect_live

        authorization.purge_expired_grants(db_session, secret_id=secret.id)
        survived = (
            db_session.query(models.AccessGrant).filter_by(secret_id=secret.id).first() is not None
        )
        assert survived is expect_live, "purge and find_live_grant disagree about this grant"

    def test_purge_scopes_to_the_key_it_is_given(self, db_session):
        """A purge for one user must not touch another user's expired rows."""
        owner = _user(db_session, "purge-scope-owner")
        mine = _user(db_session, "purge-scope-mine")
        theirs = _user(db_session, "purge-scope-theirs")

        secret = models.Secret(owner_address=owner, name="s", type="note", encrypted_data="ab")
        db_session.add(secret)
        db_session.flush()
        stale = utcnow_naive() - timedelta(hours=1)
        for who in (mine, theirs):
            db_session.add(
                models.AccessGrant(
                    secret_id=secret.id,
                    grantee_address=who,
                    encrypted_key="k",
                    expires_at=stale,
                )
            )
        db_session.commit()

        authorization.purge_expired_grants(db_session, grantee=mine)
        remaining = {
            g.grantee_address
            for g in db_session.query(models.AccessGrant).filter_by(secret_id=secret.id)
        }
        assert remaining == {theirs}


class TestLeavingHasOneSpelling:
    """Account deletion walks every group the user belongs to. That is the
    second caller of a rule the leave endpoint already had — who inherits a
    channel, and what happens when nobody is left — and two spellings of it
    would be the O-2 failure mode again.

    Rather than asserting the outcome twice, these build the SAME fixture twice
    and drive each path over it, then compare the rows. A re-implementation that
    got one succession case wrong would pass hand-written assertions about the
    case its author was thinking of.
    """

    @staticmethod
    def _members(db, channel_id):
        rows = db.query(models.GroupMember).filter_by(channel_id=channel_id).all()
        return sorted((m.user_address, m.role) for m in rows)

    @staticmethod
    def _build(client, owner_token, addresses, admin_address=None):
        resp = client.post(
            "/groups",
            json={"name": "drift", "member_addresses": addresses},
            headers=auth_header(owner_token),
        )
        assert resp.status_code == 200, resp.text
        channel_id = resp.json()["id"]
        if admin_address:
            promoted = client.put(
                f"/groups/{channel_id}/members/{admin_address}/role",
                json={"role": "admin"},
                headers=auth_header(owner_token),
            )
            assert promoted.status_code == 200, promoted.text
        return channel_id

    @pytest.mark.parametrize("with_admin", [True, False], ids=["admin-present", "no-admin"])
    def test_leaving_via_the_endpoint_and_via_deletion_agree(
        self, client, db_session, user1, user2, with_admin
    ):
        import base64

        token1, u1 = user1
        _, u2 = user2
        third = synthetic_address("drift-leaver-3")
        from conftest import do_login

        _, u3 = do_login(client, third, TEST_ENCRYPTION_KEY, "DriftThird")
        members = [u1["address"], u2["address"], u3["address"]]

        # The endpoint: the owner leaves by removing themselves.
        endpoint_channel = self._build(
            client, token1, members, u2["address"] if with_admin else None
        )
        left = client.delete(
            f"/groups/{endpoint_channel}/members/{u1['address']}",
            headers=auth_header(token1),
        )
        assert left.status_code == 200, left.text
        via_endpoint = self._members(db_session, endpoint_channel)

        # Deletion: the same owner, the same group shape, the other path.
        deletion_channel = self._build(
            client, token1, members, u2["address"] if with_admin else None
        )
        nonce = client.get(f"/auth/nonce/{u1['address']}").json()["nonce"]
        deleted = client.post(
            "/account/delete",
            json={
                "mode": "leave",
                "nonce": nonce,
                "signature": base64.b64encode(b"\x00" * 2420).decode(),
                "redactions": [],
            },
            headers=auth_header(token1),
        )
        assert deleted.status_code == 200, deleted.text
        db_session.expire_all()
        via_deletion = self._members(db_session, deletion_channel)

        assert via_deletion == via_endpoint
        # ...and neither leaves the channel ownerless (the Q-1 bug).
        owner = db_session.query(models.GroupChannel).filter_by(id=deletion_channel).one()
        assert owner.owner_address in dict(via_deletion)
        assert dict(via_deletion)[owner.owner_address] == "owner"

    def test_the_last_member_leaving_tears_the_group_down_either_way(
        self, client, db_session, user1
    ):
        import base64

        token1, u1 = user1
        endpoint_channel = self._build(client, token1, [u1["address"]])
        assert (
            client.delete(
                f"/groups/{endpoint_channel}/members/{u1['address']}",
                headers=auth_header(token1),
            ).status_code
            == 200
        )

        deletion_channel = self._build(client, token1, [u1["address"]])
        nonce = client.get(f"/auth/nonce/{u1['address']}").json()["nonce"]
        assert (
            client.post(
                "/account/delete",
                json={
                    "mode": "leave",
                    "nonce": nonce,
                    "signature": base64.b64encode(b"\x00" * 2420).decode(),
                    "redactions": [],
                },
                headers=auth_header(token1),
            ).status_code
            == 200
        )

        db_session.expire_all()
        assert db_session.query(models.GroupChannel).filter_by(id=endpoint_channel).first() is None
        assert db_session.query(models.GroupChannel).filter_by(id=deletion_channel).first() is None
