"""Message retention (audit 2026-09-11 M-6).

The property that matters is not that old rows go — that is one DELETE — but
that a session goes as a WHOLE: its first message carries the key, and deleting
it while later messages of the same session are still kept would leave those
on screen, undecryptable, for good.
"""

import json
from datetime import timedelta

import pytest

import config
import models
import retention
from utils.clock import utcnow_naive

NOW = utcnow_naive()


def _dm(db, sender, recipient, sid, age, *, content=None):
    row = models.Message(
        sender_address=sender,
        recipient_address=recipient,
        content=content if content is not None else json.dumps({"sid": sid, "ct": "c"}),
        created_at=NOW - age,
    )
    db.add(row)
    db.commit()
    return row.id


def _alive(db, ids):
    db.expire_all()
    return {i for i in ids if db.get(models.Message, i) is not None}


@pytest.fixture
def pair(user1, user2):
    return user1[1]["address"], user2[1]["address"]


def test_old_sessions_go_and_recent_ones_stay(db_session, pair):
    a, b = pair
    old = _dm(db_session, a, b, "old", timedelta(days=40))
    recent = _dm(db_session, a, b, "new", timedelta(days=2))

    retention.purge_expired_messages(db_session, days=30, now=NOW)
    assert _alive(db_session, {old, recent}) == {recent}


def test_a_session_straddling_the_cutoff_keeps_its_key(db_session, pair):
    """The carrier is 31 days old, its session's last message 29: deleting the
    carrier alone would make the 29-day-old message unreadable forever."""
    a, b = pair
    carrier = _dm(db_session, a, b, "s", timedelta(days=31))
    later = _dm(db_session, a, b, "s", timedelta(days=29, hours=23))

    retention.purge_expired_messages(db_session, days=30, now=NOW)
    assert _alive(db_session, {carrier, later}) == {carrier, later}

    # Once the whole session is past the cutoff, it goes in one pass.
    retention.purge_expired_messages(db_session, days=30, now=NOW + timedelta(days=2))
    assert _alive(db_session, {carrier, later}) == set()


def test_the_same_sid_from_another_sender_protects_nothing(db_session, pair):
    """A session has one sender since crypto-core 3.0.0; a sid is not a key on
    its own, and a stranger reusing one must not pin someone else's history."""
    a, b = pair
    old = _dm(db_session, a, b, "s", timedelta(days=40))
    _dm(db_session, b, a, "s", timedelta(days=29))
    retention.purge_expired_messages(db_session, days=30, now=NOW)
    assert old not in _alive(db_session, {old})


def test_rows_with_no_session_go_by_age(db_session, pair):
    a, b = pair
    junk = _dm(db_session, a, b, None, timedelta(days=40), content="not json")
    retention.purge_expired_messages(db_session, days=30, now=NOW)
    assert _alive(db_session, {junk}) == set()


def test_group_messages_are_purged_too(client, db_session, user1, user2):
    from test_account_deletion import _create_group

    token, me = user1
    gid = _create_group(client, token, [user2[1]["address"]])
    row = models.GroupMessage(
        channel_id=gid,
        sender_address=me["address"],
        content=json.dumps({"sid": "g", "ct": "c"}),
        created_at=NOW - timedelta(days=40),
    )
    db_session.add(row)
    db_session.commit()
    assert retention.purge_expired_messages(db_session, days=30, now=NOW)["group"] == 1


def test_unset_means_keep_everything(monkeypatch, db_session, pair):
    from conftest import TestingSessionLocal

    monkeypatch.delenv("KRYPTOLOG_MESSAGE_RETENTION_DAYS", raising=False)
    a, b = pair
    old = _dm(db_session, a, b, "old", timedelta(days=4000))
    assert retention.run_once(TestingSessionLocal) is None
    assert old in _alive(db_session, {old})


def test_configured_it_runs_and_says_so_in_the_audit_trail(monkeypatch, db_session, pair):
    from conftest import TestingSessionLocal

    monkeypatch.setenv("KRYPTOLOG_MESSAGE_RETENTION_DAYS", "30")
    a, b = pair
    old = _dm(db_session, a, b, "old", timedelta(days=40))
    assert retention.run_once(TestingSessionLocal) == {"dm": 1, "group": 0}
    assert old not in _alive(db_session, {old})


@pytest.mark.parametrize("value", ["0", "-5", "30d", "1.5", "forever"])
def test_a_malformed_policy_refuses_to_start(monkeypatch, value):
    """Asked for a policy and given none: silently keeping everything would be
    the one wrong answer."""
    monkeypatch.setenv("KRYPTOLOG_MESSAGE_RETENTION_DAYS", value)
    with pytest.raises(RuntimeError, match="RETENTION"):
        config.check_production_settings()
