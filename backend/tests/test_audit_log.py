"""The security audit trail (audit 2026-09-11 M-3).

Nothing security-relevant was logged: not a login, a failed one, a key change,
a share, a revocation, or a refused request. These pin what the trail records
and, as much, what it must never carry.
"""

import json
import logging

import pytest
from conftest import (
    TEST_ENCRYPTION_KEY,
    auth_header,
    do_login,
    get_nonce,
    login_body,
    synthetic_address,
)

from security.audit_log import ADDRESS_PREFIX, audit_event, audit_logger


class _Collect(logging.Handler):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, record):
        self.events.append(json.loads(record.getMessage()))


@pytest.fixture
def trail():
    handler = _Collect()
    audit_logger.addHandler(handler)
    yield handler.events
    audit_logger.removeHandler(handler)


def _of(trail, event):
    return [e for e in trail if e["event"] == event]


class TestLogin:
    def test_a_login_is_recorded_with_who_from_where_and_which_request(self, client, user1, trail):
        # user1 registered before the handler existed; log in again.
        _, me = user1
        nonce = get_nonce(client, me["address"])
        resp = client.post("/auth/login", json=login_body(me["address"], nonce))
        assert resp.status_code == 200

        [line] = _of(trail, "auth.login")
        assert line["outcome"] == "ok"
        assert line["kind"] == "login"
        assert line["actor"] == me["address"][:ADDRESS_PREFIX]
        assert line["ip"]
        # The id an operator can match against what the client saw.
        assert line["request_id"] == resp.headers["x-request-id"]

    def test_a_refused_login_is_recorded_with_its_reason(self, client, user1, trail):
        _, me = user1
        body = login_body(me["address"], "00" * 16)  # a nonce never issued
        assert client.post("/auth/login", json=body).status_code == 400

        [line] = _of(trail, "auth.login")
        assert line["outcome"] == "refused"
        assert line["status"] == 400
        assert "nonce" in line["reason"].lower()

    def test_registration_and_a_key_change_are_their_own_kinds(self, client, trail):
        address = synthetic_address("audit-kinds")
        do_login(client, address, TEST_ENCRYPTION_KEY)
        do_login(client, address, "cd" * 1216)

        kinds = [e["kind"] for e in _of(trail, "auth.login")]
        assert kinds == ["register", "key_changed"]
        assert len(_of(trail, "auth.key_changed")) == 1


class TestRefusedRequests:
    def test_an_unauthenticated_request_is_recorded(self, client, trail):
        resp = client.get("/secrets")
        assert resp.status_code == 401
        [line] = _of(trail, "http.denied")
        assert (line["status"], line["method"], line["path"]) == (401, "GET", "/secrets")
        assert line["request_id"] == resp.headers["x-request-id"]

    def test_throttling_is_recorded(self, client, trail):
        address = synthetic_address("audit-throttle")
        statuses = [client.get(f"/auth/nonce/{address}").status_code for _ in range(12)]
        assert 429 in statuses
        line = _of(trail, "http.denied")[-1]
        assert line["status"] == 429
        # The address in the path is shortened like every other one.
        assert address not in line["path"]

    def test_every_response_carries_a_request_id(self, client):
        ids = {client.get("/").headers["x-request-id"] for _ in range(3)}
        assert len(ids) == 3


class TestSharing:
    def test_share_and_revoke_name_the_grantee_and_never_the_key(self, client, user1, user2, trail):
        token, owner = user1
        _, grantee = user2
        secret_id = client.post(
            "/secrets",
            json={
                "name": "s",
                "type": "standard",
                "encrypted_data": "c2VjcmV0",
                "encrypted_key": "b3duZXI=",
            },
            headers=auth_header(token),
        ).json()["id"]
        grant = client.post(
            "/secrets/share",
            json={
                "secret_id": secret_id,
                "grantee_address": grantee["address"],
                "encrypted_key": "V1JBUFBFRC1LRVk=",
            },
            headers=auth_header(token),
        ).json()
        client.delete(f"/secrets/share/{grant['id']}", headers=auth_header(token))

        [share] = _of(trail, "secret.share")
        [revoke] = _of(trail, "secret.revoke")
        for line in (share, revoke):
            assert line["actor"] == owner["address"][:ADDRESS_PREFIX]
            assert line["grantee"] == grantee["address"][:ADDRESS_PREFIX]
            assert line["secret_id"] == secret_id

        everything = json.dumps(trail)
        assert "V1JBUFBFRC1LRVk=" not in everything
        assert "c2VjcmV0" not in everything
        assert token not in everything


def test_no_line_ever_carries_a_whole_address(client, user1, user2, trail):
    """An address is a 2 624-character public key; the trail carries 16 of
    them, enough for an investigator, not a copy of the directory."""
    token, me = user1
    _, other = user2
    client.post(
        "/groups",
        json={"name": "g" * 10, "member_addresses": [other["address"]]},
        headers=auth_header(token),
    )
    client.get(f"/users/{other['address']}")  # 401, path carries the address
    assert trail
    everything = json.dumps(trail)
    for address in (me["address"], other["address"]):
        assert address[: ADDRESS_PREFIX + 1] not in everything


def test_an_audit_failure_never_fails_the_request(caplog):
    class Unprintable:
        def __str__(self):
            raise RuntimeError("no")

    audit_event("test.event", weird=Unprintable())  # must not raise
