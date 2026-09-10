"""The request shapes the SPA actually sends, end to end.

Every messenger and group write broke with a 422 after the shared apiFetch
helper landed: its callers kept a JSON.stringify the helper also applies, so
the body arrived as a JSON string and Pydantic refused it. Nothing in the suite
noticed, because the messenger tests cover session and signature logic while the
HTTP layer had no coverage at all.

These walk the same endpoints the browser does, in the same order, with the
same body shapes — and pin the failure mode itself, so a reintroduction fails
here rather than in someone's manual pass.
"""

import json

from conftest import auth_header


def test_spa_dm_flow(client, user1, user2):
    t1, u1 = user1
    t2, u2 = user2

    # 1. Send, with the body shape the SPA now sends (an object).
    envelope = json.dumps({"v": 2, "sid": "s1", "ct": {"iv": "aa", "content": "bb"}})
    r = client.post(
        "/messages",
        json={"recipient_address": u2["address"], "content": envelope},
        headers=auth_header(t1),
    )
    assert r.status_code == 200, r.text
    sent = r.json()

    # 2. History, same shape.
    r = client.post(
        "/messages/history", json={"partner_address": u1["address"]}, headers=auth_header(t2)
    )
    assert r.status_code == 200, r.text
    assert any(m["id"] == sent["id"] for m in r.json()), "sent message missing from history"

    # 3. Conversations listing.
    r = client.get("/messages/conversations", headers=auth_header(t2))
    assert r.status_code == 200, r.text
    assert r.json(), "no conversation surfaced"

    # 4. Mark read.
    r = client.post(f"/messages/mark-read/{u1['address']}", headers=auth_header(t2))
    assert r.status_code == 200, r.text


def test_double_encoded_body_is_what_produced_the_422(client, user1, user2):
    """The exact failure reported from the browser."""
    t1, _ = user1
    _, u2 = user2
    body = json.dumps({"partner_address": u2["address"]})
    r = client.post(
        "/messages/history",
        content=json.dumps(body),
        headers={**auth_header(t1), "Content-Type": "application/json"},
    )
    assert r.status_code == 422


def test_spa_group_flow(client, user1, user2):
    t1, u1 = user1
    t2, u2 = user2

    r = client.post(
        "/groups",
        json={"name": "enc-name", "member_addresses": [u2["address"]]},
        headers=auth_header(t1),
    )
    assert r.status_code == 200, r.text
    ch = r.json()["id"]

    r = client.post(
        f"/groups/{ch}/messages", json={"content": json.dumps({"v": 2})}, headers=auth_header(t1)
    )
    assert r.status_code == 200, r.text

    r = client.post(
        f"/groups/{ch}/history", json={"limit": 50, "offset": 0}, headers=auth_header(t2)
    )
    assert r.status_code == 200, r.text
    assert r.json(), "group history empty"

    r = client.put(f"/groups/{ch}", json={"name": "renamed"}, headers=auth_header(t1))
    assert r.status_code == 200, r.text
