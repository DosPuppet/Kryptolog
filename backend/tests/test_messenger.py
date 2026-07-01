"""Tests for /messages endpoints — send, history, conversations, mark-read."""

from conftest import auth_header


def _send_message(client, token, recipient_address, content="Hello encrypted"):
    return client.post("/messages", json={
        "recipient_address": recipient_address,
        "content": content,
    }, headers=auth_header(token))


class TestSendMessage:
    def test_send_message_success(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = _send_message(client, token1, u2["address"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["content"] == "Hello encrypted"
        assert data["recipient_address"] == u2["address"]
        assert data["is_read"] is False

    def test_send_to_nonexistent_user_fails(self, client, user1):
        token, _ = user1
        resp = _send_message(client, token, "nonexistent_user")
        assert resp.status_code == 404

    def test_send_message_unauthenticated(self, client, user2):
        _, u2 = user2
        resp = client.post("/messages", json={
            "recipient_address": u2["address"], "content": "x",
        })
        assert resp.status_code == 401

    def test_message_too_long_rejected(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = _send_message(client, token1, u2["address"], "x" * 10001)
        assert resp.status_code == 422


class TestMessageHistory:
    def test_get_history_between_two_users(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        _send_message(client, token1, u2["address"], "msg1")
        _send_message(client, token2, u1["address"], "msg2")
        _send_message(client, token1, u2["address"], "msg3")
        resp = client.post("/messages/history", json={
            "partner_address": u2["address"], "limit": 50, "offset": 0,
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        messages = resp.json()
        assert len(messages) == 3
        contents = [m["content"] for m in messages]
        assert contents == ["msg1", "msg2", "msg3"]

    def test_history_pagination(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        for i in range(5):
            _send_message(client, token1, u2["address"], f"msg{i}")
        resp = client.post("/messages/history", json={
            "partner_address": u2["address"], "limit": 2, "offset": 0,
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_history_limit_capped_at_100(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = client.post("/messages/history", json={
            "partner_address": u2["address"], "limit": 200, "offset": 0,
        }, headers=auth_header(token1))
        assert resp.status_code == 422  # Pydantic rejects limit > 100


class TestConversations:
    def test_conversations_list(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        _send_message(client, token1, u2["address"], "hello")
        resp = client.get("/messages/conversations", headers=auth_header(token1))
        assert resp.status_code == 200
        convos = resp.json()
        assert len(convos) >= 1
        partner_addresses = [c["user"]["address"] for c in convos]
        assert u2["address"] in partner_addresses

    def test_empty_conversations(self, client, user1):
        token, _ = user1
        resp = client.get("/messages/conversations", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json() == []


class TestMarkRead:
    def test_mark_messages_as_read(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2
        _send_message(client, token1, u2["address"], "unread msg")

        hist = client.post("/messages/history", json={
            "partner_address": u1["address"], "limit": 50, "offset": 0,
        }, headers=auth_header(token2))
        assert hist.json()[0]["is_read"] is False

        resp = client.post(
            f"/messages/mark-read/{u1['address']}",
            headers=auth_header(token2),
        )
        assert resp.status_code == 200

        hist2 = client.post("/messages/history", json={
            "partner_address": u1["address"], "limit": 50, "offset": 0,
        }, headers=auth_header(token2))
        assert hist2.json()[0]["is_read"] is True
