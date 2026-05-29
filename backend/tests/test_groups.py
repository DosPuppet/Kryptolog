"""
Tests for the Group Channels feature.
"""
import pytest
from conftest import do_login, auth_header, TEST_USER_ADDRESS, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY


TEST_USER_ADDRESS_3 = "pqc_test_user_" + "d" * 100


@pytest.fixture()
def user3(client):
    token, user = do_login(client, TEST_USER_ADDRESS_3, TEST_ENCRYPTION_KEY, "TestUser3")
    return token, user


class TestCreateGroup:
    def test_create_group(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        resp = client.post("/groups", json={
            "name": "Team Alpha",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Team Alpha"
        assert data["owner_address"] == u1["address"]
        assert len(data["members"]) == 2
        roles = {m["user_address"]: m["role"] for m in data["members"]}
        assert roles[u1["address"]] == "owner"
        assert roles[u2["address"]] == "member"

    def test_creator_auto_added(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        resp = client.post("/groups", json={
            "name": "Only Other",
            "member_addresses": [u2["address"]],
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        members = resp.json()["members"]
        addrs = [m["user_address"] for m in members]
        assert u1["address"] in addrs  # creator auto-included

    def test_create_with_nonexistent_user_fails(self, client, user1):
        token1, _ = user1
        resp = client.post("/groups", json={
            "name": "Bad Group",
            "member_addresses": ["nonexistent_address"],
        }, headers=auth_header(token1))
        assert resp.status_code == 404


class TestListGroups:
    def test_list_my_groups(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        client.post("/groups", json={
            "name": "Group A",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))

        # User1 sees the group
        resp = client.get("/groups", headers=auth_header(token1))
        assert resp.status_code == 200
        groups = resp.json()
        assert len(groups) == 1
        assert groups[0]["channel"]["name"] == "Group A"

        # User2 also sees it
        resp = client.get("/groups", headers=auth_header(token2))
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_non_member_doesnt_see_group(self, client, user1, user2, user3):
        token1, u1 = user1
        _, u2 = user2
        token3, _ = user3

        client.post("/groups", json={
            "name": "Private",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))

        resp = client.get("/groups", headers=auth_header(token3))
        assert resp.status_code == 200
        assert len(resp.json()) == 0


class TestGroupMessages:
    def test_send_and_get_history(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        # Create group
        create_resp = client.post("/groups", json={
            "name": "Chat Room",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        # Send message
        resp = client.post(f"/groups/{channel_id}/messages", json={
            "content": "encrypted_blob_here",
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        msg = resp.json()
        assert msg["sender_address"] == u1["address"]
        assert msg["channel_id"] == channel_id

        # Get history
        resp = client.post(f"/groups/{channel_id}/history", json={
            "limit": 50, "offset": 0,
        }, headers=auth_header(token2))
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) == 1
        assert history[0]["content"] == "encrypted_blob_here"

    def test_non_member_cannot_send(self, client, user1, user2, user3):
        token1, u1 = user1
        _, u2 = user2
        token3, _ = user3

        create_resp = client.post("/groups", json={
            "name": "Restricted",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.post(f"/groups/{channel_id}/messages", json={
            "content": "intruder",
        }, headers=auth_header(token3))
        assert resp.status_code == 403

    def test_non_member_cannot_read_history(self, client, user1, user2, user3):
        token1, u1 = user1
        _, u2 = user2
        token3, _ = user3

        create_resp = client.post("/groups", json={
            "name": "Restricted",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.post(f"/groups/{channel_id}/history", json={}, headers=auth_header(token3))
        assert resp.status_code == 403


class TestGroupMembers:
    def test_owner_can_add_member(self, client, user1, user2, user3):
        token1, u1 = user1
        _, u2 = user2
        _, u3 = user3

        create_resp = client.post("/groups", json={
            "name": "Expandable",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.post(f"/groups/{channel_id}/members", json={
            "user_address": u3["address"],
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["user_address"] == u3["address"]

        # Verify group now has 3 members
        resp = client.get(f"/groups/{channel_id}", headers=auth_header(token1))
        assert len(resp.json()["members"]) == 3

    def test_non_owner_cannot_add_member(self, client, user1, user2, user3):
        token1, u1 = user1
        token2, u2 = user2
        _, u3 = user3

        create_resp = client.post("/groups", json={
            "name": "Restricted Add",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.post(f"/groups/{channel_id}/members", json={
            "user_address": u3["address"],
        }, headers=auth_header(token2))
        assert resp.status_code == 403

    def test_owner_can_remove_member(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        create_resp = client.post("/groups", json={
            "name": "Removable",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.delete(f"/groups/{channel_id}/members/{u2['address']}", headers=auth_header(token1))
        assert resp.status_code == 200

        # Verify only 1 member left
        resp = client.get(f"/groups/{channel_id}", headers=auth_header(token1))
        assert len(resp.json()["members"]) == 1

    def test_member_can_leave(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        create_resp = client.post("/groups", json={
            "name": "Leavable",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        # User2 leaves
        resp = client.delete(f"/groups/{channel_id}/members/{u2['address']}", headers=auth_header(token2))
        assert resp.status_code == 200

    def test_cannot_add_duplicate_member(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        create_resp = client.post("/groups", json={
            "name": "No Dupes",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        resp = client.post(f"/groups/{channel_id}/members", json={
            "user_address": u2["address"],
        }, headers=auth_header(token1))
        assert resp.status_code == 400


class TestGroupAdmin:
    def test_promote_member_to_admin(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        # Create group
        create_resp = client.post("/groups", json={
            "name": "Admin Test",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        # Promote user2 to admin
        resp = client.put(f"/groups/{channel_id}/members/{u2['address']}/role", json={
            "role": "admin"
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

        # Verify in group details
        resp = client.get(f"/groups/{channel_id}", headers=auth_header(token1))
        members = resp.json()["members"]
        u2_role = next(m["role"] for m in members if m["user_address"] == u2["address"])
        assert u2_role == "admin"

    def test_admin_can_remove_owner_and_take_ownership(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        # Create group
        create_resp = client.post("/groups", json={
            "name": "Coup Test",
            "member_addresses": [u1["address"], u2["address"]],
        }, headers=auth_header(token1))
        channel_id = create_resp.json()["id"]

        # Promote user2 to admin
        client.put(f"/groups/{channel_id}/members/{u2['address']}/role", json={
            "role": "admin"
        }, headers=auth_header(token1))

        # Admin (u2) removes Owner (u1)
        resp = client.delete(f"/groups/{channel_id}/members/{u1['address']}", headers=auth_header(token2))
        assert resp.status_code == 200

        # Verify u2 is now owner
        resp = client.get(f"/groups/{channel_id}", headers=auth_header(token2))
        data = resp.json()
        assert data["owner_address"] == u2["address"]
        members = data["members"]
        # u1 should be gone
        assert not any(m["user_address"] == u1["address"] for m in members)
        # u2 should be owner
        u2_role = next(m["role"] for m in members if m["user_address"] == u2["address"])
        assert u2_role == "owner"

    def test_rename_group(self, client, user1, user2):
        token1, u1 = user1
        _, u2 = user2

        create_resp = client.post("/groups", json={
            "name": "Old Name",
            "member_addresses": [u2["address"]],
        }, headers=auth_header(token1))
        assert create_resp.status_code == 200
        channel_id = create_resp.json()["id"]

        resp = client.put(f"/groups/{channel_id}", json={
            "name": "New Name"
        }, headers=auth_header(token1))
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

        # Verify get
        resp = client.get(f"/groups/{channel_id}", headers=auth_header(token1))
        assert resp.json()["name"] == "New Name"
