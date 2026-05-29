"""Tests for /users endpoints — user CRUD and authorization."""

from conftest import auth_header


class TestGetUser:
    def test_get_user_by_address(self, client, user1):
        token, user = user1
        resp = client.get(f"/users/{user['address']}")
        assert resp.status_code == 200
        assert resp.json()["address"] == user["address"]

    def test_get_nonexistent_user(self, client, user1):
        resp = client.get("/users/nonexistent_address")
        assert resp.status_code == 404


class TestUpdateUser:
    def test_update_own_username(self, client, user1):
        token, user = user1
        resp = client.put(
            f"/users/{user['address']}",
            json={"username": "NewName"},
            headers=auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "NewName"

    def test_cannot_update_other_user(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        resp = client.put(
            f"/users/{u2['address']}",
            json={"username": "Hacked"},
            headers=auth_header(token1),
        )
        assert resp.status_code == 403


class TestListUsers:
    def test_list_users_returns_created_users(self, client, user1, user2):
        resp = client.get("/users")
        assert resp.status_code == 200
        addresses = [u["address"] for u in resp.json()]
        _, u1 = user1
        _, u2 = user2
        assert u1["address"] in addresses
        assert u2["address"] in addresses

    def test_list_users_search(self, client, user1):
        resp = client.get("/users?search=TestUser")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_list_users_limit(self, client, user1, user2):
        resp = client.get("/users?limit=1")
        assert resp.status_code == 200
        assert len(resp.json()) == 1


class TestResolveUser:
    def test_resolve_existing_user(self, client, user1):
        _, user = user1
        resp = client.post("/users/resolve", json={"address": user["address"]})
        assert resp.status_code == 200
        assert resp.json()["address"] == user["address"]

    def test_resolve_nonexistent_user(self, client, user1):
        resp = client.post("/users/resolve", json={"address": "does_not_exist"})
        assert resp.status_code == 404
