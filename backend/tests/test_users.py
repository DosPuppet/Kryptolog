"""Tests for /users endpoints — user CRUD, authorization, and directory auth."""

import pytest

from conftest import auth_header


class TestGetUser:
    def test_get_user_by_address(self, client, user1):
        token, user = user1
        resp = client.get(f"/users/{user['address']}", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["address"] == user["address"]

    def test_get_nonexistent_user(self, client, user1):
        token, _ = user1
        resp = client.get("/users/nonexistent_address", headers=auth_header(token))
        assert resp.status_code == 404

    def test_get_user_requires_auth(self, client, user1):
        _, user = user1
        resp = client.get(f"/users/{user['address']}")
        assert resp.status_code == 401


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


class TestUsernameUniquenessIsCaseInsensitive:
    """The directory is how people pick who they talk to.

    Uniqueness used to be an exact-match comparison backed by a plain btree
    unique index, both case-SENSITIVE on PostgreSQL — so "alice" and "Alice"
    could coexist as separate identities, which is display-name impersonation
    in a recipient picker.
    """

    def _set_username(self, client, token, address, username):
        return client.put(
            f"/users/{address}",
            json={"username": username},
            headers=auth_header(token),
        )

    def test_cannot_take_a_case_variant_of_an_existing_name(self, client, user1, user2):
        token1, u1 = user1
        token2, u2 = user2

        assert self._set_username(client, token1, u1["address"], "alice").status_code == 200

        for variant in ("Alice", "ALICE", "aLiCe"):
            resp = self._set_username(client, token2, u2["address"], variant)
            assert resp.status_code == 409, f"{variant} was accepted alongside 'alice'"

    def test_can_still_change_the_case_of_your_own_name(self, client, user1):
        token, u1 = user1
        assert self._set_username(client, token, u1["address"], "bob").status_code == 200
        # The collision check excludes the caller, so re-casing your own name
        # must not collide with yourself.
        resp = self._set_username(client, token, u1["address"], "Bob")
        assert resp.status_code == 200
        assert resp.json()["username"] == "Bob"

    def test_username_is_trimmed(self, client, user1):
        token, u1 = user1
        resp = self._set_username(client, token, u1["address"], "  Padded  ")
        assert resp.status_code == 200
        # Leading/trailing space is invisible in every client, so " x" and "x"
        # must not be two different users.
        assert resp.json()["username"] == "Padded"

    def test_whitespace_only_username_is_rejected(self, client, user1):
        token, u1 = user1
        resp = self._set_username(client, token, u1["address"], "   ")
        assert resp.status_code == 400


class TestListUsers:
    def test_list_users_returns_created_users(self, client, user1, user2):
        token, _ = user1
        resp = client.get("/users", headers=auth_header(token))
        assert resp.status_code == 200
        addresses = [u["address"] for u in resp.json()]
        _, u1 = user1
        _, u2 = user2
        assert u1["address"] in addresses
        assert u2["address"] in addresses

    def test_list_users_search(self, client, user1):
        token, _ = user1
        resp = client.get("/users?search=TestUser", headers=auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_list_users_limit(self, client, user1, user2):
        token, _ = user1
        resp = client.get("/users?limit=1", headers=auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_list_users_requires_auth(self, client, user1):
        resp = client.get("/users?search=TestUser")
        assert resp.status_code == 401

    def test_short_search_returns_empty(self, client, user1):
        token, _ = user1
        # A 1-char substring search must not dump the directory.
        resp = client.get("/users?search=T", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.parametrize("query", ["limit=-1", "limit=0", "offset=-1", "limit=101"])
    def test_out_of_range_pagination_is_rejected(self, client, user1, query):
        """Bounded at both ends, in the signature.

        The ceiling was clamped in the body while the floor was unchecked, so
        `?limit=-1` reached PostgreSQL as `LIMIT -1` — a hard error, i.e. a 500
        from a trivial query string. FastAPI now rejects it as a 422 before any
        SQL is built.
        """
        token, _ = user1
        resp = client.get(f"/users?{query}", headers=auth_header(token))
        assert resp.status_code == 422


class TestResolveUser:
    def test_resolve_existing_user(self, client, user1):
        token, user = user1
        resp = client.post(
            "/users/resolve",
            json={"address": user["address"]},
            headers=auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["address"] == user["address"]

    def test_resolve_is_case_insensitive(self, client, user1):
        # Addresses are stored lowercased; a mixed-case query must still resolve
        # (audit S4) rather than silently 404.
        token, user = user1
        resp = client.post(
            "/users/resolve",
            json={"address": user["address"].upper()},
            headers=auth_header(token),
        )
        assert resp.status_code == 200
        assert resp.json()["address"] == user["address"]

    def test_resolve_nonexistent_user(self, client, user1):
        token, _ = user1
        resp = client.post(
            "/users/resolve",
            json={"address": "does_not_exist"},
            headers=auth_header(token),
        )
        assert resp.status_code == 404

    def test_resolve_requires_auth(self, client, user1):
        _, user = user1
        resp = client.post("/users/resolve", json={"address": user["address"]})
        assert resp.status_code == 401
