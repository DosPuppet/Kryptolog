"""Ciphertext lives on the detail endpoints, not in the lists (audit O-3).

Paging bounded the list endpoints by row count. It did not bound them by
bytes: every row still carried its `encrypted_data` — up to 500 KB by schema —
for content the list never renders. The dashboard draws itself from `name` and
`encrypted_key`; the payload is read in exactly one place, on demand, one
secret at a time.

So the lists return summaries and `GET /secrets/{id}` returns the content. The
assertions below are mostly about *absence*, which is the awkward kind: a
response that stops carrying a field looks fine until something needed it.
"""
from datetime import datetime, timedelta, timezone

import models
from conftest import auth_header


def _naive_utc(dt):
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


PAYLOAD = "ab" * 64


def _make_secret(client, token, name="s"):
    resp = client.post(
        "/secrets",
        json={
            "name": name,
            "type": "note",
            "encrypted_data": PAYLOAD,
            "encrypted_key": "00ff",
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _share(client, owner_token, secret_id, grantee_address, expires_in=None):
    body = {
        "secret_id": secret_id,
        "grantee_address": grantee_address,
        "encrypted_key": "11ee",
    }
    if expires_in is not None:
        body["expires_in"] = expires_in
    resp = client.post("/secrets/share", json=body, headers=auth_header(owner_token))
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestListsCarryNoCiphertext:
    def test_owned_secret_list_omits_the_payload(self, client, user1):
        token, _ = user1
        _make_secret(client, token)

        rows = client.get("/secrets", headers=auth_header(token)).json()
        assert len(rows) == 1
        # Absent, not empty: a client that forgets to fetch the detail must
        # fail loudly on a missing key rather than decrypt an empty string.
        assert "encrypted_data" not in rows[0], rows[0].keys()
        # Everything the list actually draws is still there.
        assert rows[0]["name"] and rows[0]["encrypted_key"] and rows[0]["owner"]

    def test_shared_with_me_omits_the_payload_but_keeps_the_title(
        self, client, user1, user2
    ):
        owner_token, _ = user1
        grantee_token, grantee = user2
        secret = _make_secret(client, owner_token, name="shared-title")
        _share(client, owner_token, secret["id"], grantee["address"])

        rows = client.get("/secrets/shared-with-me", headers=auth_header(grantee_token)).json()
        assert len(rows) == 1
        assert "encrypted_data" not in rows[0]["secret"]
        # The grant list is a secrets list: it has to render a title and owner.
        assert rows[0]["secret"]["name"] == "shared-title"
        assert rows[0]["secret"]["owner"]["address"]
        assert rows[0]["encrypted_key"] == "11ee"

    def test_grant_list_carries_no_secret_at_all(self, client, user1, user2):
        """`/secrets/{id}/access` answers a question about grantees.

        Embedding the secret meant one full copy of the same ciphertext per
        person it was shared with — the response grew with the ACL, for a field
        the share modal never reads.
        """
        owner_token, _ = user1
        _, grantee = user2
        secret = _make_secret(client, owner_token)
        _share(client, owner_token, secret["id"], grantee["address"])

        rows = client.get(f"/secrets/{secret['id']}/access",
                          headers=auth_header(owner_token)).json()
        assert len(rows) == 2  # owner's own grant + the grantee's
        for row in rows:
            assert "secret" not in row, row.keys()
            assert {"grantee_address", "expires_at", "id"} <= set(row)

    def test_workflow_list_omits_the_payload_and_the_detail_keeps_it(
        self, client, user1, user2
    ):
        owner_token, _ = user1
        _, signer = user2
        created = client.post(
            "/multisig/workflow",
            json={
                "name": "wf",
                "secret_data": {
                    "name": "wf-secret", "type": "note",
                    "encrypted_data": PAYLOAD, "encrypted_key": "00ff",
                },
                "signers": [signer["address"]],
                "recipients": [],
                "signer_keys": {signer["address"]: "22dd"},
                "recipient_keys": {},
                "threshold": 1,
            },
            headers=auth_header(owner_token),
        )
        assert created.status_code == 200, created.text
        workflow_id = created.json()["id"]

        listed = client.get("/multisig/workflows", headers=auth_header(owner_token)).json()
        assert len(listed) == 1
        assert "encrypted_data" not in listed[0]["secret"]
        # Still enough to draw the row and decide whether a signature is owed.
        assert listed[0]["status"] == "pending" and listed[0]["signers"]

        detail = client.get(f"/multisig/workflow/{workflow_id}",
                            headers=auth_header(owner_token)).json()
        assert detail["secret"]["encrypted_data"] == PAYLOAD


class TestSecretDetail:
    def test_owner_gets_the_payload_and_their_own_key(self, client, user1):
        token, _ = user1
        secret = _make_secret(client, token)

        got = client.get(f"/secrets/{secret['id']}", headers=auth_header(token)).json()
        assert got["encrypted_data"] == PAYLOAD
        assert got["encrypted_key"] == "00ff"

    def test_grantee_gets_the_payload_and_their_own_wrap(self, client, user1, user2):
        owner_token, _ = user1
        grantee_token, grantee = user2
        secret = _make_secret(client, owner_token)
        _share(client, owner_token, secret["id"], grantee["address"])

        got = client.get(f"/secrets/{secret['id']}", headers=auth_header(grantee_token)).json()
        assert got["encrypted_data"] == PAYLOAD
        # The grantee's wrap, not the owner's.
        assert got["encrypted_key"] == "11ee"

    def test_stranger_is_refused(self, client, user1, user3):
        owner_token, _ = user1
        stranger_token, _ = user3
        secret = _make_secret(client, owner_token)

        resp = client.get(f"/secrets/{secret['id']}", headers=auth_header(stranger_token))
        assert resp.status_code == 403

    def test_expired_grant_no_longer_opens_the_secret(self, client, user1, user2, db_session):
        """KRY-001 applied to the new endpoint.

        It is the reason this route goes through `_check_secret_access` rather
        than re-deriving the rule: the original bug was a read path that
        checked membership but not expiry.
        """
        owner_token, _ = user1
        grantee_token, grantee = user2
        secret = _make_secret(client, owner_token)
        grant = _share(client, owner_token, secret["id"], grantee["address"], expires_in=3600)

        assert client.get(f"/secrets/{secret['id']}",
                          headers=auth_header(grantee_token)).status_code == 200

        row = db_session.query(models.AccessGrant).filter(
            models.AccessGrant.id == grant["id"]).first()
        row.expires_at = _naive_utc(datetime.now(timezone.utc)) - timedelta(minutes=1)
        db_session.commit()

        assert client.get(f"/secrets/{secret['id']}",
                          headers=auth_header(grantee_token)).status_code == 403

    def test_multisig_signer_may_read_a_pending_secret_but_a_recipient_may_not(
        self, client, user1, user2, user3, db_session
    ):
        """Delegated to `can_read_workflow`, so this pins the delegation.

        A signer must be able to inspect what they are approving; a recipient
        is precisely the person the secret has not been released to yet.
        """
        owner_token, owner = user1
        signer_token, signer = user2
        recipient_token, recipient = user3

        created = client.post(
            "/multisig/workflow",
            json={
                "name": "wf",
                "secret_data": {
                    "name": "wf-secret", "type": "note",
                    "encrypted_data": PAYLOAD, "encrypted_key": "00ff",
                },
                "signers": [signer["address"]],
                "recipients": [recipient["address"]],
                "signer_keys": {signer["address"]: "22dd"},
                "recipient_keys": {recipient["address"]: "33cc"},
                "threshold": 1,
            },
            headers=auth_header(owner_token),
        )
        assert created.status_code == 200, created.text
        secret_id = created.json()["secret_id"]

        as_signer = client.get(f"/secrets/{secret_id}", headers=auth_header(signer_token))
        assert as_signer.status_code == 200
        assert as_signer.json()["encrypted_data"] == PAYLOAD
        # No AccessGrant of their own: a signer's wrap lives on the signer row.
        assert as_signer.json()["encrypted_key"] is None

        assert client.get(f"/secrets/{secret_id}",
                          headers=auth_header(recipient_token)).status_code == 403

        # Completing the workflow releases it to the recipient.
        db_session.query(models.MultisigWorkflow).filter(
            models.MultisigWorkflow.secret_id == secret_id
        ).update({"status": "completed"})
        db_session.commit()
        assert client.get(f"/secrets/{secret_id}",
                          headers=auth_header(recipient_token)).status_code == 200

    def test_missing_secret_is_a_404(self, client, user1):
        token, _ = user1
        assert client.get("/secrets/999999", headers=auth_header(token)).status_code == 404


class TestRouteOrdering:
    """`GET /secrets/{secret_id}` must not shadow the literal routes.

    FastAPI matches in declaration order, so a `{secret_id}` path declared
    above `/secrets/shared-with-me` captures it and the listing comes back as a
    422 on an int that was never an int. Nothing about that failure points at
    route order, so it gets its own test rather than being noticed in passing.
    """

    def test_shared_with_me_still_resolves_to_the_listing(self, client, user1, user2):
        owner_token, _ = user1
        grantee_token, grantee = user2
        secret = _make_secret(client, owner_token)
        _share(client, owner_token, secret["id"], grantee["address"])

        resp = client.get("/secrets/shared-with-me", headers=auth_header(grantee_token))
        assert resp.status_code == 200, resp.text
        assert isinstance(resp.json(), list)
        assert resp.json()[0]["secret_id"] == secret["id"]

    def test_the_access_listing_still_resolves(self, client, user1):
        token, _ = user1
        secret = _make_secret(client, token)
        resp = client.get(f"/secrets/{secret['id']}/access", headers=auth_header(token))
        assert resp.status_code == 200, resp.text
        assert isinstance(resp.json(), list)
