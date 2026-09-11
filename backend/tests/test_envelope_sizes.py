"""The size bounds on fields that hold PQC envelopes rather than user text.

Three fields in this app look like they hold a name or a chat line and do not:

  * a group `name` is a per-member key-wrap map (audit M-3), so each member can
    decrypt it — `"encg1:" + JSON({ct, keys: {address: wrappedKey}})`;
  * a DM `content` is a signed envelope carrying the session key wrapped for
    both parties;
  * a group message `content` is the same, wrapped for every member.

All three were budgeted as if they held the text. The result was that no group
could be created at all, no group past nine members could send a message, and
the first message of any conversation was capped at roughly 160 characters —
each surfacing as a bare 422.

These tests use the sizes the clients really produce, so tightening a bound
back toward a label-sized number fails here rather than in someone's browser.
`packages/crypto-core/test/envelope-size.test.js` pins the same costs on the
producing side.
"""

from conftest import (
    TEST_ENCRYPTION_KEY,
    TEST_USER_ADDRESS,
    auth_header,
    do_login,
)

import schemas

# Measured against crypto-core 2.0.0 with real key material. Deliberately
# literals rather than the schemas constants: asserting a bound against the
# constant it is derived from would pass for any value, including the ones that
# shipped broken.
CHARS_PER_MEMBER = 4_192  # a 2 624-char hex ML-DSA address + its wrapped key
SIGNED_ENVELOPE_CHARS = 3_500  # ML-DSA-44 signature (3 228) + ids + JSON
DM_SESSION_WRAPS_CHARS = 3_200  # the recipient's and the sender's wrapped key
# What the ciphertext of a full-length message costs on the wire. NOT
# `2 * MAX_MESSAGE_TEXT_CHARS`: the cap counts UTF-16 units and a unit is worth
# up to 3 bytes, which is the assumption that used to reject long non-ASCII
# messages. See MAX_MESSAGE_TEXT_BYTES in schemas.py.
FULL_CIPHERTEXT_CHARS = 40_024


def group_name_blob(member_count: int) -> str:
    """A stand-in the size the browser really sends for `member_count`."""
    return "encg1:" + "x" * (member_count * CHARS_PER_MEMBER)


def _create_group(client, token, member_address, member_count=2):
    return client.post(
        "/groups",
        json={
            "name": group_name_blob(member_count),
            "member_addresses": [member_address],
        },
        headers=auth_header(token),
    )


class TestGroupNameSize:
    def test_creating_a_group_accepts_a_real_encrypted_name(self, client, user2):
        """The two-member case: what a user hits the moment they click Create."""
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        r = _create_group(client, token, member["address"])
        assert r.status_code == 200, r.text

    def test_creating_a_group_accepts_a_name_wrapped_for_a_full_group(self, client, user2):
        """The bound has to hold at the member cap, which is what sizes it."""
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        r = _create_group(client, token, member["address"], schemas.MAX_GROUP_MEMBERS)
        assert r.status_code == 200, r.text

    def test_renaming_a_group_accepts_a_real_encrypted_name(self, client, user2):
        """Rename rebuilds the same blob — and runs after every add-member."""
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        created = _create_group(client, token, member["address"])
        assert created.status_code == 200, created.text

        r = client.put(
            f"/groups/{created.json()['id']}",
            json={"name": group_name_blob(2)},
            headers=auth_header(token),
        )
        assert r.status_code == 200, r.text

    def test_a_name_beyond_a_full_group_is_rejected(self, client, user2):
        """Still a DoS bound: one member past the cap does not get through."""
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        r = client.post(
            "/groups",
            json={
                "name": "encg1:" + "x" * (schemas.MAX_GROUP_NAME_LEN + 1),
                "member_addresses": [member["address"]],
            },
            headers=auth_header(token),
        )
        assert r.status_code == 422


class TestDirectMessageSize:
    def test_the_first_message_of_a_conversation_fits(self, client, user1, user2):
        """The session-minting message carries two wrapped keys plus a signature.

        With the old 10 000 cap that envelope left ~160 chars for the message,
        so this is the case a user meets on their very first send.
        """
        token1, _ = user1
        _, u2 = user2
        content = "x" * (SIGNED_ENVELOPE_CHARS + DM_SESSION_WRAPS_CHARS + FULL_CIPHERTEXT_CHARS)

        r = client.post(
            "/messages",
            json={"recipient_address": u2["address"], "content": content},
            headers=auth_header(token1),
        )
        assert r.status_code == 200, r.text

    def test_an_oversized_message_is_still_rejected(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        r = client.post(
            "/messages",
            json={
                "recipient_address": u2["address"],
                "content": "x" * (schemas.MAX_DM_CONTENT_LEN + 1),
            },
            headers=auth_header(token1),
        )
        assert r.status_code == 422


class TestGroupMessageSize:
    def test_a_full_group_rekey_message_fits(self, client, user2):
        """The first message of each key epoch wraps the key for every member.

        A ten-member group could not send at all under the old 50 000 cap, in a
        feature that advertises fifty.
        """
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        created = _create_group(client, token, member["address"])
        assert created.status_code == 200, created.text

        content = "x" * (
            SIGNED_ENVELOPE_CHARS
            + schemas.MAX_GROUP_MEMBERS * CHARS_PER_MEMBER
            + FULL_CIPHERTEXT_CHARS
        )
        r = client.post(
            f"/groups/{created.json()['id']}/messages",
            json={"content": content},
            headers=auth_header(token),
        )
        assert r.status_code == 200, r.text

    def test_an_oversized_group_message_is_still_rejected(self, client, user2):
        token, _ = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "A")
        _, member = user2

        created = _create_group(client, token, member["address"])
        assert created.status_code == 200, created.text

        r = client.post(
            f"/groups/{created.json()['id']}/messages",
            json={"content": "x" * (schemas.MAX_GROUP_MESSAGE_CONTENT_LEN + 1)},
            headers=auth_header(token),
        )
        assert r.status_code == 422


class TestTheTwoLanguagesAgree:
    """The producing side measures these costs; this side budgets for them.

    `packages/crypto-core/test/envelope-size.test.js` mirrors the constants
    below so it can assert the envelopes it builds fit. Two numbers in two
    languages in two packages is exactly how the original bug happened, so the
    mirror is checked rather than trusted.
    """

    MIRRORED = (
        "MAX_GROUP_MEMBERS",
        "KEY_WRAP_CHARS_PER_MEMBER",
        "SIGNATURE_CHARS",
        "WRAPPED_KEY_CHARS",
        "MAX_MESSAGE_TEXT_CHARS",
        "MAX_GROUP_NAME_LEN",
        "MAX_DM_CONTENT_LEN",
        "MAX_GROUP_MESSAGE_CONTENT_LEN",
    )

    def test_the_crypto_core_mirror_is_current(self):
        import pathlib
        import re

        mirror = (
            pathlib.Path(__file__).resolve().parents[2]
            / "packages"
            / "crypto-core"
            / "test"
            / "envelope-size.test.js"
        )
        assert mirror.exists(), f"the mirror moved or was deleted: {mirror}"
        source = mirror.read_text(encoding="utf-8")

        for name in self.MIRRORED:
            match = re.search(rf"\b{name}:\s*([\d_]+)", source)
            assert match, f"{name} is not mirrored in {mirror.name}"
            mirrored = int(match.group(1).replace("_", ""))
            expected = getattr(schemas, name)
            assert mirrored == expected, (
                f"{name} is {expected} here and {mirrored} in {mirror.name} — "
                "update both, or the client will build envelopes the server rejects"
            )
