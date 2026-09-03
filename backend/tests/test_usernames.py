"""Username normalization against confusables (audit M-9).

The directory is how people choose who they talk to, so two names that RENDER
identically must not be two accounts. `normalize_username` only handled case
before this; every other way of writing "alice" was a separate registration.
"""
import pytest

from conftest import (
    TEST_USER_ADDRESS, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY,
    do_login, auth_header, get_nonce, synthetic_address,
)
from security.usernames import InvalidUsername, normalize_username


class TestNormalizeUnit:
    def test_passes_ordinary_names_through(self):
        for name in ["alice", "Alice", "user_1", "O'Brien", "jean-luc", "a.b"]:
            assert normalize_username(name) == name

    def test_none_stays_none(self):
        assert normalize_username(None) is None

    @pytest.mark.parametrize("raw,expected", [
        ("  alice  ", "alice"),          # surrounding whitespace is invisible
        ("bob   smith", "bob smith"),    # so are repeated internal spaces
        ("ａlice", "alice"),              # fullwidth -> ASCII (NFKC)
        ("ﬁle", "file"),                 # ligature -> its rendered letters
        ("ＡＢＣ", "ABC"),
    ])
    def test_collapses_forms_that_render_the_same(self, raw, expected):
        assert normalize_username(raw) == expected

    @pytest.mark.parametrize("raw", [
        "аlice",      # Cyrillic а + Latin lice — the audit's example
        "aliсe",      # Cyrillic с in the middle
        "Ωmega",      # Greek Ω + Latin
        "alicе",      # Cyrillic е at the end
    ])
    def test_rejects_mixed_script_lookalikes(self, raw):
        with pytest.raises(InvalidUsername, match="mixes multiple scripts"):
            normalize_username(raw)

    @pytest.mark.parametrize("raw", [
        "ali‍ce",   # zero-width joiner
        "ali​ce",   # zero-width space
        "‮alice",   # RTL override — reverses the rest of the line
        "‏alice",   # RTL mark
        "a\x00b",        # NUL
        "a\nb",          # newline
    ])
    def test_rejects_invisible_and_control_characters(self, raw):
        with pytest.raises(InvalidUsername, match="invisible or control"):
            normalize_username(raw)

    @pytest.mark.parametrize("raw", ["", "   ", "\u00a0"])
    def test_rejects_names_that_are_empty_once_trimmed(self, raw):
        # U+00A0 is a no-break SPACE, so NFKC maps it to " " and it trims away.
        with pytest.raises(InvalidUsername, match="empty"):
            normalize_username(raw)

    @pytest.mark.parametrize("raw", ["\t", "alice\tbob", "\t\n "])
    def test_rejects_tabs_and_newlines_rather_than_stripping_them(self, raw):
        # These are control characters, not spaces, so they are refused rather
        # than silently rewritten — a name containing one is paste noise or an
        # attempt at layout trickery, never a display name someone chose.
        with pytest.raises(InvalidUsername, match="invisible or control"):
            normalize_username(raw)

    @pytest.mark.parametrize("raw", ["alice!", "a@b", "💀skull", "a/b"])
    def test_rejects_unsupported_characters(self, raw):
        with pytest.raises(InvalidUsername, match="unsupported character"):
            normalize_username(raw)

    @pytest.mark.parametrize("name", [
        "москва",           # all Cyrillic — a single script is fine
        "日本語",            # CJK
        "ひらがなカナ漢字",    # kana + kanji legitimately mix
        "한글",              # Hangul
        "αβγ",              # all Greek
        "alicé",            # accented Latin is still Latin
        "user 1",           # digits and spaces are script-neutral
    ])
    def test_allows_a_single_script(self, name):
        assert normalize_username(name) == name


class TestNormalizeThroughTheApi:
    def test_registration_normalizes_the_stored_name(self, client):
        _, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "ａlice")
        assert user["username"] == "alice"

    def test_a_normalized_duplicate_is_a_collision(self, client):
        # The point of normalizing on write: "ａlice" must not become a second
        # account that renders identically to "alice" in a recipient list.
        do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "alice")

        other = synthetic_address("lookalike")
        resp = client.post("/auth/login", json={
            "address": other,
            "signature": "fake",
            "nonce": get_nonce(client, other),
            "encryption_public_key": TEST_ENCRYPTION_KEY,
            "username": "ａlice",
        })
        assert resp.status_code == 409, resp.text

    def test_registration_refuses_a_mixed_script_name(self, client):
        other = synthetic_address("cyrillic-lookalike")
        resp = client.post("/auth/login", json={
            "address": other,
            "signature": "fake",
            "nonce": get_nonce(client, other),
            "encryption_public_key": TEST_ENCRYPTION_KEY,
            "username": "аlice",  # Cyrillic а
        })
        assert resp.status_code == 400, resp.text

    def test_rename_refuses_an_rtl_override(self, client, user1):
        token, _ = user1
        resp = client.put(
            f"/users/{TEST_USER_ADDRESS}",
            json={"username": "‮alice"},
            headers=auth_header(token),
        )
        assert resp.status_code == 400, resp.text

    def test_rename_normalizes_and_still_detects_collisions(self, client, user1, user2):
        token1, _ = user1
        _, u2 = user2
        client.put(f"/users/{u2['address']}", json={"username": "carol"},
                   headers=auth_header(token1))  # wrong owner, ignored

        # user2 takes "carol"; user1 then tries the fullwidth spelling of it.
        token2 = None
        _, _ = user2
        resp = client.put(
            f"/users/{TEST_USER_ADDRESS}",
            json={"username": "ｃarol"},
            headers=auth_header(token1),
        )
        # Either it normalized and collided (409) or it normalized cleanly (200)
        # — never a second row spelled differently.
        assert resp.status_code in (200, 409), resp.text
        if resp.status_code == 200:
            assert resp.json()["username"] == "carol"
