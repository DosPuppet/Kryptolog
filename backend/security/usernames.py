"""Username normalization and uniqueness.

The directory is how people pick who they talk to, so "this name is taken" has
to mean taken — not "taken in this exact casing", and not "taken in this exact
sequence of code points that happens to render identically to another one".

Two separate problems, both fixed here:

CASE. The check used to be an exact-match comparison (`User.username == value`)
under a comment claiming it was case-insensitive, and the DB backstop was a
plain btree unique index, which is case-sensitive on PostgreSQL. `alice`,
`Alice` and `ALICE` could therefore all exist at once.

CONFUSABLES (audit M-9). `normalize_username` did a bare `.strip()`, so every
other way of writing a name that LOOKS like "alice" was a separate account:
`аlice` with a Cyrillic а, `ａlice` in fullwidth, `ali<ZWJ>ce` with a
zero-width joiner, or a name carrying an RTL override that reverses how the
rest of the line renders. The module's own docstring already named this as the
risk it existed to address; it only ever handled case.

The address (an ML-DSA public key) remains the real identity and the safety
number is the actual defence against impersonation. This makes the directory
behave the way the code already claimed it did.

Comparison is on `lower()` in SQL so the predicate matches the functional
unique index in migration d4e5f6a7b8c3 and the DB stays the backstop for the
race between check and insert. Python's `.lower()` is used on the input rather
than `.casefold()` precisely so the two sides agree: casefold is more
aggressive than SQL's lower() and the pair would disagree on e.g. ß/ss.
"""
import unicodedata
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

import models


class InvalidUsername(ValueError):
    """Raised when a submitted username is not usable as a display name."""


# Categories that must never appear in a rendered name:
#   Cc  control characters
#   Cf  format characters — the zero-width joiner/non-joiner that split a name
#       into invisibly-different variants, and the bidi overrides that make the
#       REST of a line render backwards
#   Zl/Zp  line and paragraph separators
#   Cs/Co/Cn  surrogates, private use, unassigned
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})

# Script-neutral characters, allowed alongside any one script.
_SCRIPT_NEUTRAL = frozenset("0123456789 _-.'")

# Coarse script lookup from the character's Unicode NAME. The stdlib exposes no
# script property, but the name prefix is stable and this only has to be right
# about which characters are confusable with Latin — the families below are
# grouped so that legitimately-mixed writing systems (Japanese kana with kanji,
# Hangul with kanji) count as one, while Latin/Cyrillic/Greek stay distinct
# because that is exactly the substitution being blocked.
_SCRIPT_FAMILIES = {
    "LATIN": "latin",
    "CYRILLIC": "cyrillic",
    "GREEK": "greek",
    "COPTIC": "greek",
    "ARABIC": "arabic",
    "HEBREW": "hebrew",
    "DEVANAGARI": "devanagari",
    "THAI": "thai",
    "HIRAGANA": "cjk",
    "KATAKANA": "cjk",
    "KATAKANA-HIRAGANA": "cjk",
    "CJK": "cjk",
    "HANGUL": "cjk",
    "IDEOGRAPHIC": "cjk",
}


def _script_family(char: str) -> Optional[str]:
    try:
        name = unicodedata.name(char)
    except ValueError:  # unnamed character
        return None
    return _SCRIPT_FAMILIES.get(name.split()[0])


def normalize_username(value: Optional[str]) -> Optional[str]:
    """Canonicalize a submitted username, or raise InvalidUsername.

    Returns None for None (the caller decides whether the field was optional).

    NFKC first, so compatibility forms collapse to the characters they render
    as — fullwidth `ａlice` and ligature `ﬁ` stop being separate names — and so
    the value stored is the one every later comparison sees. NFKC also composes,
    which folds most accented Latin into precomposed code points and removes the
    combining-mark stacking route to a duplicate name.

    Surrounding whitespace is stripped and internal runs collapsed rather than
    rejected: both are invisible in every client that renders the name, so
    " alice" and "alice" would read as the same user while occupying two rows.
    """
    if value is None:
        return None

    normalized = unicodedata.normalize("NFKC", value)

    for char in normalized:
        if unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise InvalidUsername(
                "Username contains an invisible or control character"
            )

    # Collapse after the category check, so a rejected separator cannot be
    # laundered into an ordinary space first.
    collapsed = " ".join(normalized.split())
    if not collapsed:
        raise InvalidUsername("Username cannot be empty")

    families = set()
    for char in collapsed:
        if char in _SCRIPT_NEUTRAL:
            continue
        if unicodedata.category(char)[0] not in "LMN":
            raise InvalidUsername(
                f"Username contains an unsupported character: {char!r}"
            )
        family = _script_family(char)
        if family is None:
            raise InvalidUsername(
                f"Username contains an unsupported character: {char!r}"
            )
        families.add(family)

    # The whole point: `аlice` (Cyrillic а, Latin lice) is two families and is
    # refused, rather than quietly becoming a second account that renders
    # identically to the first in a recipient list.
    if len(families) > 1:
        raise InvalidUsername(
            "Username mixes multiple scripts (" + ", ".join(sorted(families)) + ")"
        )

    return collapsed


def username_taken(db: Session, username: str, *, exclude_address: Optional[str] = None) -> bool:
    """True if any OTHER user already holds this username, ignoring case.

    Callers must pass an already-normalized name (normalize_username): this
    compares against stored values, which are normalized on write, so an
    un-normalized argument would miss the collision it exists to find.
    """
    query = db.query(models.User).filter(
        func.lower(models.User.username) == username.lower()
    )
    if exclude_address is not None:
        query = query.filter(models.User.address != exclude_address)
    return query.first() is not None
