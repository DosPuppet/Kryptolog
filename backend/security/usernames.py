"""Username normalization and uniqueness.

The directory is how people pick who they talk to, so "this name is taken" has
to mean taken — not "taken in this exact casing". The check used to be an
exact-match comparison (`User.username == value`) under a comment claiming it
was case-insensitive, and the DB backstop was a plain btree unique index, which
is case-sensitive on PostgreSQL. `alice`, `Alice` and `ALICE` could therefore
all exist at once, which is a display-name impersonation vector in a messenger
where the recipient is chosen from a search list.

The address (an ML-DSA public key) remains the real identity and the fingerprint
UI is the actual defence against impersonation. This just makes the directory
behave the way the code already claimed it did.

Comparison is on `lower()` in SQL so the predicate matches the functional unique
index in migration d4e5f6a7b8c3 and the DB stays the backstop for the race
between check and insert.
"""
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

import models


class InvalidUsername(ValueError):
    """Raised when a submitted username is not usable as a display name."""


def normalize_username(value: Optional[str]) -> Optional[str]:
    """Trim a submitted username and reject the empty result.

    Surrounding whitespace is stripped rather than rejected: it is invisible in
    every client that renders the name, so " alice" and "alice" would read as
    the same user while occupying two rows. Returns None for None (the caller
    decides whether the field was optional).
    """
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        raise InvalidUsername("Username cannot be empty")
    return trimmed


def username_taken(db: Session, username: str, *, exclude_address: Optional[str] = None) -> bool:
    """True if any OTHER user already holds this username, ignoring case."""
    query = db.query(models.User).filter(
        func.lower(models.User.username) == username.lower()
    )
    if exclude_address is not None:
        query = query.filter(models.User.address != exclude_address)
    return query.first() is not None
