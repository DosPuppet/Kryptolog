"""Per-user storage quota (audit 2026-10-12 K-09).

There was none. A secret could hold 50 MB of chunks, a user could create secrets
without limit (20 a minute), and signup was open by default, so anyone who could
reach the API could fill the database disk — chunks live in PostgreSQL as base64.

Two ceilings per owner, both counted in characters actually stored (that is what
costs disk; for the ASCII these columns hold, a character is a byte):

* how many secrets they own,
* how much they store across all of them: inline `encrypted_data` and `name`,
  plus every file chunk.

**The check runs under a row lock on the owner.** Counting first and inserting
after is a race — two concurrent uploads each see room for one more and both
land — and the existing 50 MB per-file ceiling in `upload_chunk` had exactly that
shape. Taking `SELECT … FOR UPDATE` on the owner's `users` row serialises every
quota decision for that owner until the inserting transaction commits, which
closes both. It is a no-op on SQLite, which serialises writes anyway.
"""

import os

from sqlalchemy import func
from sqlalchemy.orm import Session

import models


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or default)
    except ValueError:
        return default


def max_secrets_per_user() -> int:
    """KRYPTOLOG_QUOTA_SECRETS, default 1 000. Read at call time (tests set it)."""
    return _env_int("KRYPTOLOG_QUOTA_SECRETS", 1_000)


def max_stored_chars_per_user() -> int:
    """KRYPTOLOG_QUOTA_BYTES, default 1 GiB — twenty full-size files."""
    return _env_int("KRYPTOLOG_QUOTA_BYTES", 1024 * 1024 * 1024)


class QuotaExceeded(Exception):
    """The write would take the owner past a ceiling. The message is user-facing."""


def lock_owner(db: Session, address: str) -> None:
    """Serialise this owner's quota decisions until the transaction ends."""
    db.query(models.User).filter(models.User.address == address).with_for_update().one()


def stored_chars(db: Session, address: str) -> int:
    """Characters this owner currently stores, inline and in chunks."""
    inline = (
        db.query(
            func.coalesce(
                func.sum(
                    func.coalesce(func.length(models.Secret.encrypted_data), 0)
                    + func.coalesce(func.length(models.Secret.name), 0)
                ),
                0,
            )
        )
        .filter(models.Secret.owner_address == address)
        .scalar()
    )
    chunks = (
        db.query(func.coalesce(func.sum(func.length(models.FileChunk.encrypted_data)), 0))
        .join(models.Secret, models.Secret.id == models.FileChunk.secret_id)
        .filter(models.Secret.owner_address == address)
        .scalar()
    )
    return int(inline) + int(chunks)


def check_new_secret(db: Session, address: str, new_chars: int) -> None:
    """Room for one more secret of `new_chars`? Call after lock_owner()."""
    owned = (
        db.query(func.count(models.Secret.id))
        .filter(models.Secret.owner_address == address)
        .scalar()
    )
    if owned + 1 > max_secrets_per_user():
        raise QuotaExceeded(
            f"Secret quota reached ({max_secrets_per_user()} per account). Delete some to make room."
        )
    check_new_bytes(db, address, new_chars)


def check_new_bytes(db: Session, address: str, new_chars: int) -> None:
    """Room for `new_chars` more stored characters? Call after lock_owner()."""
    limit = max_stored_chars_per_user()
    if stored_chars(db, address) + new_chars > limit:
        raise QuotaExceeded(
            f"Storage quota reached ({limit // (1024 * 1024)} MB per account). "
            "Delete some secrets or files to make room."
        )
