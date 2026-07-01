"""Invite-code access filter (audit §5).

Helpers for minting and atomically consuming invite codes. The consume path is a
single guarded SQL UPDATE so concurrent redemptions of the same code can't
over-spend it (no read-then-write race). Times are naive UTC to match how the
rest of the app stores/reads datetimes through SQLite.
"""
import secrets
from datetime import datetime, timezone, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

import models


def _utcnow() -> datetime:
    # Naive UTC, consistent with the other datetime columns as read back from
    # SQLite (avoids mixing aware/naive in the expiry comparison).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_code() -> str:
    """A short, URL-safe, hard-to-guess invite token."""
    return secrets.token_urlsafe(12)


def consume_invite(db: Session, code: str, used_by: str | None) -> bool:
    """Atomically redeem one use of `code`. Returns True iff a valid, unexpired,
    not-yet-exhausted code was consumed. The guard lives in the WHERE clause, so
    the UPDATE only ever affects a row that is still spendable."""
    if not code:
        return False

    now = _utcnow()
    affected = (
        db.query(models.InviteCode)
        .filter(
            models.InviteCode.code == code,
            models.InviteCode.uses < models.InviteCode.max_uses,
            or_(
                models.InviteCode.expires_at.is_(None),
                models.InviteCode.expires_at > now,
            ),
        )
        .update(
            {
                models.InviteCode.uses: models.InviteCode.uses + 1,
                models.InviteCode.used_by: used_by,
                models.InviteCode.used_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return affected == 1


def create_invites(
    db: Session,
    count: int = 1,
    *,
    created_by: str | None = None,
    max_uses: int = 1,
    expires_in_days: int | None = None,
) -> list[str]:
    """Mint `count` invite codes and persist them. Returns the raw codes."""
    expires_at = None
    if expires_in_days is not None:
        expires_at = _utcnow() + timedelta(days=expires_in_days)

    codes = []
    for _ in range(count):
        code = generate_code()
        db.add(
            models.InviteCode(
                code=code,
                created_by=created_by,
                max_uses=max_uses,
                uses=0,
                expires_at=expires_at,
            )
        )
        codes.append(code)
    db.commit()
    return codes
