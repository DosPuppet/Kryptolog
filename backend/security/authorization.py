"""Centralised authorization decisions for secrets and access grants.

Every "may this address read this secret?" question goes through here. The
routers must not re-derive the rules: KRY-001 was a direct consequence of the
grant-expiry condition existing in the listing endpoints but not in
`_check_secret_access`, so expired grants still unlocked file chunks.

Datetime convention: `AccessGrant.expires_at` is `DateTime` without
`timezone=True`, i.e. naive UTC on both Postgres and SQLite. Some writers store
an aware value (see `share_secret`), so comparisons here normalise to naive UTC
rather than assuming either form.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

import models


def utcnow_naive() -> datetime:
    """Current UTC as a naive datetime, matching the DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalise a possibly-aware datetime to naive UTC for comparison."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def grant_is_live(grant: Optional[models.AccessGrant], now: Optional[datetime] = None) -> bool:
    """A grant is live when it exists and has not passed its expiry.

    A NULL `expires_at` means "no expiry" — the grant lasts until revoked.
    """
    if grant is None:
        return False
    expires_at = as_naive_utc(grant.expires_at)
    if expires_at is None:
        return True
    return expires_at > (now or utcnow_naive())


def _live_grant_filter(now: datetime):
    """SQL predicate selecting grants that have not expired."""
    return or_(
        models.AccessGrant.expires_at.is_(None),
        models.AccessGrant.expires_at > now,
    )


def find_live_grant(
    db: Session, secret_id: int, user_address: str
) -> Optional[models.AccessGrant]:
    """Return this user's non-expired grant on the secret, if any."""
    now = utcnow_naive()
    return (
        db.query(models.AccessGrant)
        .filter(
            models.AccessGrant.secret_id == secret_id,
            models.AccessGrant.grantee_address == user_address,
            _live_grant_filter(now),
        )
        .first()
    )


def can_read_secret(db: Session, secret: models.Secret, user_address: str) -> bool:
    """Read access: owner, holder of a live grant, or a multisig participant.

    Multisig signers may read while the workflow runs (they must be able to
    inspect what they are approving); recipients only once it has completed.
    """
    if secret is None:
        return False

    if secret.owner_address == user_address:
        return True

    if find_live_grant(db, secret.id, user_address) is not None:
        return True

    workflow = (
        db.query(models.MultisigWorkflow)
        .filter(models.MultisigWorkflow.secret_id == secret.id)
        .first()
    )
    if workflow is None:
        return False

    is_signer = (
        db.query(models.MultisigWorkflowSigner)
        .filter(
            models.MultisigWorkflowSigner.workflow_id == workflow.id,
            models.MultisigWorkflowSigner.user_address == user_address,
        )
        .first()
        is not None
    )
    if is_signer:
        return True

    is_recipient = (
        db.query(models.MultisigWorkflowRecipient)
        .filter(
            models.MultisigWorkflowRecipient.workflow_id == workflow.id,
            models.MultisigWorkflowRecipient.user_address == user_address,
        )
        .first()
        is not None
    )
    return is_recipient and workflow.status == "completed"


def can_write_secret(db: Session, secret: models.Secret, user_address: str) -> bool:
    """Write access (upload chunks, mutate content): owner only.

    Deliberately narrower than read: a grant shares a key, it does not delegate
    the ability to change what the secret holds.
    """
    return secret is not None and secret.owner_address == user_address


def can_manage_grant(
    db: Session, grant: models.AccessGrant, user_address: str
) -> bool:
    """Revoke a grant: the secret's owner, or the grantee giving up their access."""
    if grant is None:
        return False
    if grant.grantee_address == user_address:
        return True
    secret = (
        db.query(models.Secret)
        .filter(models.Secret.id == grant.secret_id)
        .first()
    )
    return secret is not None and secret.owner_address == user_address
