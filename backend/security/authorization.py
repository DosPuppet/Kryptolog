"""Centralised authorization decisions: secrets, grants, groups, workflows.

Every "may this address do that?" question goes through here. The routers must
not re-derive the rules: KRY-001 was a direct consequence of the grant-expiry
condition existing in the listing endpoints but not in `_check_secret_access`,
so expired grants still unlocked file chunks.

Groups and multisig workflows were added for the same reason (audit O-2), not
because they were broken: `groups.py` asked "is this caller a member?" three
different ways and re-derived the role rules at every call site, and
`multisig.py` rebuilt owner/signer/recipient inline while `can_read_secret`
already encoded the same three rules. Duplicated rules are only ever one
one-sided edit away from being different rules.

Addresses are lowercase everywhere in the database and in signed bodies, so
every entry point here normalises its address argument rather than trusting the
caller to have done it — a comparison that silently never matches is an
authorization decision made by accident.

Datetime convention: `AccessGrant.expires_at` is `DateTime` without
`timezone=True`, i.e. naive UTC on both Postgres and SQLite. Some writers store
an aware value (see `share_secret`), so comparisons here normalise to naive UTC
rather than assuming either form.
"""

from datetime import UTC, datetime

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

import models


def normalize_address(address: str | None) -> str | None:
    """Lowercase an address for comparison against stored values."""
    return address.lower() if address is not None else None


def utcnow_naive() -> datetime:
    """Current UTC as a naive datetime, matching the DateTime columns."""
    return datetime.now(UTC).replace(tzinfo=None)


def as_naive_utc(value: datetime | None) -> datetime | None:
    """Normalise a possibly-aware datetime to naive UTC for comparison."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _live_grant_filter(now: datetime):
    """SQL predicate selecting grants that have not expired."""
    return or_(
        models.AccessGrant.expires_at.is_(None),
        models.AccessGrant.expires_at > now,
    )


def find_live_grant(db: Session, secret_id: int, user_address: str) -> models.AccessGrant | None:
    """Return this user's non-expired grant on the secret, if any."""
    now = utcnow_naive()
    return (
        db.query(models.AccessGrant)
        .filter(
            models.AccessGrant.secret_id == secret_id,
            models.AccessGrant.grantee_address == normalize_address(user_address),
            _live_grant_filter(now),
        )
        .first()
    )


def can_read_secret(db: Session, secret: models.Secret, user_address: str) -> bool:
    """Read access: owner, holder of a live grant, or a multisig participant.

    The multisig half is delegated rather than restated: the same three rules
    (owner / signer / recipient-once-completed) also gate the workflow
    endpoints, and one of the two copies would eventually stop being updated
    (audit O-2).
    """
    if secret is None:
        return False

    user_address = normalize_address(user_address)

    if normalize_address(secret.owner_address) == user_address:
        return True

    if find_live_grant(db, secret.id, user_address) is not None:
        return True

    workflow = (
        db.query(models.MultisigWorkflow)
        .filter(models.MultisigWorkflow.secret_id == secret.id)
        .first()
    )
    return can_read_workflow(db, workflow, user_address)


def can_write_secret(db: Session, secret: models.Secret, user_address: str) -> bool:
    """Write access (upload chunks, mutate content): owner only.

    Deliberately narrower than read: a grant shares a key, it does not delegate
    the ability to change what the secret holds.
    """
    return secret is not None and normalize_address(secret.owner_address) == normalize_address(
        user_address
    )


def can_manage_secret(db: Session, secret: models.Secret, user_address: str) -> bool:
    """Rename, delete, share, or list who has access: owner only.

    Same predicate as `can_write_secret` today, kept separate because the two
    answer different questions — if sharing ever becomes delegable, only one of
    them should move.
    """
    return can_write_secret(db, secret, user_address)


def can_manage_grant(db: Session, grant: models.AccessGrant, user_address: str) -> bool:
    """Revoke a grant: the secret's owner, or the grantee giving up their access."""
    if grant is None:
        return False
    user_address = normalize_address(user_address)
    if normalize_address(grant.grantee_address) == user_address:
        return True
    secret = db.query(models.Secret).filter(models.Secret.id == grant.secret_id).first()
    return can_manage_secret(db, secret, user_address)


# ── Group channels ──────────────────────────────────────────────────────────
#
# Roles form a strict ladder: owner > admin > member. Every predicate below
# takes the caller's GroupMember row (or None for a non-member) and fails
# closed on None, so "not a member" and "member without the role" answer the
# same way at the call site.

GROUP_ADMIN_ROLES = ("owner", "admin")


def find_group_member(db: Session, channel_id: str, user_address: str) -> models.GroupMember | None:
    """This address's membership row on the channel, or None.

    THE membership lookup. It stays a query even for callers that already hold
    a joinedload-ed `channel.members`: scanning the loaded collection is a
    fourth spelling of the same question (audit O-2), and the read is a keyed
    hit on uq_group_member_channel_user (migration e5f6a7b8c9d4).
    """
    return (
        db.query(models.GroupMember)
        .filter(
            models.GroupMember.channel_id == channel_id,
            models.GroupMember.user_address == normalize_address(user_address),
        )
        .first()
    )


def is_group_member(db: Session, channel_id: str, user_address: str) -> bool:
    """Read the channel and its history, and post to it."""
    return find_group_member(db, channel_id, user_address) is not None


def member_channel_ids(db: Session, user_address: str):
    """Subquery of the channel ids this address belongs to.

    The set form of `is_group_member`, for the listing endpoint — which has to
    filter and page in the database, not in Python. Two spellings of one rule
    is the drift O-2 is about, so `test_authorization_is_centralised` asserts
    the two agree over every membership configuration.
    """
    return (
        db.query(models.GroupMember.channel_id)
        .filter(models.GroupMember.user_address == normalize_address(user_address))
        .scalar_subquery()
    )


def can_administer_group(member: models.GroupMember | None) -> bool:
    """Add members, remove other members, rename the channel: owner or admin.

    Renaming sits here rather than with the owner-only powers because the
    channel name is an E2EE blob (audit M-3): whoever adds a member has to
    re-wrap the name for them, and adding is an owner/admin capability.
    """
    return member is not None and member.role in GROUP_ADMIN_ROLES


def can_manage_group_roles(member: models.GroupMember | None) -> bool:
    """Promote or demote a member: owner only.

    Narrower than `can_administer_group` on purpose — an admin who could mint
    admins would make the distinction between the two roles meaningless.
    """
    return member is not None and member.role == "owner"


def can_remove_group_member(member: models.GroupMember | None, target_address: str) -> bool:
    """Remove a member: anyone may remove themselves, others need owner/admin."""
    if member is None:
        return False
    if normalize_address(member.user_address) == normalize_address(target_address):
        return True  # leaving is always allowed
    return can_administer_group(member)


# ── Multisig workflows ──────────────────────────────────────────────────────


def find_workflow_signer(
    db: Session, workflow_id: int, user_address: str
) -> models.MultisigWorkflowSigner | None:
    """This address's signer row on the workflow, or None.

    Callers need the row itself (to record the signature), so this returns it
    rather than a bool — but it remains the only place the lookup is spelled.
    """
    return (
        db.query(models.MultisigWorkflowSigner)
        .filter(
            models.MultisigWorkflowSigner.workflow_id == workflow_id,
            models.MultisigWorkflowSigner.user_address == normalize_address(user_address),
        )
        .first()
    )


def find_workflow_recipient(
    db: Session, workflow_id: int, user_address: str
) -> models.MultisigWorkflowRecipient | None:
    """This address's recipient row on the workflow, or None."""
    return (
        db.query(models.MultisigWorkflowRecipient)
        .filter(
            models.MultisigWorkflowRecipient.workflow_id == workflow_id,
            models.MultisigWorkflowRecipient.user_address == normalize_address(user_address),
        )
        .first()
    )


def can_read_workflow(
    db: Session, workflow: models.MultisigWorkflow | None, user_address: str
) -> bool:
    """Read the workflow and the secret behind it.

    Owner and signers throughout — a signer must be able to inspect what they
    are being asked to approve. Recipients only once the workflow has
    completed: before that, the whole point is that the secret has not been
    released to them yet.
    """
    if workflow is None:
        return False

    user_address = normalize_address(user_address)

    if normalize_address(workflow.owner_address) == user_address:
        return True

    if find_workflow_signer(db, workflow.id, user_address) is not None:
        return True

    return (
        workflow.status == "completed"
        and find_workflow_recipient(db, workflow.id, user_address) is not None
    )


def readable_workflows(db: Session, user_address: str):
    """Query over the workflows this address may read.

    The SQL form of `can_read_workflow`, same three rules — the listing
    endpoint needs a single query it can order and page, rather than the three
    separate queries it used to merge in Python (which cannot be paged
    correctly, since neither half knows the other's rows).
    """
    user_address = normalize_address(user_address)
    signer_ids = db.query(models.MultisigWorkflowSigner.workflow_id).filter(
        models.MultisigWorkflowSigner.user_address == user_address
    )
    recipient_ids = db.query(models.MultisigWorkflowRecipient.workflow_id).filter(
        models.MultisigWorkflowRecipient.user_address == user_address
    )
    return db.query(models.MultisigWorkflow).filter(
        or_(
            models.MultisigWorkflow.owner_address == user_address,
            models.MultisigWorkflow.id.in_(signer_ids),
            and_(
                models.MultisigWorkflow.id.in_(recipient_ids),
                models.MultisigWorkflow.status == "completed",
            ),
        )
    )


def can_delete_workflow(workflow: models.MultisigWorkflow | None, user_address: str) -> bool:
    """Delete a workflow: the initiator only."""
    if workflow is None:
        return False
    return normalize_address(workflow.owner_address) == normalize_address(user_address)


def workflow_is_deletable(workflow: models.MultisigWorkflow | None) -> bool:
    """A workflow may only be deleted before release.

    A completed workflow has already handed the secret to its recipients, so
    deleting it would destroy their only copy of the wrapped key. Separate
    from `can_delete_workflow` so the endpoint can still tell the caller which
    of the two it failed — "not yours" and "too late" are different answers.
    """
    return workflow is not None and workflow.status != "completed"
