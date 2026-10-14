"""Replacing an identity's encryption key, and moving what it holds onto the
new one (crypto-core 5.1.0, lot 12f).

An identity is its address and cannot change without becoming someone else;
its encryption key can, and must be able to: to move to another KEM without
wiping the server (ANSSI's crypto-agility note, Rec. 3 — old keys have to be
handled, not stranded), or after a suspected leak. Three rules, kept here
rather than in the router because the next caller will need the same ones
(KRY-001's lesson):

1. A rotation is accepted only FROM the key the server holds: the signed body
   is built here from the CURRENT key id, so the client cannot name another,
   and a recorded rotation can never be replayed to roll a key back.
2. The new key enters exactly as at login — a key that IS one, with an
   attestation by the identity — and is stored through set_encryption_key.
3. A wrap is listed for re-wrapping only if its holder can already read it
   through the existing routes (a live grant, a signer row, a recipient row
   of a workflow `readable_workflows` exposes), and may be replaced only by
   that holder, with a wrap that names their CURRENT key. A replaced wrap can
   only ever hurt the one who replaced it: the server cannot open it, and
   nobody else reads it.

What is not re-wrapped, and why: message sessions live inside signed message
payloads, which cannot change without breaking the author's signature, and a
group's name inside an opaque `encg1:` blob only an admin rewrites. Both stay
readable with the RETIRED key the account keeps; a group name moves to the
new key at its next rename or membership change, which clients already
re-wrap for every member (decided 2026-10-14).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

import auth
import models
from security import authorization
from security.crypto_validation import (
    KEM_ALG,
    encryption_key_id,
    is_valid_encryption_key,
    is_wrapped_key_for,
    wrapped_key_id,
)
from utils.clock import utcnow_naive

# How far the client's clock may sit from ours when it signs a rotation. The
# timestamp is what contacts are shown, so a wildly wrong one is refused
# rather than published; replay is handled by rule 1, not by this window.
ROTATION_CLOCK_SKEW_MS = 10 * 60 * 1000


class RotationRefused(Exception):
    """A rotation the server will not record, with the status to answer."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class StaleWrap:
    kind: str  # "grant" | "signer" | "recipient"
    id: int
    encrypted_key: str


def rotate(
    db: Session,
    user: models.User,
    *,
    encryption_public_key: str,
    attestation: str,
    ts: int,
    signature: str,
    now_ms: int | None = None,
) -> models.EncryptionKeyRotation:
    """Record a rotation and switch the identity to its new key. The caller
    holds the user row locked (FOR UPDATE) and commits."""
    if not user.encryption_public_key or not user.encryption_key_id:
        raise RotationRefused(409, "This identity has no encryption key to rotate.")
    if not is_valid_encryption_key(encryption_public_key):
        raise RotationRefused(400, f"The new key must be a lowercase-hex {KEM_ALG} public key.")
    if encryption_public_key == user.encryption_public_key:
        raise RotationRefused(400, "The new key is the current key.")
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    if abs(now_ms - ts) > ROTATION_CLOCK_SKEW_MS:
        raise RotationRefused(400, "The rotation's timestamp is too far from the server's clock.")

    attestation_body = auth.encryption_key_attestation_message(user.address, encryption_public_key)
    if not auth.verify_identity_signature(user.identity_public_key, attestation_body, attestation):
        raise RotationRefused(400, "Invalid encryption key attestation.")

    old_kid, new_kid = user.encryption_key_id, encryption_key_id(encryption_public_key)
    body = auth.key_rotation_message(user.address, old_kid, new_kid, ts)
    if not auth.verify_identity_signature(user.identity_public_key, body, signature):
        raise RotationRefused(401, "Invalid rotation signature.")

    record = models.EncryptionKeyRotation(
        user_address=user.address,
        old_kid=old_kid,
        new_kid=new_kid,
        alg=KEM_ALG,
        ts=ts,
        signature=signature,
    )
    db.add(record)
    user.set_encryption_key(encryption_public_key, attestation)
    user.key_changed_at = utcnow_naive()
    db.add(user)
    return record


def contacts_of(db: Session, address: str) -> set[str]:
    """Who should hear that `address` replaced its key: everyone it has a DM
    with, and everyone it shares a group with. Their clients hold its old key
    in a cached record and, worse, in the session keys they keep wrapping to
    it — told, they refetch the record, stop on the changed key (K-05) and,
    once it is confirmed, mint sessions for the new one."""
    address = authorization.normalize_address(address)
    sent = db.query(models.Message.recipient_address).filter(
        models.Message.sender_address == address
    )
    received = db.query(models.Message.sender_address).filter(
        models.Message.recipient_address == address
    )
    channels = db.query(models.GroupMember.channel_id).filter(
        models.GroupMember.user_address == address
    )
    members = db.query(models.GroupMember.user_address).filter(
        models.GroupMember.channel_id.in_(channels)
    )
    found = {row[0] for query in (sent, received, members) for row in query.distinct()}
    found.discard(address)
    found.discard(None)
    return found


def _held(db: Session, user_address: str):
    """Every (kind, row) carrying a wrap this address may read today, in a
    stable order. Rule 3: through the predicates the read routes use."""
    grants = (
        authorization.live_grants_of(db, user_address)
        .filter(models.AccessGrant.encrypted_key.isnot(None))
        .order_by(models.AccessGrant.id)
    )
    readable = authorization.readable_workflows(db, user_address).with_entities(
        models.MultisigWorkflow.id
    )
    address = authorization.normalize_address(user_address)
    signers = (
        db.query(models.MultisigWorkflowSigner)
        .filter(
            models.MultisigWorkflowSigner.user_address == address,
            models.MultisigWorkflowSigner.workflow_id.in_(readable),
            models.MultisigWorkflowSigner.encrypted_key.isnot(None),
        )
        .order_by(models.MultisigWorkflowSigner.id)
    )
    recipients = (
        db.query(models.MultisigWorkflowRecipient)
        .filter(
            models.MultisigWorkflowRecipient.user_address == address,
            models.MultisigWorkflowRecipient.workflow_id.in_(readable),
            models.MultisigWorkflowRecipient.encrypted_key.isnot(None),
        )
        .order_by(models.MultisigWorkflowRecipient.id)
    )
    for kind, query in (("grant", grants), ("signer", signers), ("recipient", recipients)):
        for row in query.yield_per(200):
            yield kind, row


def stale_wraps(db: Session, user: models.User, *, limit: int, offset: int = 0) -> list[StaleWrap]:
    """The wraps this identity holds that do not name its current key — what
    a client re-wraps after a rotation. Ordered and paged so that a client
    that cannot open some of them (sealed to a key it destroyed) can step past
    them instead of being handed the same page forever."""
    out: list[StaleWrap] = []
    skipped = 0
    for kind, row in _held(db, user.address):
        if wrapped_key_id(row.encrypted_key) == user.encryption_key_id:
            continue
        if skipped < offset:
            skipped += 1
            continue
        out.append(StaleWrap(kind, row.id, row.encrypted_key))
        if len(out) >= limit:
            break
    return out


_ROW_MODELS = {
    "grant": models.AccessGrant,
    "signer": models.MultisigWorkflowSigner,
    "recipient": models.MultisigWorkflowRecipient,
}


def rewrap(db: Session, user: models.User, items) -> int:
    """Replace the caller's own wraps, each with one sealed to their CURRENT
    key. All or nothing: one item the caller does not hold, or a wrap that
    does not name the current key, refuses the whole batch — with a 404 for
    the first, the same answer as for a row that does not exist (no oracle
    on other people's grants)."""
    readable_ids: dict[str, set[int]] = {kind: set() for kind in _ROW_MODELS}
    for kind, row in _held(db, user.address):
        readable_ids[kind].add(row.id)
    rows = []
    for item in items:
        model = _ROW_MODELS[item.kind]
        if item.id not in readable_ids[item.kind]:
            raise RotationRefused(404, "Not found")
        if not is_wrapped_key_for(item.encrypted_key, user.encryption_key_id):
            raise RotationRefused(
                400, "A re-wrapped key must be sealed to the identity's current encryption key."
            )
        rows.append((db.get(model, item.id), item.encrypted_key))
    for row, wrapped in rows:
        row.encrypted_key = wrapped
        db.add(row)
    return len(rows)
