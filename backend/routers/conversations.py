"""Deleting a conversation, the two ways a user can mean it (audit 2026-09-11 M-6).

- **Hide it** (`POST …/clear`): a per-user marker. The conversation leaves this
  user's list and history up to the newest message at that moment, on every
  device, and returns if something newer arrives. The rows stay: the other
  side's copy is theirs, the rule account deletion settled.
- **Erase my messages in it** (`…/redactable-messages`, `POST …/erase`): the
  account erase, scoped to one conversation. The caller's session carriers are
  redacted under signatures they supply, the rest of their messages there are
  deleted, and the other side's are untouched. A round at a time, with 409 and
  what is left, exactly like `POST /account/delete`.

The erase is authorized by its own `conversation-erase` signature for the
reason the account erase has one: the per-message redactions are
`message`-context bodies, which TrustKeys signs SILENTLY for a connected site,
so they must ride behind a signature the extension asks the user about. That is
also why there is no bare "redact this message" route.

A conversation is `dm/<partner address>` or `group/<channel id>`.
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

import account_deletion
import auth
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from routers.account import MANIFEST_PAGE_DEFAULT, MANIFEST_PAGE_MAX
from routers.auth import check_signed_for_this_server, claim_nonce
from security import authorization
from security.audit_log import audit_event, short
from security.crypto_validation import ML_DSA_44_PUBLIC_KEY_HEX_LEN
from utils.clock import utcnow_naive
from utils.upsert import insert_for

logger = logging.getLogger("kryptolog.conversations")

router = APIRouter(prefix="/conversations", tags=["conversations"])

Kind = Literal["dm", "group"]
CLEARS_PAGE_MAX = 500


def _scope(kind: str, conversation: str) -> tuple[str, str]:
    """Normalize a conversation from the path, refusing what no row could match.

    Validated to the alphabet the signed body accepts, so a value that passes
    here is one `auth.conversation_erase_message` can spell.
    """
    if kind == "dm":
        partner = conversation.lower()
        if len(partner) > ML_DSA_44_PUBLIC_KEY_HEX_LEN or not auth._is_hex(partner):
            raise HTTPException(status_code=400, detail="Invalid conversation")
        return kind, partner
    if not auth.is_signed_identifier(conversation):
        raise HTTPException(status_code=400, detail="Invalid conversation")
    return kind, conversation


# ── Hide ────────────────────────────────────────────────────────


@router.get("/clears", response_model=list[schemas.ConversationClearResponse])
@limiter.limit("60/minute")
def list_clears(
    request: Request,
    limit: int = Query(CLEARS_PAGE_MAX, ge=1, le=CLEARS_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's hide markers, which the SPA applies to its lists and history."""
    return (
        db.query(models.ConversationClear)
        .filter(models.ConversationClear.user_address == current_user.address)
        .order_by(models.ConversationClear.id)
        .limit(limit)
        .offset(offset)
        .all()
    )


@router.post("/{kind}/{conversation}/clear", response_model=schemas.ConversationClearResponse)
@limiter.limit("30/minute")
def clear_conversation(
    request: Request,
    kind: Kind,
    conversation: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Hide a conversation from the caller, up to its newest message.

    The marker is computed HERE from the stored rows, never sent by the client,
    so it can only cover messages that existed when the user asked. A group
    needs membership: the newest id in a channel says how busy it is, which is
    not a non-member's business.
    """
    kind, key = _scope(kind, conversation)
    me = current_user.address
    if kind == "dm":
        newest = (
            db.query(func.max(models.Message.id))
            .filter(
                or_(
                    (models.Message.sender_address == me)
                    & (models.Message.recipient_address == key),
                    (models.Message.sender_address == key)
                    & (models.Message.recipient_address == me),
                )
            )
            .scalar()
        )
    else:
        if authorization.find_group_member(db, key, me) is None:
            raise HTTPException(status_code=404, detail="Group not found")
        newest = (
            db.query(func.max(models.GroupMessage.id))
            .filter(models.GroupMessage.channel_id == key)
            .scalar()
        )

    stmt = insert_for(db)(models.ConversationClear).values(
        user_address=me,
        kind=kind,
        conversation=key,
        cleared_through_id=newest or 0,
        cleared_at=utcnow_naive(),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["user_address", "kind", "conversation"],
        set_={
            "cleared_through_id": stmt.excluded.cleared_through_id,
            "cleared_at": stmt.excluded.cleared_at,
        },
    ).returning(models.ConversationClear.id)
    clear_id = db.execute(stmt).scalar_one()
    db.commit()
    audit_event(
        "conversation.clear",
        request=request,
        actor=me,
        kind=kind,
        conversation=short(key) if kind == "dm" else key,
    )
    return db.get(models.ConversationClear, clear_id)


# ── Erase my messages ───────────────────────────────────────────


@router.get(
    "/{kind}/{conversation}/redactable-messages",
    response_model=list[schemas.RedactableMessageResponse],
)
@limiter.limit("30/minute")
def redactable_messages(
    request: Request,
    kind: Kind,
    conversation: str,
    limit: int = Query(MANIFEST_PAGE_DEFAULT, ge=1, le=MANIFEST_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's messages in this conversation that must be re-signed in
    redacted form before an erase. Only ever the caller's own, so this needs no
    membership: someone who left a group may still erase what they said there."""
    return account_deletion.redactable_messages(
        db, current_user.address, limit=limit, offset=offset, scope=_scope(kind, conversation)
    )


@router.post("/{kind}/{conversation}/erase", response_model=schemas.ConversationEraseResponse)
# Same budget as the account erase, for the same reason: a round spends one
# login challenge (10/minute) and up to a thousand ML-DSA verifications.
@limiter.limit("10/minute")
def erase_conversation(
    request: Request,
    kind: Kind,
    conversation: str,
    req: schemas.ConversationEraseRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Erase the caller's own messages in one conversation, a round at a time.

    Answers 409 with what is left until no carrier remains, then deletes the
    caller's other messages there and answers `erased`. Rounds commit as they
    land, so an interrupted erase resumes where it stopped.
    """
    scope = _scope(kind, conversation)
    address = current_user.address

    def refuse(status_code: int, detail: str):
        audit_event(
            "conversation.erase",
            request=request,
            actor=address,
            outcome="refused",
            kind=kind,
            status=status_code,
            reason=detail,
        )
        raise HTTPException(status_code=status_code, detail=detail)

    # Claim first, verify second (KRY-004), as everywhere a challenge is spent.
    if not claim_nonce(db, address, req.nonce):
        refuse(400, "Invalid or expired nonce.")

    signatures = {r.key: r.signature for r in req.redactions}
    if len(signatures) != len(req.redactions):
        refuse(400, "Duplicate redaction id")

    check_signed_for_this_server(req.origin, req.deployment)
    try:
        message = auth.conversation_erase_message(
            req.nonce,
            scope[0],
            scope[1],
            signatures.keys(),
            origin=req.origin,
            deployment=req.deployment,
        )
    except auth.NonCanonicalSignedBody as exc:
        refuse(400, str(exc))
    if not auth.verify_message_signature(address, message, req.signature):
        refuse(401, "Invalid erase signature")

    # One erase of this account at a time, so two rounds cannot both count the
    # same carriers as remaining and race each other's deletes.
    db.refresh(current_user, with_for_update=True)

    try:
        redacted = account_deletion.apply_redactions(db, address, signatures, scope)
    except account_deletion.RedactionRefused as exc:
        db.rollback()
        refuse(400, str(exc))

    remaining = len(account_deletion.redaction_keys(db, address, scope))
    if remaining:
        db.commit()
        audit_event(
            "conversation.erase",
            request=request,
            actor=address,
            kind=kind,
            status="redacting",
            redacted=redacted,
            remaining=remaining,
        )
        return JSONResponse(
            status_code=409,
            content={
                "status": "redacting",
                "redacted": redacted,
                "deleted": 0,
                "kept": 0,
                "remaining": remaining,
            },
        )

    kept = account_deletion.kept_messages(db, address, scope)
    deleted = account_deletion.delete_own_messages(db, address, scope)
    db.commit()
    audit_event(
        "conversation.erase",
        request=request,
        actor=address,
        kind=kind,
        status="erased",
        redacted=redacted,
        deleted=deleted,
        kept=kept,
    )
    return {"status": "erased", "redacted": redacted, "deleted": deleted, "kept": kept}
