"""The user's own account: reading what a deletion would have to redact, and
performing the deletion.

Separate from `routers/users.py` because that router is the DIRECTORY — it
answers questions about other people. Everything here is about the caller, and
only ever the caller.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

import account_deletion
import auth
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from routers.auth import claim_nonce
from utils.group_events import broadcast_removal
from websocket_manager import manager

router = APIRouter(prefix="/account", tags=["account"])

# Paged like every other list (audit O-3), bounded at both ends by FastAPI. A
# manifest row carries a full key-wrap map, so an account in large groups
# produces rows of tens of kilobytes each.
MANIFEST_PAGE_MAX = 100
MANIFEST_PAGE_DEFAULT = 50


@router.get("/redactable-messages", response_model=list[schemas.RedactableMessageResponse])
@limiter.limit("30/minute")
def redactable_messages(
    request: Request,
    limit: int = Query(MANIFEST_PAGE_DEFAULT, ge=1, le=MANIFEST_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The messages an erase must redact rather than delete.

    Each carries a wrapped session key that other people's messages depend on,
    so the client re-signs a redacted form of each before the deletion is
    accepted. Only ever the caller's own messages.
    """
    manifest = account_deletion.redactable_messages(db, current_user.address)
    return manifest[offset : offset + limit]


@router.post("/delete", status_code=204)
@limiter.limit("3/minute")
async def delete_account(
    request: Request,
    req: schemas.AccountDeleteRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete the caller's own account, in one of two modes.

    Authorized by a fresh ML-DSA signature over a domain-separated challenge as
    well as by the session: a stolen token alone must not be able to destroy an
    account, and a signature alone must not either.
    """
    address = current_user.address

    # Claim first, verify second (KRY-004): a failed verification must not hand
    # back a replayable challenge. This COMMITS, deliberately outside the
    # deletion transaction below — the nonce is spent whatever happens next.
    if not claim_nonce(db, address, req.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    signatures = {r.key: r.signature for r in req.redactions}
    if len(signatures) != len(req.redactions):
        raise HTTPException(status_code=400, detail="Duplicate redaction id")

    message = auth.account_deletion_message(req.nonce, req.mode, signatures.keys())
    if not auth.verify_message_signature(address, message, req.signature):
        raise HTTPException(status_code=401, detail="Invalid deletion signature")

    if req.mode == account_deletion.MODE_LEAVE:
        if signatures:
            raise HTTPException(status_code=400, detail="Leaving redacts nothing")
    else:
        # Recomputed here, inside the transaction that does the deleting, not
        # taken from the signed set. A message sent between the client reading
        # the manifest and this request landing would otherwise be DELETED
        # rather than redacted — and if it opened an epoch, the partner loses
        # their own history. Fail closed and make the client re-read.
        if account_deletion.redaction_keys(db, address) != set(signatures):
            raise HTTPException(
                status_code=409,
                detail="Your messages changed since the manifest was read. Retry the deletion.",
            )

    try:
        departures = account_deletion.delete_account(db, current_user, req.mode, signatures)
    except account_deletion.RedactionRefused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()

    # Everything below is after the commit and best-effort: telling a group
    # someone left, then rolling back, would be worse than telling them late.
    for departure in departures:
        await broadcast_removal(
            departure["channel_id"],
            address,
            address,
            departure["remaining_addrs"],
            departure["new_owner_info"],
            True,
        )
    # The JWT is already dead (the row is deleted and token_version bumped) and
    # the WebSocket handshake goes through the same dependency, so nothing can
    # reconnect. Sockets already open are not closed by a database write.
    await manager.close_address(address)
