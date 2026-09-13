"""The user's own account: reading what a deletion would have to redact, and
performing the deletion.

Separate from `routers/users.py` because that router is the DIRECTORY — it
answers questions about other people. Everything here is about the caller, and
only ever the caller.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
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


@router.post("/delete", response_model=schemas.AccountDeleteResponse)
# 10/minute, matching GET /auth/nonce/{address} — a round spends exactly one
# challenge, so the two limits are consumed in lockstep and the tighter of them
# is the only one that counts. At 3/minute this was the tighter one, and it
# capped an erase at three rounds: the accounts the rounds exist for (audit
# 2026-09-12 M-2a) failed on the fourth request with a 429 rather than a reason.
# Found by re-running the probe, not by reading the code.
#
# Still a hard bound on an expensive call, and not the only one: each request
# needs a fresh challenge AND a valid ML-DSA signature over it, so this is not
# reachable by anyone but the key holder.
@limiter.limit("10/minute")
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

    An erase may take SEVERAL of these. One request carries at most
    `MAX_REDACTIONS_PER_DELETE` signatures — a bound on one request, not on how
    much an account may erase — so a long-lived account redacts a round at a
    time and this answers **409 with what is left** until none is. Each round
    is separately signed, and the account is not touched until the last one
    (audit 2026-09-12 M-2a).
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

    redacted = 0
    if req.mode == account_deletion.MODE_LEAVE:
        if signatures:
            raise HTTPException(status_code=400, detail="Leaving redacts nothing")
    else:
        try:
            redacted = account_deletion.apply_redactions(db, address, signatures)
        except account_deletion.RedactionRefused as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        # Recomputed here, inside the transaction, never taken from the signed
        # set: the erase finishes only when nothing of the user's still holds
        # both a session key and its ciphertext. A message sent while the
        # client was working through its manifest therefore delays the
        # deletion instead of being caught by it — `_delete_own_messages` never
        # deletes a carrier, so the row that used to be at risk of destroying
        # the partner's history now simply keeps this from completing.
        remaining = len(account_deletion.redaction_keys(db, address))
        if remaining:
            # This round's redactions stand. They are authenticated statements
            # by the author in their own right, and keeping them means the next
            # round is strictly smaller — an erase that cannot finish in one
            # request still always makes progress.
            db.commit()
            return JSONResponse(
                status_code=409,
                content={
                    "status": "redacting",
                    "redacted": redacted,
                    "kept": 0,
                    "remaining": remaining,
                    "detail": (
                        f"{remaining} more message(s) still have to be redacted. "
                        "Read the manifest again and sign the next round."
                    ),
                },
            )

    # Counted before the deletion runs, though it counts only rows the deletion
    # leaves alone either way — those are exactly the ones it refuses to guess
    # at.
    kept = (
        account_deletion.kept_messages(db, address)
        if req.mode == account_deletion.MODE_ERASE
        else 0
    )

    departures = account_deletion.delete_account(db, current_user, req.mode)

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

    return {"status": "deleted", "redacted": redacted, "kept": kept, "remaining": 0}
