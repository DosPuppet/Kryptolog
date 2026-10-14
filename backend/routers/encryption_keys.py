"""Replacing the caller's encryption key (crypto-core 5.1.0, lot 12f).

`POST /account/encryption-key/rotate` records a signed rotation and switches
the identity to its new key; `GET …/stale-wraps` lists what the caller holds
that is still sealed to an older key, and `PUT …/wraps` replaces those with
wraps sealed to the new one. The rules live in security/key_rotation.py.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization, key_rotation
from security.audit_log import audit_event
from websocket_manager import manager

router = APIRouter(prefix="/account/encryption-key", tags=["account"])


def _locked_active(db: Session, user: models.User) -> models.User:
    """The caller's row under FOR UPDATE, re-checked behind the lock: two
    rotations racing must not both apply against the same current key."""
    db.refresh(user, with_for_update=True)
    if not authorization.is_active(user):
        raise HTTPException(status_code=410, detail="This account has been deleted.")
    return user


@router.post("/rotate", response_model=schemas.UserResponse)
@limiter.limit("5/hour")
def rotate_encryption_key(
    request: Request,
    req: schemas.KeyRotationRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replace the caller's encryption key with an attested new one, under a
    rotation signed by the identity. Accepted only from the key the server
    holds, so a recorded rotation cannot be replayed to roll it back. The old
    key stays on the caller's devices, retired, to read what was sealed to it."""
    user = _locked_active(db, current_user)
    old_kid = user.encryption_key_id
    try:
        record = key_rotation.rotate(
            db,
            user,
            encryption_public_key=req.encryption_public_key,
            attestation=req.encryption_key_attestation,
            ts=req.ts,
            signature=req.signature,
        )
    except key_rotation.RotationRefused as refused:
        db.rollback()
        audit_event(
            "key.rotate",
            request=request,
            actor=current_user.address,
            outcome="refused",
            reason=refused.detail,
        )
        raise HTTPException(status_code=refused.status, detail=refused.detail) from refused
    db.commit()
    db.refresh(user)
    audit_event(
        "key.rotate",
        request=request,
        actor=user.address,
        old_kid=old_kid,
        new_kid=record.new_kid,
    )
    # Tell the people who hold the old key: their clients refetch the record,
    # stop on the change, and stop wrapping session keys to the retired key.
    event = {"type": "KEY_ROTATED", "address": user.address}
    background_tasks.add_task(
        manager.send_many,
        [(event, addr) for addr in sorted(key_rotation.contacts_of(db, user.address))],
    )
    return user


@router.get("/stale-wraps", response_model=list[schemas.StaleWrapResponse])
@limiter.limit("60/minute")
def list_stale_wraps(
    request: Request,
    limit: int = Query(schemas.REWRAP_PAGE_MAX, ge=1, le=schemas.REWRAP_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The wrapped keys the caller holds that are not sealed to their current
    encryption key — what to re-wrap after a rotation. Only wraps the caller
    can already read: live grants, their signer rows, and recipient rows of
    workflows released to them. `offset` steps past the ones the client could
    not open, which stay listed."""
    return key_rotation.stale_wraps(db, current_user, limit=limit, offset=offset)


@router.put("/wraps")
@limiter.limit("60/minute")
def rewrap_keys(
    request: Request,
    req: schemas.RewrapRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Replace some of the caller's own wrapped keys with ones sealed to their
    current encryption key. All or nothing; a row the caller does not hold is
    a 404, as one that does not exist."""
    user = _locked_active(db, current_user)
    try:
        count = key_rotation.rewrap(db, user, req.items)
    except key_rotation.RotationRefused as refused:
        db.rollback()
        raise HTTPException(status_code=refused.status, detail=refused.detail) from refused
    db.commit()
    audit_event("key.rewrap", request=request, actor=user.address, count=count)
    return {"rewrapped": count}
