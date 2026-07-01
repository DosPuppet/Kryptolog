"""Device-to-device key transfer relay.

A logged-in device uploads its client-side-encrypted vault blob and gets a short
pickup id back; the target device fetches it once (single-use) within a short
TTL. The decryption passphrase is carried out of band (QR / short code) and never
touches the server, so this stays zero-knowledge — the server only ever holds
ciphertext + a random id.

POST /transfers       — authenticated (the source device has a session)
GET  /transfers/{id}  — unauthenticated (the target device has no identity yet);
                        guarded by the unguessable id, single-use, and TTL.
"""
import secrets as _secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models, schemas, config
from database import get_db
from dependencies import limiter, get_current_user

router = APIRouter(prefix="/transfers", tags=["transfers"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("", response_model=schemas.KeyTransferCreateResponse)
@limiter.limit("10/minute")
def create_transfer(
    request: Request,
    body: schemas.KeyTransferCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if len(body.ciphertext) > config.MAX_KEY_TRANSFER_SIZE:
        raise HTTPException(status_code=413, detail="Transfer payload too large")

    # Opportunistically purge expired rows so the table can't accumulate.
    db.query(models.KeyTransfer).filter(models.KeyTransfer.expires_at <= _now()).delete()

    transfer_id = _secrets.token_urlsafe(9)  # ~12 chars, unguessable
    expires_at = _now() + timedelta(minutes=config.KEY_TRANSFER_TTL_MINUTES)
    db.add(models.KeyTransfer(id=transfer_id, ciphertext=body.ciphertext, expires_at=expires_at))
    db.commit()

    return {"id": transfer_id, "expires_at": expires_at}


@router.get("/{transfer_id}", response_model=schemas.KeyTransferResponse)
@limiter.limit("20/minute")
def claim_transfer(request: Request, transfer_id: str, db: Session = Depends(get_db)):
    row = (
        db.query(models.KeyTransfer)
        .filter(models.KeyTransfer.id == transfer_id)
        .first()
    )
    # Treat missing AND expired identically (generic 404, no oracle). Delete an
    # expired row if we happened upon it.
    if row is None or row.expires_at.replace(tzinfo=timezone.utc) <= _now():
        if row is not None:
            db.delete(row)
            db.commit()
        raise HTTPException(status_code=404, detail="Transfer not found or expired")

    ciphertext = row.ciphertext
    # Single-use: consume on read.
    db.delete(row)
    db.commit()
    return {"ciphertext": ciphertext}
