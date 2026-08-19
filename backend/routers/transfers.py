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


def _as_naive(value: datetime) -> datetime:
    """Normalise to naive UTC. `expires_at` is DateTime (no timezone), so rows
    read back are naive while freshly-built values may still be aware."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


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
    # Naive UTC comparison to match the (timezone-less) column.
    db.query(models.KeyTransfer).filter(
        models.KeyTransfer.expires_at <= _now().replace(tzinfo=None)
    ).delete()

    transfer_id = _secrets.token_urlsafe(9)  # ~12 chars, unguessable
    expires_at = _as_naive(_now() + timedelta(minutes=config.KEY_TRANSFER_TTL_MINUTES))
    db.add(models.KeyTransfer(id=transfer_id, ciphertext=body.ciphertext, expires_at=expires_at))
    db.commit()

    return {"id": transfer_id, "expires_at": expires_at}


@router.get("/{transfer_id}", response_model=schemas.KeyTransferResponse)
@limiter.limit("20/minute")
def claim_transfer(request: Request, transfer_id: str, db: Session = Depends(get_db)):
    """Claim a transfer exactly once.

    Single-use is enforced by the DELETE itself, not by a preceding SELECT
    (KRY-003). Two concurrent claims both used to read the ciphertext before
    either delete landed, handing the vault blob to both callers. Here the
    delete is the guard: whoever's statement reports rowcount == 1 owns the
    row, everyone else gets a 404. Portable across Postgres and SQLite —
    `DELETE ... RETURNING` would not be.
    """
    # Read first, but treat the value as a *candidate* only: it is not ours
    # until the conditional delete below says so.
    row = (
        db.query(models.KeyTransfer)
        .filter(models.KeyTransfer.id == transfer_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Transfer not found or expired")

    ciphertext = row.ciphertext
    expires_at = row.expires_at

    # Detach so the pending-delete below is the only thing touching this row.
    db.expunge(row)

    # Expiry is evaluated inside the DELETE predicate, so an expired row is
    # never claimable even if it was still live at SELECT time. Naive UTC to
    # match the column convention.
    now_naive = _now().replace(tzinfo=None)
    deleted = (
        db.query(models.KeyTransfer)
        .filter(
            models.KeyTransfer.id == transfer_id,
            models.KeyTransfer.expires_at > now_naive,
        )
        .delete(synchronize_session=False)
    )
    db.commit()

    if deleted != 1:
        # Either another request consumed it first, or it had expired. Both
        # answer the same way — no oracle distinguishing the two.
        if expires_at is not None and _as_naive(expires_at) <= now_naive:
            # Expired row: clear it out so the table cannot accumulate.
            db.query(models.KeyTransfer).filter(
                models.KeyTransfer.id == transfer_id
            ).delete(synchronize_session=False)
            db.commit()
        raise HTTPException(status_code=404, detail="Transfer not found or expired")

    return {"ciphertext": ciphertext}
