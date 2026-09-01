from fastapi import APIRouter, Depends, HTTPException, status, Request
from dependencies import limiter, get_current_user
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import models, schemas, auth, config, invites
from database import get_db
from security.crypto_validation import is_valid_ml_kem_public_key
from security.usernames import InvalidUsername, normalize_username, username_taken

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.get("/nonce/{address}")
@limiter.limit("10/minute")
def get_nonce(request: Request, address: str, db: Session = Depends(get_db)):
    # Cleanup expired nonces first (lazy cleanup). Naive UTC throughout to
    # match the timezone-less expires_at column.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.query(models.Nonce).filter(models.Nonce.expires_at <= now).delete()

    nonce_val = auth.generate_nonce()
    expires = now + timedelta(minutes=5)
    
    # Upsert logic
    new_nonce = models.Nonce(address=address.lower(), nonce=nonce_val, expires_at=expires)
    db.merge(new_nonce) # Updates if exists
    db.commit()
    
    return {"nonce": nonce_val}

@router.post("/login", response_model=schemas.Token)
@limiter.limit("5/minute")
def login(request: Request, login_req: schemas.LoginRequest, db: Session = Depends(get_db)):
    address = login_req.address.lower()
    
    # Consume the nonce atomically BEFORE verifying the signature (KRY-004).
    #
    # The old flow was SELECT -> verify -> DELETE, and ML-DSA verification is
    # slow enough that the window between read and delete was comfortably wide:
    # concurrent requests could each observe the same live nonce and each go on
    # to mint a token, so "one-time" was not actually one-time. Making the
    # DELETE itself the guard means exactly one caller can ever claim a given
    # nonce — whoever's statement reports rowcount == 1 — and the expensive
    # crypto happens after the claim is already settled.
    #
    # Naive UTC to match the (timezone-less) expires_at column.
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    claimed = (
        db.query(models.Nonce)
        .filter(
            models.Nonce.address == address,
            models.Nonce.nonce == login_req.nonce,
            models.Nonce.expires_at > now_naive,
        )
        .delete(synchronize_session=False)
    )
    db.commit()

    if claimed != 1:
        # Missing, mismatched, expired, or already consumed — one generic
        # answer, so this can't be used to probe which nonces exist.
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    # From here the nonce is spent: every failure below must leave it spent,
    # otherwise a failed attempt would hand back a replayable challenge.
    if not auth.verify_signature(address, login_req.nonce, login_req.signature, login_req.encryption_public_key):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Reject malformed encryption keys before they can be stored (KRY-011).
    # Enforced only on keys being *submitted*, so accounts whose stored key
    # predates this check keep working until their client sends a new one —
    # existing users are not locked out by a validation tightening.
    if login_req.encryption_public_key and not is_valid_ml_kem_public_key(
        login_req.encryption_public_key
    ):
        raise HTTPException(
            status_code=400,
            detail="encryption_public_key must be a hex-encoded ML-KEM-768 public key",
        )

    # Key attestation (audit M-1): a self-signature by `address` over its own
    # ML-KEM key. Peers verify it client-side; the server checks it here too so
    # an invalid one is never stored. Optional (older clients don't send it).
    attestation = login_req.encryption_key_attestation
    if attestation:
        if not login_req.encryption_public_key:
            raise HTTPException(status_code=400, detail="Attestation without an encryption key")
        att_msg = auth.encryption_key_attestation_message(login_req.encryption_public_key)
        if not auth.verify_message_signature(address, att_msg, attestation):
            raise HTTPException(status_code=400, detail="Invalid encryption key attestation")

    # (Nonce already consumed atomically above — nothing to clean up here.)

    # Find or create user
    user = db.query(models.User).filter(models.User.address == address).first()
    if not user:
        # Default username logic: Use provided username OR first 7 chars of address
        try:
            default_username = normalize_username(login_req.username) or address[:7]
        except InvalidUsername as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # Check username uniqueness (case-insensitive, so the directory can't
        # hold "alice" and "Alice" as two identities) before consuming any
        # invite, so a name clash doesn't burn the code.
        if username_taken(db, default_username):
            raise HTTPException(
                status_code=409,
                detail=f"Username '{default_username}' is already taken. Please choose a different one."
            )

        user = models.User(
            address=address,
            encryption_public_key=login_req.encryption_public_key,
            encryption_key_attestation=attestation,
            username=default_username
        )
        db.add(user)
        # Flush (don't commit) so the invite's used_by FK can see the new user
        # while keeping user creation + invite consumption a single atomic
        # transaction: a failed consume rolls the user back, and a crash can't
        # burn a code without creating the user.
        db.flush()

        # Access filter (audit §5): a brand-new identity may only be created with a
        # valid invite code when invites are required. Consumed atomically so the
        # same code can't be over-spent. Existing users never reach this branch.
        # Generic 403 on failure — no distinction between missing/expired/used, to
        # avoid turning this into an invite-code oracle.
        if config.invites_required():
            if not invites.consume_invite(db, login_req.invite_code, used_by=address):
                db.rollback()
                raise HTTPException(status_code=403, detail="A valid invite code is required to register.")

        db.commit()
        db.refresh(user)
    elif login_req.encryption_public_key and user.encryption_public_key != login_req.encryption_public_key:
        # Encryption key changed (or was never set). Update it, but — unlike the
        # previous silent overwrite (audit S1) — stamp key_changed_at so the
        # change is auditable and clients can warn contacts about a key swap.
        # Only stamp when a key was already present (a genuine change), not when
        # backfilling a key onto an identity that had none.
        if user.encryption_public_key:
            user.key_changed_at = datetime.now(timezone.utc)
        user.encryption_public_key = login_req.encryption_public_key
        # The old attestation signed the old key — never leave a stale one.
        user.encryption_key_attestation = attestation
        db.commit()
        db.refresh(user)
    else:
        # Backfill: an account that predates attestations (or whose earlier
        # client didn't send one) starts attesting its unchanged key.
        if attestation and not user.encryption_key_attestation:
            user.encryption_key_attestation = attestation
            db.commit()
        # Ensure we refresh even if no changes to get latest state
        db.refresh(user)
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.address, "tv": user.token_version or 0},
        expires_delta=access_token_expires
    )
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token signing failed."
        )
    return {"access_token": access_token, "token_type": "bearer", "user": user}


@router.post("/logout")
@limiter.limit("20/minute")
def logout(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke all of this user's tokens by bumping their token_version.
    Existing JWTs (carrying the old tv) stop validating immediately."""
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    return {"status": "ok"}
