from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

import auth
import config
import invites
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization
from security.audit_log import audit_event
from security.crypto_validation import is_valid_ml_dsa_public_key, is_valid_ml_kem_public_key
from security.usernames import InvalidUsername, normalize_username, username_taken
from utils.clock import utcnow_naive
from websocket_manager import SESSION_REVOKED, manager

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/nonce/{address}")
@limiter.limit("10/minute")
def get_nonce(request: Request, address: str, db: Session = Depends(get_db)):
    """Issue a single-use login challenge for this address, valid five minutes.

    Unauthenticated by necessity. Answers `nonce` and the server's `deployment`
    id, both of which the client signs into the login body. Several challenges
    may be live at once for one address, so a stranger cannot cancel someone
    else's login by asking for a new one (audit H-1).
    """
    # The address IS an ML-DSA-44 public key, so anything that is not one can
    # never produce a verifying signature and can never complete a login
    # (audit L-5). Checking the shape here stops an unauthenticated endpoint
    # from writing a row for every distinct string it is handed.
    if not is_valid_ml_dsa_public_key(address):
        raise HTTPException(status_code=400, detail="Invalid address")

    # Cleanup expired nonces first (lazy cleanup). Naive UTC throughout to
    # match the timezone-less expires_at column.
    now = utcnow_naive()
    db.query(models.Nonce).filter(models.Nonce.expires_at <= now).delete()

    nonce_val = auth.generate_nonce()
    expires = now + timedelta(minutes=5)

    # INSERT, never an upsert keyed by the address (audit H-1). This was
    # `db.merge` on an address-keyed row, so issuing a challenge REPLACED
    # whichever one that identity already held — and this endpoint cannot be
    # authenticated (the caller has no session yet) and is keyed by a public
    # value, so any stranger could invalidate a chosen user's in-flight login
    # with one request, repeatedly. Several challenges may now be live at once;
    # `_claim_nonce` still consumes exactly one. See models.Nonce for why there
    # is no per-address cap.
    db.add(models.Nonce(nonce=nonce_val, address=address.lower(), expires_at=expires))
    db.commit()

    # The deployment id goes into the signed body (crypto-core 3.0.0, K-02).
    # Public on purpose: it identifies this server, it does not authenticate it.
    return {"nonce": nonce_val, "deployment": config.deployment_id()}


def check_signed_for_this_server(origin: str, deployment: str) -> None:
    """Refuse a signature made for another site or another deployment.

    Shared by login and account deletion, the two bodies that name a server
    (crypto-core 3.0.0, audit 2026-10-12 K-02). Checked BEFORE the signature:
    a body naming a foreign origin is refused whether or not it verifies, and a
    stubbed verifier in the test suite cannot hide a missing check here.
    """
    if not auth.is_canonical_origin(origin) or not config.login_origin_allowed(origin):
        raise HTTPException(status_code=400, detail="This login was signed for another site.")
    if deployment != config.deployment_id():
        raise HTTPException(
            status_code=400, detail="This login was signed for another Kryptolog server."
        )


def claim_nonce(db: Session, address: str, nonce: str) -> bool:
    """Consume the login nonce atomically, returning whether this caller won it.

    The claim happens BEFORE signature verification (KRY-004). The old flow was
    SELECT then verify then DELETE, and ML-DSA verification is slow enough that
    the window between read and delete was comfortably wide: concurrent
    requests could each observe the same live nonce and each go on to mint a
    token, so "one-time" was not one-time. Making the DELETE itself the guard
    means exactly one caller can ever claim a given nonce — whoever's statement
    reports rowcount == 1 — and the expensive crypto happens after the claim is
    already settled.

    Public because account deletion claims a challenge the same way: the same
    single-use guarantee, for an action even less repeatable than a login.

    An address may hold several live challenges at once (audit H-1), which
    changes nothing here: the predicate names one of them, and the delete is
    still what settles ownership. Matching on the address as well as the nonce
    is what stops a challenge issued to one identity being spent by another.
    """
    claimed = (
        db.query(models.Nonce)
        .filter(
            models.Nonce.address == address,
            models.Nonce.nonce == nonce,
            models.Nonce.expires_at > utcnow_naive(),
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    return claimed == 1


def _verify_login_payload(login_req: schemas.LoginRequest, address: str) -> None:
    """Check the signature, the submitted key's format, and the attestation.

    Called only after the nonce is spent, so every failure here must leave it
    spent: handing back a replayable challenge on a failed attempt is exactly
    what consuming it first prevents.
    """
    check_signed_for_this_server(login_req.origin, login_req.deployment)

    if not auth.verify_signature(
        address,
        login_req.signature,
        nonce=login_req.nonce,
        origin=login_req.origin,
        deployment=login_req.deployment,
        encryption_public_key=login_req.encryption_public_key,
    ):
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
    # an invalid one is never stored.
    #
    # REQUIRED whenever a key is submitted (audit 2026-10-12 K-04). It was
    # optional "for older clients", and a login with a new key and no
    # attestation replaced the key AND erased the stored attestation — leaving
    # every new contact to accept an unattested key on first sight, which is
    # precisely the substitution the attestation exists to stop. Since the 3.0.0
    # cutover there are no older clients to accommodate.
    attestation = login_req.encryption_key_attestation
    if login_req.encryption_public_key and not attestation:
        raise HTTPException(
            status_code=400, detail="An encryption key must come with its attestation."
        )
    if attestation:
        if not login_req.encryption_public_key:
            raise HTTPException(status_code=400, detail="Attestation without an encryption key")
        att_msg = auth.encryption_key_attestation_message(login_req.encryption_public_key)
        if not auth.verify_message_signature(address, att_msg, attestation):
            raise HTTPException(status_code=400, detail="Invalid encryption key attestation")


def _claim_username(
    db: Session, login_req: schemas.LoginRequest, address: str, *, current: str | None = None
) -> str:
    """The username a new or revived identity will hold.

    `current` is what this address already holds — the name a "leave" left
    reserved for it. A revived identity that asks for nothing keeps it rather
    than being renamed to a truncated address, which is the whole point of
    reserving it (audit 2026-09-12 L-1).
    """
    try:
        default_username = normalize_username(login_req.username) or current or address[:7]
    except InvalidUsername as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Uniqueness is case-insensitive, so the directory can't hold "alice" and
    # "Alice" as two identities. Checked before consuming any invite, so a name
    # clash doesn't burn the code. Excluding this address is what lets a revived
    # identity reclaim the name it reserved on the way out; for a brand-new one
    # there is no row to exclude, so it changes nothing.
    if username_taken(db, default_username, exclude_address=address):
        raise HTTPException(
            status_code=409,
            detail=f"Username '{default_username}' is already taken. Please choose a different one.",
        )
    return default_username


def _consume_invite_or_403(db: Session, login_req: schemas.LoginRequest, address: str) -> None:
    """Access filter (audit §5): a new identity needs a valid code.

    Generic 403 on failure — no distinction between missing/expired/used, to
    avoid turning this into an invite-code oracle.
    """
    if config.invites_required() and not invites.consume_invite(
        db, login_req.invite_code, used_by=address
    ):
        db.rollback()
        raise HTTPException(status_code=403, detail="A valid invite code is required to register.")


def _revive_user(
    db: Session,
    login_req: schemas.LoginRequest,
    address: str,
    attestation: str | None,
    user: models.User,
) -> models.User:
    """Bring back an identity deleted with the "leave" mode.

    Every row the account owned is still attached to this address — nothing was
    ever detached — so reviving the row restores the account with its data.

    It is still an ADMISSION, not a plain login: an invite-only server charges a
    fresh code, because deleting and returning must not be a way around the
    access filter.

    The username is NOT re-contested, though. A "leave" keeps it reserved on
    the row, so returning finds it waiting — it used to be freed on the way
    out, which meant any stranger could take it while the account was away and
    the reversibility this mode promises depended on nobody having bothered
    (audit 2026-09-12 L-1).
    """
    username = _claim_username(db, login_req, address, current=user.username)

    user.username = username
    user.encryption_public_key = login_req.encryption_public_key
    user.encryption_key_attestation = attestation
    # A return is a key-directory event, and the server cannot tell whether the
    # key coming back is the one that left: the strip NULLed it, so there is
    # nothing to compare against. Stamping is the conservative direction of the
    # two — contacts see "this entry changed on <date>" and can re-verify, where
    # leaving it NULL says the key has never changed since creation, which is
    # not something this path knows (audit 2026-09-12 I-3).
    #
    # It does not cry wolf at the layer that matters: the TOFU store in
    # services/trustedKeys.js compares the actual key bytes on the client and
    # stays quiet when they are identical.
    user.key_changed_at = utcnow_naive()
    user.deleted_at = None
    db.add(user)
    db.flush()

    _consume_invite_or_403(db, login_req, address)
    db.commit()
    db.refresh(user)
    return user


def _register_user(
    db: Session, login_req: schemas.LoginRequest, address: str, attestation: str | None
) -> models.User:
    """Create a brand-new identity, consuming an invite if the server needs one."""
    default_username = _claim_username(db, login_req, address)

    user = models.User(
        address=address,
        encryption_public_key=login_req.encryption_public_key,
        encryption_key_attestation=attestation,
        username=default_username,
    )
    db.add(user)
    # Flush (don't commit) so the invite's used_by FK can see the new user while
    # keeping user creation + invite consumption a single atomic transaction: a
    # failed consume rolls the user back, and a crash can't burn a code without
    # creating the user.
    db.flush()

    # Access filter (audit §5): a brand-new identity may only be created with a
    # valid invite code when invites are required. Consumed atomically so the
    # same code can't be over-spent. Existing users never reach this branch.
    _consume_invite_or_403(db, login_req, address)

    db.commit()
    db.refresh(user)
    return user


def _upsert_identity(
    db: Session, login_req: schemas.LoginRequest, address: str, attestation: str | None
) -> tuple[models.User, str]:
    """Return the identity behind this login, creating or updating it as needed,
    and which of those happened — the audit trail records it (2026-09-11 M-3):
    "register", "return", "key_changed" or "login"."""
    user = db.query(models.User).filter(models.User.address == address).first()

    if not user:
        return _register_user(db, login_req, address, attestation), "register"

    if user.deleted_at is not None:
        # An "erase" deletion is final, and this is the one check that makes
        # the modal's promise true. Explicit rather than generic on purpose:
        # only the holder of the key reaches this point, and they are owed the
        # reason. GET /auth/nonce/{address} stays silent for the opposite
        # reason — it is unauthenticated, so answering there would turn it into
        # a "was this address deleted" oracle for anybody.
        if not authorization.may_register(user):
            # 410, NOT 403. The invite gate below also answers 403, and the SPA
            # turns any 403 from login into "this server is invite-only, enter
            # your code" — so an erased key was telling the user to find an
            # invite code for a key that can never be used again, whatever they
            # typed. Gone is also the honest status: the identity existed and
            # will not be available again.
            raise HTTPException(
                status_code=410,
                detail=(
                    "This account was deleted and this key can no longer be used. "
                    "Create a new identity to register again."
                ),
            )
        return _revive_user(db, login_req, address, attestation, user), "return"

    kind = "login"
    if (
        login_req.encryption_public_key
        and user.encryption_public_key != login_req.encryption_public_key
    ):
        kind = "key_changed"
        # Encryption key changed (or was never set). Update it, but — unlike the
        # previous silent overwrite (audit S1) — stamp key_changed_at so the
        # change is auditable and clients can warn contacts about a key swap.
        # Only stamp when a key was already present (a genuine change), not when
        # backfilling a key onto an identity that had none.
        if user.encryption_public_key:
            user.key_changed_at = utcnow_naive()
        user.encryption_public_key = login_req.encryption_public_key
        # The old attestation signed the old key — never leave a stale one.
        user.encryption_key_attestation = attestation
        db.commit()
    elif attestation and not user.encryption_key_attestation:
        # Backfill: an account that predates attestations (or whose earlier
        # client didn't send one) starts attesting its unchanged key.
        user.encryption_key_attestation = attestation
        db.commit()

    db.refresh(user)
    return user, kind


@router.post("/login", response_model=schemas.Token)
@limiter.limit("5/minute")
def login(request: Request, login_req: schemas.LoginRequest, db: Session = Depends(get_db)):
    """Exchange a signed nonce for an access token, registering on first sight.

    Four phases, in this order for a reason: claim the nonce, verify the
    payload, upsert the identity, mint the token. The claim comes first so a
    failed verification cannot hand back a replayable challenge (KRY-004).
    """
    address = login_req.address.lower()
    try:
        user, kind = _login(db, login_req, address)
    except HTTPException as exc:
        # Every refusal, with its reason: a run of these against one address
        # is what an attack on it looks like (audit 2026-09-11 M-3).
        audit_event(
            "auth.login",
            request=request,
            actor=address,
            outcome="refused",
            status=exc.status_code,
            reason=exc.detail,
        )
        raise
    audit_event("auth.login", request=request, actor=address, kind=kind)
    if kind == "key_changed":
        audit_event("auth.key_changed", request=request, actor=address)

    access_token = auth.create_access_token(
        data={"sub": user.address, "tv": user.token_version or 0},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Token signing failed."
        )
    return {"access_token": access_token, "token_type": "bearer", "user": user}


def _login(db: Session, login_req: schemas.LoginRequest, address: str):
    """Claim, verify, upsert — everything `login` audits the outcome of. The
    address is the CLAIMED one until the signature has been checked, which is
    how a refused line in the audit trail should be read."""
    if not claim_nonce(db, address, login_req.nonce):
        # Missing, mismatched, expired, or already consumed — one generic
        # answer, so this can't be used to probe which nonces exist.
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    _verify_login_payload(login_req, address)
    return _upsert_identity(db, login_req, address, login_req.encryption_key_attestation)


@router.post("/logout")
@limiter.limit("20/minute")
def logout(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke all of this user's tokens by bumping their token_version.
    Existing JWTs (carrying the old tv) stop validating immediately.

    Immediately on the REST surface, that is. A WebSocket is authenticated once,
    at its handshake, so bumping the version left an ALREADY-OPEN socket
    delivering every incoming message in real time (audit 2026-09-11 M-1) — and
    "revoke all sessions" is aimed precisely at a tab the user no longer
    controls. The row has to be committed before the hangup, or a socket that
    races the close and reconnects is re-admitted against the old version — a
    background task runs after the response, so after the commit by
    construction.
    """
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    audit_event("auth.logout", request=request, actor=current_user.address)
    background_tasks.add_task(manager.close_address, current_user.address, reason=SESSION_REVOKED)
    return {"status": "ok"}
