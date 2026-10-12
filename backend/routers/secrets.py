from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, joinedload

import config
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization, quota
from utils.clock import utcnow_naive
from utils.push import display_name, schedule_push
from websocket_manager import manager

router = APIRouter(tags=["secrets"])

# Page sizes for the list endpoints (audit O-3). These used to return every row
# the user owned, in one response, with no ceiling — and a Secret carries its
# `encrypted_data` inline (500 KB by schema), so the response size was bounded
# only by how many secrets the account happened to hold, against a worker that
# PM2 restarts at 500 MB. Bounded at BOTH ends by FastAPI, like GET /users: the
# ceiling alone still let `?limit=-1` reach PostgreSQL as `LIMIT -1`, which is a
# hard error rather than an empty page.
#
# The lists no longer carry `encrypted_data` at all (see SecretSummaryResponse),
# so these bound row counts on responses that are metadata throughout.
SECRET_PAGE_MAX = 100
SECRET_PAGE_DEFAULT = 50
GRANT_PAGE_MAX = 200
GRANT_PAGE_DEFAULT = 100


def _load_secret(
    secret_id: int, user_address: str, db: Session, requires=authorization.can_read_secret
) -> models.Secret:
    """Load a secret the caller is allowed to touch, or raise 404/403.

    The rules live in security.authorization so they cannot drift between the
    endpoints that enforce them (KRY-001: expired grants used to keep unlocking
    file chunks because only the listing endpoints checked expiry). `requires`
    picks which question to ask — read, write, or manage — because five
    endpoints below used to inline this block with their own predicate, which
    is how the two copies get to disagree in the first place.
    """
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if not requires(db, secret, user_address):
        _refuse(db, secret, user_address)

    return secret


def _refuse(db: Session, secret: models.Secret, user_address: str):
    """Refuse an action on a secret: 403 if the caller may read it, else 404.

    A stranger got 403 for somebody else's secret and 404 for a missing one,
    and ids are sequential, so walking them measured how many secrets exist and
    how fast they are made (audit 2026-09-11 F-4). Someone who cannot read a
    secret now learns nothing about it, not even that it exists. Someone who can
    read it already knows, so a 403 tells them only which right they lack.
    """
    if authorization.can_read_secret(db, secret, user_address):
        raise HTTPException(status_code=403, detail="Not authorized")
    raise HTTPException(status_code=404, detail="Secret not found")


def _enforce_quota(check, *args) -> None:
    """Run a quota check, answering 413 with its reason (audit 2026-10-12 K-09)."""
    try:
        check(*args)
    except quota.QuotaExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


def _refuse_if_workflow_managed(db: Session, secret_id: int, verb: str) -> None:
    """Block direct mutation of a secret a multisig workflow owns."""
    if authorization.is_workflow_managed(db, secret_id):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot {verb} a secret managed by a Multisig Workflow",
        )


def create_secret_with_owner_grant(
    db: Session, owner: models.User, secret_data: schemas.SecretBase, *, commit: bool = True
) -> models.Secret:
    """Create a secret and the owner's own access grant, and commit both.

    `commit=False` only flushes, for a caller that creates more in the same
    transaction (multisig workflow creation, audit 2026-09-23 F-2) and commits
    once at the end.

    A secret is useless without a grant: the content is encrypted under a key
    only AccessGrant carries, so creating one without the other leaves a row
    its own owner cannot read. Multisig workflow creation builds the same pair,
    which is why this is a function rather than eight statements in two files —
    and why the quota is checked here, so neither path can skip it.
    """
    # Locked until the commit below, so two concurrent creations cannot both
    # see room for "one more" (security/quota.py).
    quota.lock_owner(db, owner.address)
    _enforce_quota(
        quota.check_new_secret,
        db,
        owner.address,
        len(secret_data.encrypted_data) + len(secret_data.name),
    )

    secret = models.Secret(
        owner_address=owner.address,
        name=secret_data.name,
        type=secret_data.type,
        encrypted_data=secret_data.encrypted_data,
    )
    db.add(secret)
    db.flush()  # assigns secret.id, which the grant needs

    db.add(
        models.AccessGrant(
            secret_id=secret.id,
            grantee_address=owner.address,
            encrypted_key=secret_data.encrypted_key,
        )
    )
    if commit:
        db.commit()
        db.refresh(secret)
    else:
        db.flush()

    # Not a column: the response carries the caller's wrap, which lives on
    # AccessGrant. Set on the instance so Pydantic can read it.
    secret.encrypted_key = secret_data.encrypted_key
    return secret


@router.post("/secrets", response_model=schemas.SecretResponse)
@limiter.limit("20/minute")
def create_secret(
    request: Request,
    secret: schemas.SecretCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return create_secret_with_owner_grant(db, current_user, secret)


@router.get("/secrets", response_model=list[schemas.SecretSummaryResponse])
@limiter.limit("60/minute")
def get_secrets(
    request: Request,
    limit: int = Query(SECRET_PAGE_DEFAULT, ge=1, le=SECRET_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # `encrypted_data` is deferred, not just absent from SecretSummaryResponse
    # (audit O-3). Dropping it in the schema alone would still have Postgres
    # ship every ciphertext to the worker for Pydantic to discard — the bytes
    # this endpoint was criticised for moving would simply move one step less
    # far. Content comes from GET /secrets/{id}.
    results = (
        db.query(models.Secret, models.AccessGrant.encrypted_key)
        .options(joinedload(models.Secret.owner), defer(models.Secret.encrypted_data))
        .join(
            models.AccessGrant,
            (models.AccessGrant.secret_id == models.Secret.id)
            & (models.AccessGrant.grantee_address == current_user.address),
        )
        .outerjoin(models.MultisigWorkflow, models.MultisigWorkflow.secret_id == models.Secret.id)
        .filter(models.Secret.owner_address == current_user.address)
        .filter(models.MultisigWorkflow.id.is_(None))
        .order_by(models.Secret.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    response = []
    for secret, key in results:
        secret.encrypted_key = key
        response.append(secret)

    return response


@router.put("/secrets/{secret_id}", response_model=schemas.SecretResponse)
@limiter.limit("30/minute")
def update_secret(
    request: Request,
    secret_id: int,
    secret_update: schemas.SecretCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    secret = _load_secret(secret_id, current_user.address, db, authorization.can_manage_secret)
    _refuse_if_workflow_managed(db, secret_id, "edit")

    # An edit can grow a secret up to the 500 KB field bound; only the growth
    # counts against the quota.
    quota.lock_owner(db, current_user.address)
    growth = (len(secret_update.encrypted_data) + len(secret_update.name)) - (
        len(secret.encrypted_data or "") + len(secret.name or "")
    )
    if growth > 0:
        _enforce_quota(quota.check_new_bytes, db, current_user.address, growth)

    secret.name = secret_update.name
    secret.encrypted_data = secret_update.encrypted_data
    db.commit()
    db.refresh(secret)
    return secret


@router.delete("/secrets/{secret_id}")
@limiter.limit("30/minute")
def delete_secret(
    request: Request,
    secret_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    secret = _load_secret(secret_id, current_user.address, db, authorization.can_manage_secret)
    _refuse_if_workflow_managed(db, secret_id, "delete")

    db.query(models.AccessGrant).filter(models.AccessGrant.secret_id == secret_id).delete()
    db.delete(secret)
    db.commit()
    return {"status": "ok"}


@router.post("/secrets/share", response_model=schemas.AccessGrantResponse)
@limiter.limit("30/minute")
def share_secret(
    request: Request,
    background_tasks: BackgroundTasks,
    grant: schemas.AccessGrantCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    grantee_address = authorization.normalize_address(grant.grantee_address)

    secret = _load_secret(
        grant.secret_id, current_user.address, db, authorization.can_manage_secret
    )
    _refuse_if_workflow_managed(db, grant.secret_id, "manually share")

    if authorization.is_owner_grant(secret, grantee_address):
        raise HTTPException(status_code=400, detail="You already own this secret")

    grantee = authorization.find_active_user(db, grantee_address)
    if not grantee:
        raise HTTPException(status_code=404, detail="Grantee not found")

    expires_at = None
    if grant.expires_in:
        expires_at = utcnow_naive() + timedelta(seconds=grant.expires_in)

    new_grant = _upsert_grant(
        db,
        secret_id=grant.secret_id,
        grantee_address=grantee_address,
        encrypted_key=grant.encrypted_key,
        expires_at=expires_at,
    )

    background_tasks.add_task(
        manager.send_personal_message,
        {
            "type": "SECRET_SHARED",
            "data": {
                "secret_id": new_grant.secret_id,
                "sender": current_user.address,
                "grant_id": new_grant.id,
            },
        },
        grantee_address,
    )

    sender_name = display_name(current_user)
    schedule_push(
        grantee_address,
        title="Secret Shared",
        # Generic body: secret titles are E2EE blobs the server can't read (M-3).
        body=f"{sender_name} shared a secure secret with you",
        data={"type": "secret_shared", "secret_id": secret.id},
    )

    return new_grant


def _upsert_grant(db: Session, **values) -> models.AccessGrant:
    """Create the grant, or replace the wrap and expiry of the existing one.

    One statement against `uq_access_grant_secret_grantee` (audit 2026-09-23
    F-1). Sharing used to delete and re-insert in two commits, so concurrent
    shares each saw no row and each inserted one; revoking one left the other
    serving the key. A re-share keeps the grant's id and resets created_at.
    """
    dialect = db.get_bind().dialect.name
    insert = sqlite_insert if dialect == "sqlite" else pg_insert
    stmt = insert(models.AccessGrant).values(created_at=utcnow_naive(), **values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["secret_id", "grantee_address"],
        set_={
            "encrypted_key": stmt.excluded.encrypted_key,
            "expires_at": stmt.excluded.expires_at,
            "created_at": stmt.excluded.created_at,
        },
    ).returning(models.AccessGrant.id)
    grant_id = db.execute(stmt).scalar_one()
    db.commit()
    return db.get(models.AccessGrant, grant_id)


@router.delete("/secrets/share/{grant_id}")
@limiter.limit("30/minute")
def revoke_grant(
    request: Request,
    grant_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    grant = db.query(models.AccessGrant).filter(models.AccessGrant.id == grant_id).first()
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")

    if not authorization.can_manage_grant(db, grant, current_user.address):
        # Same rule as _refuse, for grant ids: they are sequential too (F-4).
        if authorization.can_read_secret(db, grant.secret, current_user.address):
            raise HTTPException(status_code=403, detail="Not authorized")
        raise HTTPException(status_code=404, detail="Grant not found")

    if authorization.is_owner_grant(grant.secret, grant.grantee_address):
        raise HTTPException(
            status_code=400, detail="The owner's own access cannot be revoked; delete the secret"
        )

    _refuse_if_workflow_managed(db, grant.secret_id, "manually revoke access to")

    db.delete(grant)
    db.commit()
    return {"status": "ok"}


@router.get("/secrets/{secret_id}/access", response_model=list[schemas.AccessGrantResponse])
@limiter.limit("60/minute")
def get_secret_access(
    request: Request,
    secret_id: int,
    limit: int = Query(GRANT_PAGE_DEFAULT, ge=1, le=GRANT_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _load_secret(secret_id, current_user.address, db, authorization.can_manage_secret)
    authorization.purge_expired_grants(db, secret_id=secret_id)

    return (
        db.query(models.AccessGrant)
        .filter(models.AccessGrant.secret_id == secret_id)
        .order_by(models.AccessGrant.id)
        .limit(limit)
        .offset(offset)
        .all()
    )


@router.get("/secrets/shared-with-me", response_model=list[schemas.SharedSecretResponse])
@limiter.limit("60/minute")
def get_shared_secrets(
    request: Request,
    limit: int = Query(SECRET_PAGE_DEFAULT, ge=1, le=SECRET_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    authorization.purge_expired_grants(db, grantee=current_user.address)

    return (
        db.query(models.AccessGrant)
        .options(
            # Deferred for the same reason as GET /secrets: the schema drops the
            # ciphertext, this stops it being fetched at all (audit O-3).
            joinedload(models.AccessGrant.secret)
            .defer(models.Secret.encrypted_data)
            .joinedload(models.Secret.owner),
            joinedload(models.AccessGrant.grantee),
        )
        .join(models.Secret)
        .outerjoin(models.MultisigWorkflow, models.MultisigWorkflow.secret_id == models.Secret.id)
        .filter(
            models.AccessGrant.grantee_address == current_user.address,
            models.Secret.owner_address != current_user.address,
            models.MultisigWorkflow.id.is_(None),
        )
        .order_by(models.AccessGrant.id.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )


# ORDERING MATTERS: this must stay BELOW every literal /secrets/... route.
# FastAPI matches in declaration order, so a `{secret_id}` path declared above
# `/secrets/shared-with-me` swallows it — the request never reaches the listing
# and comes back as a 422 on an int that was never an int. Covered by a test,
# because nothing else about the failure points at route order.
@router.get("/secrets/{secret_id}", response_model=schemas.SecretResponse)
@limiter.limit("120/minute")
def get_secret(
    request: Request,
    secret_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """One secret with its ciphertext.

    The lists stopped carrying `encrypted_data` (audit O-3) and this is where
    it went. Same read rule as the chunk endpoints — owner, live grant, or
    multisig participant — because it is the same question, asked through
    `_check_secret_access` so the two cannot answer it differently (KRY-001).

    The 120/min limit matches `get_chunk`: opening one secret is one request
    here, and a client browsing its vault makes a burst of them.
    """
    secret = _load_secret(secret_id, current_user.address, db)

    # The caller's own wrap, if they hold one. Multisig signers and recipients
    # get theirs from the workflow instead, so this is legitimately None for
    # them — `find_live_grant` also refuses an expired grant, which is the
    # whole of KRY-001.
    grant = authorization.find_live_grant(db, secret.id, current_user.address)
    secret.encrypted_key = grant.encrypted_key if grant else None
    return secret


# NOTE: the /documents endpoints were removed (audit L-10). POST /documents
# accepted an arbitrary `content_hash` and `signature`, verified neither, and
# carried no rate limit — an authenticated write endpoint storing unvalidated
# text under the user's name. No client ever called it, in the SPA or the
# extension, so there was no feature to preserve by hardening it instead.
# The table is dropped in migration a7b8c9d0e5f6.


# --- File Chunks ---


@router.post("/secrets/chunks", status_code=201)
@limiter.limit("120/minute")
def upload_chunk(
    request: Request,
    chunk: schemas.FileChunkUpload,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload a single encrypted file chunk. Only the secret owner can upload."""
    _load_secret(chunk.secret_id, current_user.address, db, authorization.can_write_secret)

    # Lock the owner BEFORE counting anything. Both ceilings below are
    # read-then-insert, and concurrent uploads used to each see room under the
    # 50 MB per-file cap and all land past it (security/quota.py).
    quota.lock_owner(db, current_user.address)
    _enforce_quota(quota.check_new_bytes, db, current_user.address, len(chunk.encrypted_data))

    # Enforce total file size limit using SQL-level aggregation. Base64 since
    # the L-12 cutover: 4 chars per 3 bytes, so chars * 3/4 (was chars / 2).
    # Counted in SQL rather than by loading the rows — see the note on the
    # listing query below.
    total_stored_size_b64 = (
        db.query(func.sum(func.length(models.FileChunk.encrypted_data)))
        .filter(models.FileChunk.secret_id == chunk.secret_id)
        .scalar()
        or 0
    )

    # Slightly over-counts: padding makes the true byte count up to 2 lower per
    # chunk. Over-counting is the safe direction for a ceiling.
    current_total_bytes = total_stored_size_b64 * 3 / 4
    new_chunk_size = len(chunk.encrypted_data) * 3 / 4

    if (current_total_bytes + new_chunk_size) > config.MAX_TOTAL_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {config.MAX_TOTAL_FILE_SIZE // (1024 * 1024)}MB)",
        )

    new_chunk = models.FileChunk(
        secret_id=chunk.secret_id,
        chunk_index=chunk.chunk_index,
        iv=chunk.iv,
        encrypted_data=chunk.encrypted_data,
    )
    db.add(new_chunk)
    try:
        db.commit()
    except IntegrityError:
        # uq_file_chunk_secret_index (audit M-2). Re-uploading an index the file
        # already holds is a client bug or an attempt to shadow a chunk, not a
        # partial write to paper over — reject it rather than letting reads pick
        # non-deterministically between two rows.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Chunk {chunk.chunk_index} already uploaded for this secret",
        )
    return {"status": "ok", "chunk_index": chunk.chunk_index}


# NOTE: `GET /secrets/{id}/chunks` (list every chunk WITH its payload) was removed
# — audit H-2. Despite its "metadata only if needed" docstring it loaded every
# row's full encrypted_data: at MAX_TOTAL_FILE_SIZE, one
# unauthenticated-by-rate-limit request materialized ~100 MB of strings (~67 MB
# now that payloads are base64 — cheaper, still ruinous), again
# through Pydantic, against a 500 MB worker restart threshold. No client ever
# called it — fileChunks.js fetches chunks one at a time by index, below.


@router.get("/secrets/{secret_id}/chunks/{chunk_index}", response_model=schemas.FileChunkResponse)
@limiter.limit("240/minute")
def get_chunk(
    request: Request,
    secret_id: int,
    chunk_index: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download a single encrypted chunk by index."""
    _load_secret(secret_id, current_user.address, db)

    chunk = (
        db.query(models.FileChunk)
        .filter(
            models.FileChunk.secret_id == secret_id, models.FileChunk.chunk_index == chunk_index
        )
        .first()
    )

    if not chunk:
        raise HTTPException(status_code=404, detail=f"Chunk {chunk_index} not found")

    return chunk
