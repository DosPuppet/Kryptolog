from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, joinedload

import config
import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import authorization
from utils.push import notify_user_push_async
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


def _check_secret_access(secret_id: int, user_address: str, db: Session) -> models.Secret:
    """Verify the user may read this secret, or raise.

    The rules live in security.authorization so they cannot drift between the
    endpoints that enforce them (KRY-001: expired grants used to keep unlocking
    file chunks because only the listing endpoints checked expiry).
    """
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if not authorization.can_read_secret(db, secret, user_address):
        raise HTTPException(status_code=403, detail="Not authorized")

    return secret


@router.post("/secrets", response_model=schemas.SecretResponse)
@limiter.limit("20/minute")
def create_secret(request: Request, secret: schemas.SecretCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_secret = models.Secret(
        owner_address=current_user.address,
        name=secret.name,
        type=secret.type,
        encrypted_data=secret.encrypted_data
    )
    db.add(new_secret)
    db.flush() # Flush to get ID

    owner_grant = models.AccessGrant(
        secret_id=new_secret.id,
        grantee_address=current_user.address,
        encrypted_key=secret.encrypted_key
    )
    db.add(owner_grant)
    db.commit()
    db.refresh(new_secret)
    
    # Not a column: the response carries the caller's wrap, which lives on
    # AccessGrant. Set on the instance so Pydantic can read it.
    new_secret.encrypted_key = secret.encrypted_key
    return new_secret

@router.get("/secrets", response_model=List[schemas.SecretSummaryResponse])
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
def update_secret(request: Request, secret_id: int, secret_update: schemas.SecretCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    if not authorization.can_manage_secret(db, secret, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent editing a workflow-managed secret directly
    workflow = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.secret_id == secret_id).first()
    if workflow:
        raise HTTPException(status_code=400, detail="Cannot edit a secret managed by a Multisig Workflow")

    secret.name = secret_update.name
    secret.encrypted_data = secret_update.encrypted_data
    db.commit()
    db.refresh(secret)
    return secret

@router.delete("/secrets/{secret_id}")
@limiter.limit("30/minute")
def delete_secret(request: Request, secret_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    if not authorization.can_manage_secret(db, secret, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent deleting a workflow-managed secret directly
    workflow = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.secret_id == secret_id).first()
    if workflow:
        raise HTTPException(status_code=400, detail="Cannot delete a secret managed by a Multisig Workflow")

    db.query(models.AccessGrant).filter(models.AccessGrant.secret_id == secret_id).delete()
    db.delete(secret)
    db.commit()
    return {"status": "ok"}

@router.post("/secrets/share", response_model=schemas.AccessGrantResponse)
@limiter.limit("30/minute")
async def share_secret(request: Request, grant: schemas.AccessGrantCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = db.query(models.Secret).filter(models.Secret.id == grant.secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    if not authorization.can_manage_secret(db, secret, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent sharing a workflow-managed secret directly
    workflow = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.secret_id == grant.secret_id).first()
    if workflow:
        raise HTTPException(status_code=400, detail="Cannot manually share a secret managed by a Multisig Workflow")

    grantee = db.query(models.User).filter(models.User.address == grant.grantee_address.lower()).first()
    if not grantee:
        raise HTTPException(status_code=404, detail="Grantee not found")

    existing_grant = db.query(models.AccessGrant).filter(
        models.AccessGrant.secret_id == grant.secret_id,
        models.AccessGrant.grantee_address == grant.grantee_address.lower()
    ).first()
    
    if existing_grant:
        db.delete(existing_grant)
        db.commit()

    expires_at = None
    if grant.expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=grant.expires_in)

    new_grant = models.AccessGrant(
        secret_id=grant.secret_id,
        grantee_address=grant.grantee_address.lower(),
        encrypted_key=grant.encrypted_key,
        expires_at=expires_at
    )
    db.add(new_grant)
    db.commit()
    db.refresh(new_grant)

    await manager.send_personal_message({
        "type": "SECRET_SHARED",
        "data": {
            "secret_id": new_grant.secret_id,
            "sender": current_user.address,
            "grant_id": new_grant.id
        }
    }, grant.grantee_address.lower())

    sender_name = current_user.username or f"{current_user.address[:8]}..."
    await notify_user_push_async(
        db,
        grant.grantee_address.lower(),
        title="Secret Shared",
        # Generic body: secret titles are E2EE blobs the server can't read (M-3).
        body=f"{sender_name} shared a secure secret with you",
        data={"type": "secret_shared", "secret_id": secret.id}
    )

    return new_grant

@router.delete("/secrets/share/{grant_id}")
@limiter.limit("30/minute")
def revoke_grant(request: Request, grant_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    grant = db.query(models.AccessGrant).filter(models.AccessGrant.id == grant_id).first()
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    
    if not authorization.can_manage_grant(db, grant, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent revoking a workflow-managed secret grant directly
    workflow = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.secret_id == grant.secret_id).first()
    if workflow:
        raise HTTPException(status_code=400, detail="Cannot manually revoke access to a secret managed by a Multisig Workflow")

    db.delete(grant)
    db.commit()
    return {"status": "ok"}

@router.get("/secrets/{secret_id}/access", response_model=List[schemas.AccessGrantResponse])
@limiter.limit("60/minute")
def get_secret_access(
    request: Request,
    secret_id: int,
    limit: int = Query(GRANT_PAGE_DEFAULT, ge=1, le=GRANT_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
        
    if not authorization.can_manage_secret(db, secret, current_user.address):
        raise HTTPException(status_code=403, detail="Not authorized")

    now = datetime.now(timezone.utc)
    db.query(models.AccessGrant).filter(
        models.AccessGrant.secret_id == secret_id,
        models.AccessGrant.expires_at.isnot(None),
        models.AccessGrant.expires_at <= now
    ).delete(synchronize_session="fetch")
    db.commit()

    return db.query(models.AccessGrant).filter(
        models.AccessGrant.secret_id == secret_id
    ).order_by(models.AccessGrant.id).limit(limit).offset(offset).all()

@router.get("/secrets/shared-with-me", response_model=List[schemas.SharedSecretResponse])
@limiter.limit("60/minute")
def get_shared_secrets(
    request: Request,
    limit: int = Query(SECRET_PAGE_DEFAULT, ge=1, le=SECRET_PAGE_MAX),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)

    db.query(models.AccessGrant).filter(
        models.AccessGrant.grantee_address == current_user.address,
        models.AccessGrant.expires_at.isnot(None),
        models.AccessGrant.expires_at <= now
    ).delete(synchronize_session="fetch")
    db.commit()

    return db.query(models.AccessGrant).options(
        # Deferred for the same reason as GET /secrets: the schema drops the
        # ciphertext, this stops it being fetched at all (audit O-3).
        joinedload(models.AccessGrant.secret)
            .defer(models.Secret.encrypted_data)
            .joinedload(models.Secret.owner),
        joinedload(models.AccessGrant.grantee)
    ).join(
        models.Secret
    ).outerjoin(
        models.MultisigWorkflow, models.MultisigWorkflow.secret_id == models.Secret.id
    ).filter(
        models.AccessGrant.grantee_address == current_user.address,
        models.Secret.owner_address != current_user.address,
        models.MultisigWorkflow.id.is_(None),
    ).order_by(models.AccessGrant.id.desc()).limit(limit).offset(offset).all()


# ORDERING MATTERS: this must stay BELOW every literal /secrets/... route.
# FastAPI matches in declaration order, so a `{secret_id}` path declared above
# `/secrets/shared-with-me` swallows it — the request never reaches the listing
# and comes back as a 422 on an int that was never an int. Covered by a test,
# because nothing else about the failure points at route order.
@router.get("/secrets/{secret_id}", response_model=schemas.SecretResponse)
@limiter.limit("120/minute")
def get_secret(request: Request, secret_id: int,
               current_user: models.User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """One secret with its ciphertext.

    The lists stopped carrying `encrypted_data` (audit O-3) and this is where
    it went. Same read rule as the chunk endpoints — owner, live grant, or
    multisig participant — because it is the same question, asked through
    `_check_secret_access` so the two cannot answer it differently (KRY-001).

    The 120/min limit matches `get_chunk`: opening one secret is one request
    here, and a client browsing its vault makes a burst of them.
    """
    secret = _check_secret_access(secret_id, current_user.address, db)

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
def upload_chunk(request: Request, chunk: schemas.FileChunkUpload,
                 current_user: models.User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    """Upload a single encrypted file chunk. Only the secret owner can upload."""
    secret = db.query(models.Secret).filter(models.Secret.id == chunk.secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
    if not authorization.can_write_secret(db, secret, current_user.address):
        raise HTTPException(status_code=403, detail="Only the owner can upload chunks")

    # Enforce total file size limit using SQL-level aggregation (hex-encoded: 2 chars = 1 byte)
    total_stored_size_hex = db.query(func.sum(func.length(models.FileChunk.encrypted_data))).filter(
        models.FileChunk.secret_id == chunk.secret_id
    ).scalar() or 0

    current_total_bytes = total_stored_size_hex / 2
    new_chunk_size = len(chunk.encrypted_data) / 2

    if (current_total_bytes + new_chunk_size) > config.MAX_TOTAL_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large (max {config.MAX_TOTAL_FILE_SIZE // (1024 * 1024)}MB)")

    new_chunk = models.FileChunk(
        secret_id=chunk.secret_id,
        chunk_index=chunk.chunk_index,
        iv=chunk.iv,
        encrypted_data=chunk.encrypted_data
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
# row's full encrypted_data: at MAX_TOTAL_FILE_SIZE and hex encoding, one
# unauthenticated-by-rate-limit request materialized ~100 MB of strings, again
# through Pydantic, against a 500 MB worker restart threshold. No client ever
# called it — fileChunks.js fetches chunks one at a time by index, below.


@router.get("/secrets/{secret_id}/chunks/{chunk_index}", response_model=schemas.FileChunkResponse)
@limiter.limit("240/minute")
def get_chunk(request: Request, secret_id: int, chunk_index: int,
              current_user: models.User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    """Download a single encrypted chunk by index."""
    _check_secret_access(secret_id, current_user.address, db)

    chunk = db.query(models.FileChunk).filter(
        models.FileChunk.secret_id == secret_id,
        models.FileChunk.chunk_index == chunk_index
    ).first()

    if not chunk:
        raise HTTPException(status_code=404, detail=f"Chunk {chunk_index} not found")

    return chunk
