from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from typing import List
from datetime import datetime, timezone, timedelta
import models, schemas
from database import get_db
from dependencies import get_current_user
from websocket_manager import manager
from utils.push import notify_user_push_async
from security import authorization
import config

router = APIRouter(tags=["secrets"])

# Secrets
@router.post("/secrets", response_model=schemas.SecretResponse)
@limiter.limit("20/minute")
def create_secret(request: Request, secret: schemas.SecretCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # 1. Create Secret (Content)
    new_secret = models.Secret(
        owner_address=current_user.address,
        name=secret.name,
        type=secret.type,
        encrypted_data=secret.encrypted_data
    )
    db.add(new_secret)
    db.flush() # Flush to get ID

    # 2. Create AccessGrant for Owner (Key)
    owner_grant = models.AccessGrant(
        secret_id=new_secret.id,
        grantee_address=current_user.address,
        encrypted_key=secret.encrypted_key
    )
    db.add(owner_grant)
    db.commit()
    db.refresh(new_secret)
    
    # Manually attach encrypted_key for response
    new_secret.encrypted_key = secret.encrypted_key
    return new_secret

@router.get("/secrets", response_model=List[schemas.SecretResponse])
@limiter.limit("60/minute")
def get_secrets(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    results = db.query(models.Secret, models.AccessGrant.encrypted_key)\
        .options(joinedload(models.Secret.owner))\
        .join(models.AccessGrant, (models.AccessGrant.secret_id == models.Secret.id) & (models.AccessGrant.grantee_address == current_user.address))\
        .outerjoin(models.MultisigWorkflow, models.MultisigWorkflow.secret_id == models.Secret.id)\
        .filter(models.Secret.owner_address == current_user.address)\
        .filter(models.MultisigWorkflow.id == None)\
        .all()

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
    
    # Check ownership
    if secret.owner_address != current_user.address:
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

    if secret.owner_address != current_user.address:
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
    
    # Verify ownership
    if secret.owner_address != current_user.address:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Prevent sharing a workflow-managed secret directly
    workflow = db.query(models.MultisigWorkflow).filter(models.MultisigWorkflow.secret_id == grant.secret_id).first()
    if workflow:
        raise HTTPException(status_code=400, detail="Cannot manually share a secret managed by a Multisig Workflow")

    # Verify grantee exists
    grantee = db.query(models.User).filter(models.User.address == grant.grantee_address.lower()).first()
    if not grantee:
        raise HTTPException(status_code=404, detail="Grantee not found")

    # Check if already shared
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

    # Real-time Update
    await manager.send_personal_message({
        "type": "SECRET_SHARED",
        "data": {
            "secret_id": new_grant.secret_id,
            "sender": current_user.address,
            "grant_id": new_grant.id
        }
    }, grant.grantee_address.lower())

    # Push Notification
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
    
    # Check permissions: Caller must be Secret Owner OR Grantee
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
def get_secret_access(request: Request, secret_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")
        
    if secret.owner_address != current_user.address:
         raise HTTPException(status_code=403, detail="Not authorized")
         
    # Bulk-delete expired grants in one SQL roundtrip
    now = datetime.now(timezone.utc)
    db.query(models.AccessGrant).filter(
        models.AccessGrant.secret_id == secret_id,
        models.AccessGrant.expires_at != None,
        models.AccessGrant.expires_at <= now
    ).delete(synchronize_session="fetch")
    db.commit()

    return db.query(models.AccessGrant).filter(
        models.AccessGrant.secret_id == secret_id
    ).all()

@router.get("/secrets/shared-with-me", response_model=List[schemas.AccessGrantResponse])
@limiter.limit("60/minute")
def get_shared_secrets(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)

    # Bulk-delete expired grants for this user
    db.query(models.AccessGrant).filter(
        models.AccessGrant.grantee_address == current_user.address,
        models.AccessGrant.expires_at != None,
        models.AccessGrant.expires_at <= now
    ).delete(synchronize_session="fetch")
    db.commit()

    return db.query(models.AccessGrant).options(
        joinedload(models.AccessGrant.secret).joinedload(models.Secret.owner),
        joinedload(models.AccessGrant.grantee)
    ).join(models.Secret)\
    .outerjoin(models.MultisigWorkflow, models.MultisigWorkflow.secret_id == models.Secret.id)\
    .filter(
        models.AccessGrant.grantee_address == current_user.address,
        models.Secret.owner_address != current_user.address,
        models.MultisigWorkflow.id == None
    ).all()

# Documents (Keep in secrets router as per plan implication or separate if desired. "Move secrets and sharing endpoints here." Documents are kind of secrets.)
@router.post("/documents", response_model=schemas.DocumentResponse)
def create_document(doc: schemas.DocumentCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_doc = models.Document(
        owner_address=current_user.address,
        name=doc.name,
        content_hash=doc.content_hash,
        signature=doc.signature
    )
    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)
    return new_doc

@router.get("/documents", response_model=List[schemas.DocumentResponse])
def get_documents(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(models.Document).filter(models.Document.owner_address == current_user.address).all()


# --- File Chunks ---

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
        raise HTTPException(status_code=413, detail="File too large (Max 50MB)")

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
