from fastapi import APIRouter, Depends, HTTPException, Query, Request
from dependencies import limiter
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
import models, schemas
from database import get_db
from dependencies import get_current_user
from security.crypto_validation import LEGACY_MIN_KEY_LEN
from security.usernames import InvalidUsername, normalize_username, username_taken

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

# NOTE: a free-form `PUT /users/me/public-key` setter used to live here. It was
# unused by any client and let an authenticated session change its ML-KEM key
# without a signature — undermining the login-time key binding (M-2) and lacking
# input validation (M-5). Removed: the encryption key is set only at login, where
# the identity's signature now covers it (see auth._login_message).

@router.put("/{address}", response_model=schemas.UserResponse)
def update_user(address: str, user_update: schemas.UserUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.address.lower() != address.lower():
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
        
    user = current_user
    
    if user_update.username is not None:
        try:
            new_username = normalize_username(user_update.username)
        except InvalidUsername as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Uniqueness is case-insensitive: the directory must not hold both
        # "alice" and "Alice" as separate identities.
        if username_taken(db, new_username, exclude_address=current_user.address):
            raise HTTPException(
                status_code=409,
                detail=f"Username '{new_username}' is already taken."
            )
        user.username = new_username
        
    db.commit()
    db.refresh(user)
    return user

# Minimum length for a directory substring search — avoids dumping the whole
# user directory via a 1-char `LIKE %x%` (anti-enumeration).
MIN_SEARCH_LEN = 2

@router.get("/{address}", response_model=schemas.UserResponse)
def get_user(address: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.address == address.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("", response_model=List[schemas.UserResponse])
@limiter.limit("30/minute")
def list_users(
    request: Request,
    search: str = None,
    only_pqc: bool = False,
    # Bounded at BOTH ends by FastAPI. The ceiling used to be clamped in the
    # body while the floor was unchecked, so `?limit=-1` reached PostgreSQL as
    # `LIMIT -1` — which is a hard error, i.e. a 500 on a trivial query string.
    limit: int = Query(5, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(models.User)

    if search is not None:
        term = search.strip()
        # Reject too-short substring searches to limit directory enumeration.
        if len(term) < MIN_SEARCH_LEN:
            return []
        # ilike: LIKE is case-insensitive on SQLite but case-sensitive on
        # Postgres — the directory search must match regardless of case.
        search_pattern = f"%{term.lower()}%"
        query = query.filter(
            (models.User.address.ilike(search_pattern)) |
            (models.User.username.ilike(search_pattern))
        )

    if only_pqc:
        # Messenger requires an ML-KEM encryption key. Filtered in SQL so paging
        # stays correct; the floor (rather than the exact 2368-char length) keeps
        # legacy accounts whose keys predate strict validation visible, matching
        # is_usable_encryption_key's non-strict behaviour used by the endpoints
        # that actually gate on capability.
        query = query.filter(
            func.length(models.User.encryption_public_key) >= LEGACY_MIN_KEY_LEN
        )

    return query.limit(limit).offset(offset).all()

class UserResolveRequest(schemas.BaseModel):
    address: str

@router.post("/resolve", response_model=schemas.UserResponse)
@limiter.limit("30/minute")
def resolve_user(request: Request, req: UserResolveRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Exact-match resolve of a user by their identity public key. Auth-gated.
    # Addresses are stored lowercased, so normalize the query (matches get_user).
    user = db.query(models.User).filter(models.User.address == req.address.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
