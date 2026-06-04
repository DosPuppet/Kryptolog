from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
import models, schemas
from database import get_db
from dependencies import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.put("/me/public-key")
def update_public_key(public_key: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = current_user
    user.encryption_public_key = public_key
    db.commit()
    return {"status": "ok"}

@router.put("/{address}", response_model=schemas.UserResponse)
def update_user(address: str, user_update: schemas.UserUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.address.lower() != address.lower():
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
        
    user = current_user
    
    if user_update.username is not None:
        # Check username uniqueness (case-insensitive)
        existing = db.query(models.User).filter(
            models.User.username == user_update.username,
            models.User.address != current_user.address
        ).first()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Username '{user_update.username}' is already taken."
            )
        user.username = user_update.username
        
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
def list_users(request: Request, search: str = None, only_pqc: bool = False, limit: int = 5, offset: int = 0, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    if limit > 100:
        limit = 100
    query = db.query(models.User)

    if search is not None:
        term = search.strip()
        # Reject too-short substring searches to limit directory enumeration.
        if len(term) < MIN_SEARCH_LEN:
            return []
        search_pattern = f"%{term.lower()}%"
        query = query.filter(
            (models.User.address.like(search_pattern)) |
            (models.User.username.like(search_pattern))
        )

    if only_pqc:
        # PQC keys (Kyber/Dilithium) are significantly larger than ETH public keys (x25519/SECP256K1)
        # Kyber768 PK is ~1088 bytes (hex ~2176), SECP256K1 is ~33 bytes (hex ~66).
        query = query.filter(func.length(models.User.encryption_public_key) > 500)

    return query.limit(limit).offset(offset).all()

class UserResolveRequest(schemas.BaseModel):
    address: str

@router.post("/resolve", response_model=schemas.UserResponse)
@limiter.limit("30/minute")
def resolve_user(request: Request, req: UserResolveRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Exact-match resolve of a user by address (Eth or PQC). Auth-gated.
    user = db.query(models.User).filter(models.User.address == req.address).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
