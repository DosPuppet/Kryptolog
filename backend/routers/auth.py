from fastapi import APIRouter, Depends, HTTPException, status, Request
from dependencies import limiter
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import models, schemas, auth
from database import get_db

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.get("/nonce/{address}")
@limiter.limit("10/minute")
def get_nonce(request: Request, address: str, db: Session = Depends(get_db)):
    # Cleanup expired nonces first (lazy cleanup)
    now = datetime.now(timezone.utc)
    db.query(models.Nonce).filter(models.Nonce.expires_at <= now).delete()
    
    nonce_val = auth.generate_nonce()
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    
    # Upsert logic
    new_nonce = models.Nonce(address=address.lower(), nonce=nonce_val, expires_at=expires)
    db.merge(new_nonce) # Updates if exists
    db.commit()
    
    return {"nonce": nonce_val}

@router.post("/login", response_model=schemas.Token)
@limiter.limit("5/minute")
def login(request: Request, login_req: schemas.LoginRequest, db: Session = Depends(get_db)):
    address = login_req.address.lower()
    
    # Fetch nonce from DB
    nonce_entry = db.query(models.Nonce).filter(models.Nonce.address == address).first()
    
    if not nonce_entry:
        raise HTTPException(status_code=400, detail="Nonce not found. Request a nonce first.")
        
    # Check expiry
    if nonce_entry.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        db.delete(nonce_entry)
        db.commit()
        raise HTTPException(status_code=400, detail="Nonce expired.")
    
    if login_req.nonce != nonce_entry.nonce:
         raise HTTPException(status_code=400, detail="Invalid nonce.")

    if not auth.verify_signature(address, login_req.nonce, login_req.signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Cleanup nonce (Anti-replay)
    db.delete(nonce_entry)
    db.commit()
    
    # Find or create user
    user = db.query(models.User).filter(models.User.address == address).first()
    if not user:
        # Default username logic: Use provided username OR first 7 chars of address
        default_username = login_req.username if login_req.username else address[:7]
        # Check username uniqueness
        existing = db.query(models.User).filter(models.User.username == default_username).first()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Username '{default_username}' is already taken. Please choose a different one."
            )
        user = models.User(
            address=address, 
            encryption_public_key=login_req.encryption_public_key,
            username=default_username
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    elif login_req.encryption_public_key and user.encryption_public_key != login_req.encryption_public_key:
        # Update key if it changed or wasn't set
        user.encryption_public_key = login_req.encryption_public_key
        db.commit()
        db.refresh(user)
    else:
        # Ensure we refresh even if no changes to get latest state
        db.refresh(user)
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.address}, expires_delta=access_token_expires
    )
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token signing failed. PQC service may be unavailable."
        )
    return {"access_token": access_token, "token_type": "bearer", "user": user}
