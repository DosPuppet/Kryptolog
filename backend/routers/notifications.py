from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session
from typing import List
import models, schemas
from database import get_db
from dependencies import get_current_user

router = APIRouter(
    prefix="/notifications",
    tags=["notifications"]
)

@router.post("/subscribe", response_model=schemas.PushSubscriptionResponse)
@limiter.limit("10/minute")
def subscribe(request: Request, sub: schemas.PushSubscriptionCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check if subscription already exists for this endpoint
    existing = db.query(models.PushSubscription).filter(
        models.PushSubscription.endpoint == sub.endpoint
    ).first()
    
    if existing:
        # Update user if it changed (e.g. login with different account on same browser)
        existing.user_address = current_user.address
        existing.p256dh = sub.p256dh
        existing.auth = sub.auth
        db.commit()
        db.refresh(existing)
        return existing

    new_sub = models.PushSubscription(
        user_address=current_user.address,
        endpoint=sub.endpoint,
        p256dh=sub.p256dh,
        auth=sub.auth
    )
    db.add(new_sub)
    db.commit()
    db.refresh(new_sub)
    return new_sub

@router.post("/unsubscribe")
@limiter.limit("10/minute")
def unsubscribe(request: Request, endpoint: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == current_user.address,
        models.PushSubscription.endpoint == endpoint
    ).delete()
    db.commit()
    return {"status": "ok"}

@router.post("/test")
@limiter.limit("5/minute")
def test_push(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Send a test push notification to the current user."""
    from utils.push import notify_user_push
    
    subs_count = db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == current_user.address
    ).count()
    
    if subs_count == 0:
        return {"status": "no_subscriptions", "message": "No push subscriptions found for your account. Enable push notifications first."}
    
    notify_user_push(
        db,
        current_user.address,
        "🔔 Safelog Test",
        "Push notifications are working!",
        {"type": "test"}
    )
    return {"status": "sent", "subscriptions": subs_count}
