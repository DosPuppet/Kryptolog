from fastapi import APIRouter, Depends, HTTPException, Request
from dependencies import limiter
from sqlalchemy.orm import Session
import models, schemas
from database import get_db
from dependencies import get_current_user
from security.url_guard import UnsafeUrlError, validate_push_endpoint

router = APIRouter(
    prefix="/notifications",
    tags=["notifications"]
)

@router.post("/subscribe", response_model=schemas.PushSubscriptionResponse)
@limiter.limit("10/minute")
def subscribe(request: Request, sub: schemas.PushSubscriptionCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Reject SSRF-capable endpoints at the door (KRY-002). The sender
    # re-validates too, since stored rows predate this check and DNS can move.
    try:
        validate_push_endpoint(sub.endpoint)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid push endpoint: {exc}")

    # Only ever look at *this* user's own subscriptions. Matching on endpoint
    # alone let any authenticated caller re-point somebody else's subscription
    # row at themselves and receive that user's notifications (IDOR).
    existing = db.query(models.PushSubscription).filter(
        models.PushSubscription.endpoint == sub.endpoint,
        models.PushSubscription.user_address == current_user.address
    ).first()

    if existing:
        # Same browser, same account — refresh the rotating keys.
        existing.p256dh = sub.p256dh
        existing.auth = sub.auth
        db.commit()
        db.refresh(existing)
        return existing

    # A browser endpoint is unique per (browser, push service) and is reissued
    # on account switch, but if this exact endpoint is still registered to a
    # different account, that registration is stale — the endpoint's current
    # owner is whoever holds the browser now. Drop the stale row instead of
    # reassigning it, so no history carries across the account boundary.
    db.query(models.PushSubscription).filter(
        models.PushSubscription.endpoint == sub.endpoint,
        models.PushSubscription.user_address != current_user.address
    ).delete(synchronize_session=False)

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
        "🔔 Kryptolog Test",
        "Push notifications are working!",
        {"type": "test"}
    )
    return {"status": "sent", "subscriptions": subs_count}
