from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db
from dependencies import get_current_user, limiter
from security import quota
from security.url_guard import UnsafeUrlError, validate_push_endpoint
from utils.push import schedule_push

router = APIRouter(prefix="/notifications", tags=["notifications"])

# Subscriptions one account may hold (audit 2026-09-23 M-1). Every push to an
# account costs one outbound request per subscription, to hosts the account
# chose; with no cap, a few hundred registrations on a host that stalls made
# every message TO that account cost minutes of server time. Ten covers a
# person's browsers and devices. The oldest is evicted rather than the new one
# refused: a subscription is not a credential, losing a stale one costs nothing,
# and refusing would strand the browser the user is actually holding.
MAX_SUBSCRIPTIONS_PER_USER = 10


@router.post("/subscribe", response_model=schemas.PushSubscriptionResponse)
@limiter.limit("10/minute")
def subscribe(
    request: Request,
    sub: schemas.PushSubscriptionCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register this browser for push notifications.

    The endpoint must be a public HTTPS host (SSRF guard). An account keeps at
    most ten subscriptions; registering an eleventh drops the oldest.
    """
    # Reject SSRF-capable endpoints at the door (KRY-002). The sender
    # re-validates too, since stored rows predate this check and DNS can move.
    try:
        validate_push_endpoint(sub.endpoint)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid push endpoint: {exc}")

    # Only ever look at *this* user's own subscriptions. Matching on endpoint
    # alone let any authenticated caller re-point somebody else's subscription
    # row at themselves and receive that user's notifications (IDOR).
    existing = (
        db.query(models.PushSubscription)
        .filter(
            models.PushSubscription.endpoint == sub.endpoint,
            models.PushSubscription.user_address == current_user.address,
        )
        .first()
    )

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
        models.PushSubscription.user_address != current_user.address,
    ).delete(synchronize_session=False)

    # Serialized per account, so two concurrent registrations cannot both
    # count room for one more (the quota module's lock, for the same reason).
    quota.lock_owner(db, current_user.address)
    new_sub = models.PushSubscription(
        user_address=current_user.address, endpoint=sub.endpoint, p256dh=sub.p256dh, auth=sub.auth
    )
    db.add(new_sub)
    db.flush()
    keep = (
        db.query(models.PushSubscription.id)
        .filter(models.PushSubscription.user_address == current_user.address)
        .order_by(models.PushSubscription.id.desc())
        .limit(MAX_SUBSCRIPTIONS_PER_USER)
    )
    db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == current_user.address,
        models.PushSubscription.id.not_in(keep.scalar_subquery()),
    ).delete(synchronize_session=False)
    db.commit()
    db.refresh(new_sub)
    return new_sub


@router.post("/unsubscribe")
@limiter.limit("10/minute")
def unsubscribe(
    request: Request,
    body: schemas.PushUnsubscribe,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove one of the caller's push subscriptions. The endpoint travels in the
    body: it is a capability URL, and query strings end up in logs.
    """
    db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == current_user.address,
        models.PushSubscription.endpoint == body.endpoint,
    ).delete()
    db.commit()
    return {"status": "ok"}


@router.post("/test")
@limiter.limit("5/minute")
def test_push(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Queue a test push notification to the current user."""
    subs_count = (
        db.query(models.PushSubscription)
        .filter(models.PushSubscription.user_address == current_user.address)
        .count()
    )

    if subs_count == 0:
        return {
            "status": "no_subscriptions",
            "message": "No push subscriptions found for your account. Enable push notifications first.",
        }

    # Queued like every other push (audit 2026-09-23 M-1): sent inline, this
    # was up to ten slow hosts' worth of a server thread per click.
    schedule_push(
        current_user.address,
        "🔔 Kryptolog Test",
        "Push notifications are working!",
        {"type": "test"},
    )
    return {"status": "queued", "subscriptions": subs_count}
