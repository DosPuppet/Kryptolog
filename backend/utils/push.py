import os
import json
from pywebpush import webpush, WebPushException
import logging

logger = logging.getLogger(__name__)

def _get_vapid_config():
    """Read VAPID keys at call time, stripping any accidental quotes."""
    private_key = (os.getenv("VAPID_PRIVATE_KEY") or "").strip().strip('"').strip("'")
    public_key = (os.getenv("VAPID_PUBLIC_KEY") or "").strip().strip('"').strip("'")
    subject = (os.getenv("VAPID_SUBJECT") or "mailto:admin@kryptolog.io").strip().strip('"').strip("'")
    return private_key, public_key, subject

def send_push_notification(subscription_info, data):
    """
    Send a push notification to a specific subscription.
    subscription_info: dict with {endpoint, p256dh, auth}
    data: dict payload
    """
    private_key, public_key, subject = _get_vapid_config()

    if not private_key or not public_key:
        logger.warning("Push Notifications: VAPID keys not configured. Skipping.")
        return False

    try:
        webpush(
            subscription_info={
                "endpoint": subscription_info["endpoint"],
                "keys": {
                    "p256dh": subscription_info["p256dh"],
                    "auth": subscription_info["auth"]
                }
            },
            data=json.dumps(data),
            vapid_private_key=private_key,
            vapid_claims={"sub": subject}
        )
        logger.info(f"Push notification sent to {subscription_info['endpoint'][:50]}...")
        return True
    except WebPushException as ex:
        # If 410 Gone, the subscription is expired or revoked
        if ex.response is not None and ex.response.status_code == 410:
             return "GONE"
        logger.error(f"Push notification failed: {ex}")
        return False
    except Exception as e:
        logger.error(f"Unexpected push error: {e}")
        return False

def notify_user_push(db, user_address, title, body, data=None):
    """
    Fetch all subscriptions for a user and send them a push.
    Skips sending if the user has an active WebSocket connection (app is open).
    """
    import models
    from websocket_manager import manager
    
    target_addr = user_address.lower()
    
    # If user is actively viewing the app (focused WebSocket), skip push notification
    if manager.is_focused(target_addr):
        logger.info(f"Skipping push for {target_addr[:10]}... (app focused)")
        return
    subs = db.query(models.PushSubscription).filter(
        models.PushSubscription.user_address == target_addr
    ).all()
    
    if not subs:
        return
        
    payload = {
        "title": title,
        "body": body,
        "data": data or {}
    }
    
    for sub in subs:
        res = send_push_notification({
            "endpoint": sub.endpoint,
            "p256dh": sub.p256dh,
            "auth": sub.auth
        }, payload)
        
        if res == "GONE":
            # Auto-cleanup stale subscriptions
            db.delete(sub)
            db.commit()
