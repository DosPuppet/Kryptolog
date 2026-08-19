import os
import json
from pywebpush import webpush, WebPushException
import logging

from security.url_guard import UnsafeUrlError, build_guarded_session

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

    endpoint = subscription_info["endpoint"]

    # KRY-002: the endpoint is attacker-controlled, so it is re-validated at
    # send time and not only at subscribe time — rows predating the check, or
    # a host that has since been re-pointed at an internal address, must not
    # turn this into an SSRF primitive. The session refuses redirects and pins
    # the host to the addresses validated here.
    try:
        session = build_guarded_session(endpoint)
    except UnsafeUrlError as exc:
        logger.warning("Refusing push to unsafe endpoint: %s", exc)
        return "UNSAFE"

    try:
        webpush(
            subscription_info={
                "endpoint": endpoint,
                "keys": {
                    "p256dh": subscription_info["p256dh"],
                    "auth": subscription_info["auth"]
                }
            },
            data=json.dumps(data),
            vapid_private_key=private_key,
            vapid_claims={"sub": subject},
            requests_session=session,
        )
        logger.info(f"Push notification sent to {endpoint[:50]}...")
        return True
    except UnsafeUrlError as exc:
        # Raised from the pinned adapter if the host re-resolved mid-flight.
        logger.warning("Refusing push (rebinding check failed): %s", exc)
        return "UNSAFE"
    except WebPushException as ex:
        # If 410 Gone, the subscription is expired or revoked
        if ex.response is not None and ex.response.status_code == 410:
             return "GONE"
        logger.error(f"Push notification failed: {ex}")
        return False
    except Exception as e:
        logger.error(f"Unexpected push error: {e}")
        return False
    finally:
        try:
            session.close()
        except Exception:
            pass

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
        elif res == "UNSAFE":
            # A stored endpoint that fails the SSRF guard can never be
            # delivered to, so drop it rather than re-attempting on every
            # notification (KRY-002).
            logger.warning(
                "Dropping push subscription %s with unsafe endpoint", sub.id
            )
            db.delete(sub)
            db.commit()
