import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, wait

from pywebpush import WebPushException, webpush

from security.url_guard import UnsafeUrlError, build_guarded_session

logger = logging.getLogger(__name__)


def display_name(user) -> str:
    """How to name a user in a notification the server composes itself.

    Falls back to a truncated address because the username is optional. The
    length is a display choice, not a security one, but it was written out six
    times, so changing it meant finding all six.
    """
    return user.username or f"{user.address[:8]}..."


# Hard ceiling on how long one push may take (connect + read, seconds).
#
# `requests` — and therefore pywebpush — defaults to NO timeout. The endpoint is
# attacker-controlled (it only has to be a public HTTPS host to clear the SSRF
# guard), so a host that accepts the connection and never answers would park
# this call forever. Combined with the threadpool offload below that used to
# mean an indefinitely wedged event loop; without a timeout it would still leak
# a worker thread per push.
PUSH_TIMEOUT_SECONDS = 10


def _get_vapid_config():
    """Read VAPID keys at call time, stripping any accidental quotes."""
    private_key = (os.getenv("VAPID_PRIVATE_KEY") or "").strip().strip('"').strip("'")
    public_key = (os.getenv("VAPID_PUBLIC_KEY") or "").strip().strip('"').strip("'")
    subject = (
        (os.getenv("VAPID_SUBJECT") or "mailto:admin@kryptolog.io").strip().strip('"').strip("'")
    )
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
                "keys": {"p256dh": subscription_info["p256dh"], "auth": subscription_info["auth"]},
            },
            data=json.dumps(data),
            vapid_private_key=private_key,
            vapid_claims={"sub": subject},
            requests_session=session,
            timeout=PUSH_TIMEOUT_SECONDS,
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

    BLOCKING: this does DNS resolution, a presence lookup and one outbound
    HTTPS request per subscription. It is safe to call directly from a sync
    (`def`) endpoint — Starlette already runs those in a worker thread — but an
    async (`async def`) endpoint MUST use `notify_user_push_async` instead, or
    the whole event loop (every request and every WebSocket on this worker)
    stalls for the duration.
    """
    import models
    from websocket_manager import manager

    target_addr = user_address.lower()

    # If user is actively viewing the app (focused WebSocket), skip push notification
    if manager.is_focused(target_addr):
        logger.info(f"Skipping push for {target_addr[:10]}... (app focused)")
        return
    subs = (
        db.query(models.PushSubscription)
        .filter(models.PushSubscription.user_address == target_addr)
        .all()
    )

    if not subs:
        return

    payload = {"title": title, "body": body, "data": data or {}}

    for sub in subs:
        res = send_push_notification(
            {"endpoint": sub.endpoint, "p256dh": sub.p256dh, "auth": sub.auth}, payload
        )

        if res == "GONE":
            # Auto-cleanup stale subscriptions
            db.delete(sub)
            db.commit()
        elif res == "UNSAFE":
            # A stored endpoint that fails the SSRF guard can never be
            # delivered to, so drop it rather than re-attempting on every
            # notification (KRY-002).
            logger.warning("Dropping push subscription %s with unsafe endpoint", sub.id)
            db.delete(sub)
            db.commit()


# ── Delivery off the request path (audit 2026-09-23 M-1) ─────────────────
#
# Every push used to be sent inside the request that caused it: a DM, a share,
# a group post waited for all of the recipient's pushes, serially, each bounded
# by PUSH_TIMEOUT_SECONDS. The endpoints are chosen by the recipient, so a user
# who registered a few hundred subscriptions on a host that accepts and then
# stalls made everyone who wrote to them wait N × 10 s, holding a thread of the
# pool that serves every sync route — a handful of such sends and the worker
# stopped answering.
#
# Now a send is queued and the request returns. Pushes run on their OWN small
# pool, so a slow host can occupy at most PUSH_WORKERS threads, never the
# server's; each job opens its own Session, since the request's is closed by
# the time it runs. The queue is bounded and drops rather than waits when full:
# a push is a hint that something arrived, the data itself is in the database,
# and a backlog must never become backpressure on the people sending messages.
# Combined with the per-account subscription cap, one recipient now costs at
# most MAX_SUBSCRIPTIONS_PER_USER × PUSH_TIMEOUT_SECONDS of ONE push worker.
PUSH_WORKERS = 4
PUSH_QUEUE_MAX = 1000

_executor = ThreadPoolExecutor(max_workers=PUSH_WORKERS, thread_name_prefix="push")
_slots = threading.BoundedSemaphore(PUSH_QUEUE_MAX)
_pending: set = set()
_pending_lock = threading.Lock()


def _run_push(user_address, title, body, data):
    from database import SessionLocal

    db = SessionLocal()
    try:
        notify_user_push(db, user_address, title, body, data)
    except Exception:
        logger.exception("Push job for %s... failed", user_address[:10])
    finally:
        db.close()


def _done(future):
    _slots.release()
    with _pending_lock:
        _pending.discard(future)


def schedule_pushes(notifications) -> None:
    """Queue (user_address, title, body, data) pushes and return at once."""
    for user_address, title, body, data in notifications:
        if not _slots.acquire(blocking=False):
            logger.warning("Push queue full; dropping a push to %s...", user_address[:10])
            continue
        future = _executor.submit(_run_push, user_address, title, body, data)
        with _pending_lock:
            _pending.add(future)
        future.add_done_callback(_done)


def schedule_push(user_address, title, body, data=None) -> None:
    schedule_pushes([(user_address, title, body, data)])


def drain_pushes(timeout: float = 30.0) -> bool:
    """Wait for every queued push to finish. For shutdown and tests: a test
    must not leave a job writing to a schema the next test drops."""
    with _pending_lock:
        pending = list(_pending)
    done, not_done = wait(pending, timeout=timeout)
    return not not_done
