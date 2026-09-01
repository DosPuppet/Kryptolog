import asyncio
import threading

import pytest
from models import PushSubscription
from utils.push import PUSH_TIMEOUT_SECONDS, notify_user_push, notify_user_push_async
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def _allow_placeholder_endpoints():
    """These tests use non-resolvable placeholder hostnames.

    The SSRF guard (KRY-002) would correctly reject them, so stub only the DNS
    step — the URL parsing/scheme/port rules still run for real. The guard's
    own behaviour is covered directly in test_ssrf_guard.py.
    """
    with patch(
        "security.url_guard.resolve_safe_addresses", return_value=["93.184.216.34"]
    ):
        yield

def test_push_subscription_registration(client, db_session, user1):
    token, current_user = user1
    auth_headers = {"Authorization": f"Bearer {token}"}

    sub_data = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/fake-endpoint",
        "p256dh": "fake-p256dh",
        "auth": "fake-auth"
    }

    # Test Subscribe
    response = client.post("/notifications/subscribe", json=sub_data, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["endpoint"] == sub_data["endpoint"]
    assert data["user_address"] == current_user["address"]

    # Verify in DB
    db_sub = db_session.query(PushSubscription).filter_by(endpoint=sub_data["endpoint"]).first()
    assert db_sub is not None
    assert db_sub.user_address == current_user["address"]

def test_notify_user_push_logic(db_session, user1):
    token, current_user = user1
    
    # Add a subscription
    sub = PushSubscription(
        user_address=current_user["address"],
        endpoint="https://fake.endpoint",
        p256dh="p256",
        auth="auth"
    )
    db_session.add(sub)
    db_session.commit()

    # Mock webpush to avoid external calls
    with patch("utils.push.webpush") as mock_webpush:
        notify_user_push(db_session, current_user["address"], "Title", "Body", {"key": "val"})
        
        # Verify it was called
        assert mock_webpush.called
        args, kwargs = mock_webpush.call_args
        assert kwargs["subscription_info"]["endpoint"] == "https://fake.endpoint"
        assert "Title" in kwargs["data"]
        assert "Body" in kwargs["data"]

def test_push_cleanup_on_gone(db_session, user1):
    token, current_user = user1
    
    # Add a subscription
    sub = PushSubscription(
        user_address=current_user["address"],
        endpoint="https://gone.endpoint",
        p256dh="p256",
        auth="auth"
    )
    db_session.add(sub)
    db_session.commit()

    # Mock WebPushException with 410 Gone
    from pywebpush import WebPushException
    mock_response = MagicMock()
    mock_response.status_code = 410
    
    with patch("utils.push.webpush", side_effect=WebPushException("Gone", response=mock_response)):
        notify_user_push(db_session, current_user["address"], "Title", "Body")

        # Verify subscription was deleted
        db_sub = db_session.query(PushSubscription).filter_by(endpoint="https://gone.endpoint").first()
        assert db_sub is None


class TestPushDoesNotStallTheEventLoop:
    """A push must never be able to hold the server hostage.

    `requests` (and therefore pywebpush) defaults to NO timeout, and the
    endpoint is attacker-controlled — it only has to be a public HTTPS host to
    clear the SSRF guard. Combined with the old inline call from `async def`
    endpoints, a host that accepted the connection and never replied would
    block the event loop — every request and every WebSocket on the worker —
    indefinitely. Two independent guarantees keep that shut.
    """

    def _subscribe(self, db_session, address, endpoint):
        db_session.add(PushSubscription(
            user_address=address, endpoint=endpoint, p256dh="p256", auth="auth",
        ))
        db_session.commit()

    def test_webpush_is_called_with_a_timeout(self, db_session, user1):
        """Guarantee 1: a hung endpoint is abandoned, not waited on forever."""
        _, current_user = user1
        self._subscribe(db_session, current_user["address"], "https://slow.endpoint")

        with patch("utils.push.webpush") as mock_webpush:
            notify_user_push(db_session, current_user["address"], "T", "B")

        _, kwargs = mock_webpush.call_args
        assert kwargs["timeout"] == PUSH_TIMEOUT_SECONDS
        assert PUSH_TIMEOUT_SECONDS > 0

    def test_async_wrapper_runs_the_blocking_send_off_the_loop(self, db_session, user1):
        """Guarantee 2: the blocking work happens on a worker thread.

        Asserted by identity of the thread the send runs on, not by timing —
        a timing test would be flaky and would not actually prove the loop was
        free.
        """
        _, current_user = user1
        self._subscribe(db_session, current_user["address"], "https://offloaded.endpoint")

        send_threads = []

        def _record(*args, **kwargs):
            send_threads.append(threading.current_thread().ident)
            return MagicMock()

        async def _run():
            loop_thread = threading.current_thread().ident
            with patch("utils.push.webpush", side_effect=_record):
                await notify_user_push_async(
                    db_session, current_user["address"], "T", "B",
                )
            return loop_thread

        loop_thread = asyncio.run(_run())

        assert send_threads, "webpush was never called"
        assert all(t != loop_thread for t in send_threads), (
            "the blocking push ran on the event-loop thread"
        )
