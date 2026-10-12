import threading
from unittest.mock import MagicMock, patch

import pytest
from conftest import auth_header

import utils.push
from models import PushSubscription
from routers.notifications import MAX_SUBSCRIPTIONS_PER_USER
from utils.push import PUSH_TIMEOUT_SECONDS, drain_pushes, notify_user_push, schedule_pushes


@pytest.fixture(autouse=True)
def _allow_placeholder_endpoints():
    """These tests use non-resolvable placeholder hostnames.

    The SSRF guard (KRY-002) would correctly reject them, so stub only the DNS
    step — the URL parsing/scheme/port rules still run for real. The guard's
    own behaviour is covered directly in test_ssrf_guard.py.
    """
    with patch("security.url_guard.resolve_safe_addresses", return_value=["93.184.216.34"]):
        yield


def test_push_subscription_registration(client, db_session, user1):
    token, current_user = user1
    auth_headers = {"Authorization": f"Bearer {token}"}

    sub_data = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/fake-endpoint",
        "p256dh": "fake-p256dh",
        "auth": "fake-auth",
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
        auth="auth",
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
        auth="auth",
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
        db_sub = (
            db_session.query(PushSubscription).filter_by(endpoint="https://gone.endpoint").first()
        )
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
        db_session.add(
            PushSubscription(
                user_address=address,
                endpoint=endpoint,
                p256dh="p256",
                auth="auth",
            )
        )
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

    def test_the_sender_does_not_wait_for_the_recipients_pushes(
        self, client, db_session, user1, user2
    ):
        """Audit 2026-09-23 M-1: a DM used to wait for every one of the
        recipient's pushes, each up to PUSH_TIMEOUT_SECONDS, on hosts the
        RECIPIENT chose. Here the push host never answers until released; the
        sender's request must come back anyway, and the send must happen on a
        push worker, not on whatever thread served the request."""
        _, recipient = user1
        sender_token, _ = user2
        self._subscribe(db_session, recipient["address"], "https://stalls.endpoint")

        release = threading.Event()
        send_threads = []

        def _stall(*args, **kwargs):
            send_threads.append(threading.current_thread().name)
            release.wait(timeout=30)
            return MagicMock()

        with patch("utils.push.webpush", side_effect=_stall):
            resp = client.post(
                "/messages",
                json={"recipient_address": recipient["address"], "content": "{}"},
                headers=auth_header(sender_token),
            )
            assert resp.status_code == 200, resp.text
            assert not release.is_set()  # answered while the push still hangs
            release.set()
            assert drain_pushes(timeout=10)

        assert send_threads and all(name.startswith("push") for name in send_threads)

    def test_a_full_queue_drops_pushes_instead_of_waiting(self, db_session, user1, monkeypatch):
        """A backlog must never become backpressure on whoever is sending."""
        _, current_user = user1
        self._subscribe(db_session, current_user["address"], "https://busy.endpoint")
        monkeypatch.setattr(utils.push, "_slots", threading.BoundedSemaphore(1))

        release = threading.Event()
        calls = []

        def _stall(*args, **kwargs):
            calls.append(1)
            release.wait(timeout=30)
            return MagicMock()

        with patch("utils.push.webpush", side_effect=_stall):
            schedule_pushes([(current_user["address"], "T", "B", None)] * 3)
            release.set()
            assert drain_pushes(timeout=10)
        assert len(calls) == 1


class TestSubscriptions:
    def _register(self, client, token, n):
        return client.post(
            "/notifications/subscribe",
            json={"endpoint": f"https://push.example/{n}", "p256dh": "p", "auth": "a"},
            headers=auth_header(token),
        )

    def test_an_account_holds_at_most_ten_and_the_oldest_go(
        self, client, db_session, user1, user2, monkeypatch
    ):
        """Audit 2026-09-23 M-1: subscriptions were uncapped, so one account
        could make every message sent to it cost hundreds of outbound requests."""
        from dependencies import limiter

        monkeypatch.setattr(limiter, "enabled", False)  # twelve registrations
        token, me = user1
        other_token, _ = user2
        self._register(client, other_token, "other")
        for n in range(MAX_SUBSCRIPTIONS_PER_USER + 2):
            assert self._register(client, token, n).status_code == 200

        mine = sorted(
            s.endpoint
            for s in db_session.query(PushSubscription).filter_by(user_address=me["address"])
        )
        assert mine == sorted(
            f"https://push.example/{n}" for n in range(2, MAX_SUBSCRIPTIONS_PER_USER + 2)
        )
        # Somebody else's are not part of anyone's count.
        assert (
            db_session.query(PushSubscription)
            .filter_by(endpoint="https://push.example/other")
            .count()
            == 1
        )

    def test_unsubscribe_takes_the_endpoint_in_the_body(self, client, db_session, user1):
        """Audit 2026-09-11 F-8: an endpoint is a capability URL, and query
        strings end up in access logs."""
        token, me = user1
        self._register(client, token, "x")
        endpoint = "https://push.example/x"

        in_query = client.post(
            f"/notifications/unsubscribe?endpoint={endpoint}", headers=auth_header(token)
        )
        assert in_query.status_code == 422
        resp = client.post(
            "/notifications/unsubscribe", json={"endpoint": endpoint}, headers=auth_header(token)
        )
        assert resp.status_code == 200
        assert db_session.query(PushSubscription).filter_by(user_address=me["address"]).count() == 0
