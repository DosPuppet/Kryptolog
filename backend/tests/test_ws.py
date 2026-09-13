"""Tests for the WebSocket /ws endpoint hardening (audit M2):
Origin allowlist (CORS doesn't cover WS handshakes) + pre-auth timeout,
and the session lifetime of an already-open socket (audit 2026-09-11 M-1)."""

import time

import pytest
from conftest import auth_header
from starlette.websockets import WebSocketDisconnect

import models
import routers.messenger as messenger
from websocket_manager import manager


def test_ws_rejects_disallowed_origin(client, monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://allowed.example")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
            pass


def test_ws_rejects_missing_origin_when_allowlist_set(client, monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://allowed.example")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws"):  # no Origin header at all
            pass


def test_ws_allows_listed_origin_and_authenticates(client, user1, monkeypatch):
    token, _ = user1
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://testserver,http://localhost:5173")
    with client.websocket_connect("/ws", headers={"origin": "http://testserver"}) as ws:
        ws.send_json({"type": "AUTH", "token": token})
        # Connection stays open; a client control message is accepted without error.
        ws.send_json({"type": "APP_FOCUSED"})


def test_ws_no_allowlist_skips_origin_check(client, user1, monkeypatch):
    """With ALLOWED_ORIGINS unset (dev default), the Origin check is skipped so
    local development still works; auth is still required to do anything."""
    token, _ = user1
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    with client.websocket_connect("/ws", headers={"origin": "http://anything"}) as ws:
        ws.send_json({"type": "AUTH", "token": token})
        ws.send_json({"type": "APP_FOCUSED"})


def test_ws_closes_on_auth_timeout(client, monkeypatch):
    """An accepted socket that never authenticates is closed (not left lingering)."""
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)  # skip origin check
    monkeypatch.setattr(messenger, "WS_AUTH_TIMEOUT_SECONDS", 0.1)
    with client.websocket_connect("/ws") as ws:
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()  # server closes after the timeout; no AUTH was sent


def test_ws_rejects_bad_token(client, monkeypatch):
    """A connection from an allowed origin still needs a valid token."""
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://testserver")
    with client.websocket_connect("/ws", headers={"origin": "http://testserver"}) as ws:
        ws.send_json({"type": "AUTH", "token": "not-a-real-token"})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()  # server closes on invalid token


# ── A socket has to keep asking, not answer once (audit 2026-09-11 M-1) ──────
#
# The token used to be checked at the handshake and never again. After a
# `POST /auth/logout` the REST surface refused it instantly while the socket it
# had opened carried on delivering NEW_MESSAGE frames, and any socket outlived
# the JWT's own 30 minutes for as long as the tab stayed open (nginx is
# configured for a 24h read timeout).
#
# Two mechanisms, and neither covers the other: a revocation hangs the sockets
# up through the fan-out the moment it is written, and the periodic recheck
# catches what nobody publishes — expiry, and a revocation whose fan-out was
# lost. Each test below drives exactly one of them.


def _wait_until(predicate, timeout: float = 2.0) -> bool:
    """Poll the registry, bounded.

    The socket is served in the TestClient's portal thread, so neither "AUTH has
    landed" nor "the server hung up" is settled by anything the test thread
    does. Polling rather than blocking on `ws.receive_*` is deliberate: a
    receive that never arrives hangs the suite instead of failing it, and both
    of the gates below are exactly the case where a broken server sends
    nothing.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_revoking_sessions_hangs_up_an_already_open_socket(client, user1, monkeypatch):
    """'Revoke all sessions' is aimed at the tab the user no longer controls,
    which is the one this used to leave receiving everything in real time.

    The recheck is pushed out of reach first, so what this pins is the hangup
    being IMMEDIATE. Left at its default the test passes with close_address
    deleted — in 62 seconds, which is exactly the window an attacker holding
    the tab is being denied.
    """
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(messenger, "WS_REVALIDATE_SECONDS", 3600.0)
    token, user = user1

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "AUTH", "token": token})
        assert _wait_until(lambda: manager.is_connected(user["address"]))

        assert client.post("/auth/logout", headers=auth_header(token)).status_code == 200

        assert _wait_until(lambda: not manager.is_connected(user["address"])), (
            "the socket outlived the revocation"
        )
        # Told why before being hung up. The frame matters on its own: a worker
        # on the previous build fans it out without closing anything.
        assert ws.receive_json() == {"type": "SESSION_REVOKED"}
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_an_open_socket_notices_its_token_dying_without_being_told(
    client, user1, db_session, monkeypatch
):
    """The half that catches EXPIRY, which nothing publishes an event for.

    The revocation here is written straight to the row rather than through
    `POST /auth/logout` on purpose: that endpoint closes the socket itself, so
    going through it would pass with the recheck deleted.
    """
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(messenger, "WS_REVALIDATE_SECONDS", 0.1)
    token, user = user1

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "AUTH", "token": token})
        assert _wait_until(lambda: manager.is_connected(user["address"]))

        db_session.query(models.User).filter(models.User.address == user["address"]).update(
            {"token_version": 99}
        )
        db_session.commit()

        assert _wait_until(lambda: not manager.is_connected(user["address"])), (
            "the socket never re-asked whether its token was still good"
        )
        assert ws.receive_json() == {"type": "SESSION_REVOKED"}
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_the_recheck_re_admits_a_live_token(client, user1, monkeypatch):
    """It re-asks the question, it does not just put a deadline on the socket.

    The SPA heartbeats every 30s, which is also why the recheck is timed off a
    deadline rather than off each receive: client traffic must not be able to
    postpone it, and must not be mistaken for an answer either.
    """
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(messenger, "WS_REVALIDATE_SECONDS", 0.05)
    token, user = user1

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "AUTH", "token": token})
        assert _wait_until(lambda: manager.is_connected(user["address"]))

        time.sleep(0.4)  # several rounds, with the socket otherwise idle
        assert manager.is_connected(user["address"])

        ws.send_json({"type": "APP_FOCUSED"})
        assert manager.is_connected(user["address"])


def test_client_traffic_cannot_postpone_the_recheck(client, user1, db_session, monkeypatch):
    """Why the recheck is timed off a DEADLINE and not off each receive.

    The SPA heartbeats every 30s and signals focus changes besides, so a plain
    per-receive timeout is re-armed by ordinary traffic and never fires on the
    tab that is actually open — which is every tab worth hanging up on. Nothing
    else here catches that: the other gates leave the socket silent, so a
    per-receive timeout passes them.
    """
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(messenger, "WS_REVALIDATE_SECONDS", 0.3)
    token, user = user1

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "AUTH", "token": token})
        assert _wait_until(lambda: manager.is_connected(user["address"]))

        db_session.query(models.User).filter(models.User.address == user["address"]).update(
            {"token_version": 99}
        )
        db_session.commit()

        def chattering():
            # More often than the interval, the way a heartbeat is.
            ws.send_json({"type": "APP_FOCUSED"})
            return not manager.is_connected(user["address"])

        assert _wait_until(chattering, timeout=3.0), (
            "a talkative client kept its revoked socket alive"
        )
