"""Tests for the WebSocket /ws endpoint hardening (audit M2):
Origin allowlist (CORS doesn't cover WS handshakes) + pre-auth timeout."""

import pytest
from starlette.websockets import WebSocketDisconnect

import routers.messenger as messenger


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
