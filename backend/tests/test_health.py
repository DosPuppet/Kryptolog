"""GET /healthz (audit 2026-10-12, operations; 2026-09-23 M-2).

A worker whose database or fan-out listener had died kept answering `/` with
200, so nothing outside it could tell.
"""

import pytest

from websocket_manager import manager


def test_healthy_single_process(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "checks": {"database": "ok", "realtime": "local"}}


def test_needs_no_login_and_says_nothing_about_the_server(client):
    resp = client.get("/healthz")
    assert set(resp.json()) == {"status", "checks"}
    assert "server" not in {k.lower() for k in resp.headers}


def test_a_dead_database_is_a_503(client, monkeypatch):
    from sqlalchemy.orm import Session

    def boom(self, *args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(Session, "execute", boom)
    resp = client.get("/healthz")
    assert resp.status_code == 503
    assert resp.json()["checks"]["database"] == "down"


@pytest.mark.parametrize("listening", [True, False])
def test_shared_mode_reports_the_fanout_listener(client, monkeypatch, listening):
    """The M-2 failure mode exactly: Redis answers, this worker hears nothing."""

    class Redis:
        def ping(self):
            return True

    monkeypatch.setattr(manager, "_redis", object())
    monkeypatch.setattr(manager, "_redis_sync", Redis())
    monkeypatch.setattr(manager, "_listening", listening)

    resp = client.get("/healthz")
    assert resp.status_code == (200 if listening else 503)
    assert resp.json()["checks"] == {
        "database": "ok",
        "redis": "ok",
        "realtime": "ok" if listening else "down",
    }
