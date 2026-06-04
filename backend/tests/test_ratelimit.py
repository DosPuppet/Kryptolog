"""Tests for the reverse-proxy-aware rate-limit key (dependencies.client_ip).

Behind nginx the direct peer is the proxy, so the limiter must resolve the real
client IP from trusted forwarding headers — but only when the peer is actually a
trusted proxy, otherwise a client could spoof headers to dodge limits.
"""

from starlette.requests import Request

from dependencies import client_ip, TRUSTED_PROXY_IPS


def _request(peer_host, headers=None):
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": (peer_host, 12345),
        "headers": raw_headers,
    }
    return Request(scope)


def test_default_trusted_proxy_is_localhost():
    assert "127.0.0.1" in TRUSTED_PROXY_IPS


def test_direct_client_no_proxy():
    # No proxy in front: the peer IS the client.
    req = _request("203.0.113.7")
    assert client_ip(req) == "203.0.113.7"


def test_trusted_proxy_uses_x_real_ip():
    req = _request("127.0.0.1", {"x-real-ip": "203.0.113.9", "x-forwarded-for": "1.1.1.1, 203.0.113.9"})
    assert client_ip(req) == "203.0.113.9"


def test_trusted_proxy_falls_back_to_rightmost_xff():
    req = _request("127.0.0.1", {"x-forwarded-for": "9.9.9.9, 203.0.113.5"})
    assert client_ip(req) == "203.0.113.5"


def test_untrusted_peer_ignores_spoofed_headers():
    # A direct (non-proxy) client cannot spoof its way to a different bucket.
    req = _request("203.0.113.50", {"x-real-ip": "127.0.0.1", "x-forwarded-for": "8.8.8.8"})
    assert client_ip(req) == "203.0.113.50"


def test_trusted_proxy_without_headers_uses_peer():
    req = _request("127.0.0.1")
    assert client_ip(req) == "127.0.0.1"
