"""Tests for the reverse-proxy-aware rate-limit key (dependencies.client_ip).

Behind nginx the direct peer is the proxy, so the limiter must resolve the real
client IP from trusted forwarding headers — but only when the peer is actually a
trusted proxy, otherwise a client could spoof headers to dodge limits.
"""

from starlette.requests import Request

from dependencies import client_ip, TRUSTED_PROXY_IPS, _ratelimit_storage_uri


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


# --- Rate-limit storage selection (audit F-3) ---

def test_storage_uri_defaults_to_memory(monkeypatch):
    monkeypatch.delenv("RATELIMIT_STORAGE_URI", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert _ratelimit_storage_uri() == "memory://"


def test_storage_uri_uses_redis_url(monkeypatch):
    monkeypatch.delenv("RATELIMIT_STORAGE_URI", raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://cache:6379/0")
    assert _ratelimit_storage_uri() == "redis://cache:6379/0"


def test_storage_uri_explicit_override_wins_over_redis_url(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://cache:6379/0")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://explicit:6379/1")
    assert _ratelimit_storage_uri() == "redis://explicit:6379/1"


# --- Endpoint coverage (audit M-7) ---
#
# 16 endpoints shipped with no @limiter.limit at all. They looked like
# oversights rather than decisions: the costly ones (chunk download, the
# joinedload-heavy workflow list) were uncapped while cheaper neighbours were
# capped, and GET /users/{address} was a free account-existence oracle beside a
# 30/min POST /users/resolve that answers the identical question.
#
# Asserted by introspection rather than by hammering each route: this stays fast
# and, more importantly, fails when someone ADDS an endpoint here without a
# limit — which is how the original 16 accumulated.

# Endpoints that must carry an explicit limit, as `module.function` keys.
RATE_LIMITED_ENDPOINTS = {
    "routers.secrets.get_secrets",
    "routers.secrets.update_secret",
    "routers.secrets.delete_secret",
    "routers.secrets.revoke_grant",
    "routers.secrets.get_secret_access",
    "routers.secrets.get_shared_secrets",
    "routers.secrets.get_chunk",
    "routers.multisig.list_multisig_workflows",
    "routers.multisig.get_multisig_workflow",
    "routers.users.update_user",
    "routers.users.get_user",
    "routers.messenger.mark_read",
    "routers.groups.mark_group_read",
}


def test_previously_unlimited_endpoints_are_now_limited():
    import main  # noqa: F401 — importing registers every router on the limiter
    from dependencies import limiter

    missing = RATE_LIMITED_ENDPOINTS - set(limiter._route_limits)
    assert not missing, f"endpoints without a rate limit: {sorted(missing)}"


def test_limit_is_actually_enforced(client, user1):
    """One end-to-end check that the decorators are wired, not just present.

    GET /users/{address} is capped at 30/min to match POST /users/resolve.
    """
    token, user = user1
    headers = {"Authorization": f"Bearer {token}"}

    statuses = [
        client.get(f"/users/{user['address']}", headers=headers).status_code
        for _ in range(35)
    ]
    assert 200 in statuses
    assert 429 in statuses, f"never throttled; saw {sorted(set(statuses))}"
