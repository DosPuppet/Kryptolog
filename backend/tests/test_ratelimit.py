"""Tests for the rate-limit key (dependencies.client_ip).

Behind a proxy the direct peer is the proxy, so the limiter must key on the real
client — resolved from a forwarding header only when the peer is a trusted
proxy, otherwise a client could spoof its way to a fresh bucket.

That resolution belongs to uvicorn now (audit 2026-10-12 K-17), so these tests
run requests through uvicorn's own ProxyHeadersMiddleware, configured the way
serve.sh configures it, rather than asserting on a function in isolation: the
property worth pinning is what a deployed server does.
"""

import asyncio
import pathlib

import httpx
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from dependencies import _ratelimit_storage_uri, client_ip


async def _key_app(scope, receive, send):
    await PlainTextResponse(client_ip(Request(scope)))(scope, receive, send)


def _key_for(peer_host, headers=None, trusted="127.0.0.1"):
    """The rate-limit key a request from `peer_host` gets behind uvicorn."""
    app = ProxyHeadersMiddleware(_key_app, trusted_hosts=trusted)
    transport = httpx.ASGITransport(app=app, client=(peer_host, 12345))

    async def go():
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (await c.get("/", headers=headers or {})).text

    return asyncio.run(go())


def test_direct_client_no_proxy():
    # No proxy in front: the peer IS the client.
    assert _key_for("203.0.113.7") == "203.0.113.7"


def test_trusted_proxy_uses_the_hop_it_appended():
    # nginx: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for, i.e.
    # whatever the client sent, then the address nginx actually saw.
    assert _key_for("127.0.0.1", {"x-forwarded-for": "9.9.9.9, 203.0.113.5"}) == "203.0.113.5"


def test_a_client_sent_x_real_ip_is_ignored_even_from_a_trusted_proxy():
    """K-17: a proxy that relays X-Real-IP untouched (Caddy does) let every
    client pick its own bucket. Only X-Forwarded-For is read now."""
    key = _key_for("127.0.0.1", {"x-real-ip": "198.51.100.1", "x-forwarded-for": "203.0.113.9"})
    assert key == "203.0.113.9"


def test_untrusted_peer_ignores_spoofed_headers():
    # A direct (non-proxy) client cannot spoof its way to a different bucket.
    key = _key_for("203.0.113.50", {"x-real-ip": "127.0.0.1", "x-forwarded-for": "8.8.8.8"})
    assert key == "203.0.113.50"


def test_trusted_proxy_without_headers_uses_peer():
    assert _key_for("127.0.0.1") == "127.0.0.1"


def test_serve_sh_hands_proxy_resolution_to_uvicorn():
    """client_ip trusts request.client, so the flags that make uvicorn rewrite
    it are part of the rule. Dropping them silently keys every client behind a
    proxy on the proxy's own address: one shared quota for everybody."""
    serve = (pathlib.Path(__file__).parents[1] / "serve.sh").read_text()
    assert "--proxy-headers" in serve
    assert '--forwarded-allow-ips "$TRUSTED_PROXY_IPS"' in serve


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
        client.get(f"/users/{user['address']}", headers=headers).status_code for _ in range(35)
    ]
    assert 200 in statuses
    assert 429 in statuses, f"never throttled; saw {sorted(set(statuses))}"


# --- Path parameters must not open a fresh quota (audit N-2) ---


def test_limit_survives_a_varying_path_parameter(client, user1):
    """The same route with a DIFFERENT path parameter shares one quota.

    slowapi's default key_style is "url", which counts per concrete url — so
    every distinct address opened its own 30/min bucket and the cap above was
    bypassed by simply enumerating. The test that exists for it hits ONE fixed
    address, which is exactly the shape that stayed correct, so it could not
    catch this. GET /users/{address} is the endpoint where it matters most:
    its limit exists to stop the account-existence oracle.
    """
    token, _ = user1
    headers = {"Authorization": f"Bearer {token}"}

    # Well-formed but unregistered addresses: distinct urls, all 404 through
    # the handler, and the limiter must still see them as one route.
    statuses = [client.get(f"/users/{i:064x}", headers=headers).status_code for i in range(35)]
    assert 429 in statuses, f"path parameter opened a fresh quota; saw {sorted(set(statuses))}"


def test_unauthenticated_nonce_limit_survives_a_varying_address(client):
    """Same defect, on the endpoint that is reachable without a token.

    GET /auth/nonce/{address} is unauthenticated and writes a row per distinct
    address, so an unbounded quota here is the table-growth path audit L-5
    closed the shape of and N-2 reopened the volume of.
    """
    statuses = [client.get(f"/auth/nonce/{i:064x}").status_code for i in range(15)]
    assert 429 in statuses, f"path parameter opened a fresh quota; saw {sorted(set(statuses))}"
