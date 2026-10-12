"""The server's own share of the deployment posture (audit 2026-10-12 lot 2).

Each of these used to be delegated entirely to nginx.conf.example — a body
limit, a closed /docs, a refusal to run production on unchosen settings — so a
deployment that reached uvicorn any other way had none of them.
"""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

import config
from security.body_limit import MAX_BODY_BYTES, BodySizeLimitMiddleware

# ── Body size (K-16, 2026-09-11 F-9) ─────────────────────────────────────────


class _Blob(BaseModel):
    data: str


def _app(max_bytes):
    app = FastAPI()
    reads = []

    @app.post("/echo")
    def echo(blob: _Blob):
        reads.append(len(blob.data))
        return {"len": len(blob.data)}

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_bytes)
    return app, reads


def _post(app, content, headers=None):
    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.post("/echo", content=content, headers=headers or {})

    return asyncio.run(go())


def test_a_declared_oversized_body_is_refused_before_it_is_read():
    app, reads = _app(max_bytes=1000)
    r = _post(app, b'{"data": "' + b"x" * 2000 + b'"}', {"content-type": "application/json"})
    assert r.status_code == 413
    assert reads == []


def test_an_undeclared_body_is_cut_off_at_the_limit():
    """Chunked: no Content-Length to check, so the bytes are counted."""
    app, reads = _app(max_bytes=1000)

    async def chunks():
        yield b'{"data": "'
        for _ in range(20):
            yield b"x" * 100
        yield b'"}'

    r = _post(app, chunks(), {"content-type": "application/json"})
    assert r.status_code == 413, r.text
    assert reads == []


def test_a_body_under_the_limit_is_untouched():
    app, reads = _app(max_bytes=1000)
    r = _post(app, b'{"data": "hello"}', {"content-type": "application/json"})
    assert r.status_code == 200 and r.json() == {"len": 5}


def test_the_real_app_carries_the_limit(client):
    r = client.post(
        "/auth/login",
        content=b"{" + b" " * (MAX_BODY_BYTES + 1) + b"}",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413


def test_the_limit_clears_the_largest_legitimate_body():
    """A device-transfer blob is the biggest thing a client ever sends."""
    from schemas import KeyTransferCreate

    largest = KeyTransferCreate.model_fields["ciphertext"].metadata
    max_len = next(m.max_length for m in largest if hasattr(m, "max_length"))
    assert max_len + 1024 < MAX_BODY_BYTES


# ── /docs (K-18) ─────────────────────────────────────────────────────────────


def test_docs_are_closed_in_production(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    assert config.api_docs_settings() == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_docs_stay_open_in_development(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "development")
    assert config.api_docs_settings() == {}


# ── Settings nobody chose (K-09, 2026-09-11 M-4) ─────────────────────────────


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    monkeypatch.setenv("KRYPTOLOG_REQUIRE_INVITE", "true")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://kryptolog.example")
    monkeypatch.setenv("KRYPTOLOG_DEPLOYMENT_ID", "prod-7Hq_x2")
    return monkeypatch


def test_production_with_explicit_settings_starts(production):
    config.check_production_settings()


def test_production_refuses_an_implicit_signup_policy(production):
    production.delenv("KRYPTOLOG_REQUIRE_INVITE")
    with pytest.raises(RuntimeError, match="KRYPTOLOG_REQUIRE_INVITE"):
        config.check_production_settings()


def test_production_accepts_open_signup_when_it_is_chosen(production):
    production.setenv("KRYPTOLOG_REQUIRE_INVITE", "false")
    config.check_production_settings()


def test_production_refuses_an_empty_origin_allowlist(production):
    """Without it the WebSocket Origin check accepts every origin."""
    production.delenv("ALLOWED_ORIGINS")
    with pytest.raises(RuntimeError, match="ALLOWED_ORIGINS"):
        config.check_production_settings()


def test_development_is_unaffected(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "development")
    monkeypatch.delenv("KRYPTOLOG_REQUIRE_INVITE", raising=False)
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    config.check_production_settings()


def test_the_real_app_refuses_an_undeclared_oversized_body_with_413(client):
    """The chunked path through the REAL middleware stack.

    Behind SecurityHeadersMiddleware (a BaseHTTPMiddleware) the overflow was
    rewrapped on its way to FastAPI and answered as a generic 400 — still not
    read past the limit, but wrong. Found by mutating the Content-Length check
    away: the only test of the real app then failed, which no isolated test did.
    """

    def chunks():
        yield b"{"
        for _ in range(MAX_BODY_BYTES // (1024 * 1024) + 1):
            yield b" " * (1024 * 1024)
        yield b"}"

    r = client.post("/auth/login", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text
    assert r.headers.get("x-content-type-options") == "nosniff"


def test_production_refuses_the_development_deployment_id(production):
    """Signed logins name the deployment (crypto-core 3.0.0, K-02). Two servers
    both calling themselves "dev" would accept each other's signatures."""
    production.delenv("KRYPTOLOG_DEPLOYMENT_ID")
    with pytest.raises(RuntimeError, match="KRYPTOLOG_DEPLOYMENT_ID"):
        config.check_production_settings()
    production.setenv("KRYPTOLOG_DEPLOYMENT_ID", "has spaces")
    with pytest.raises(RuntimeError, match="KRYPTOLOG_DEPLOYMENT_ID"):
        config.check_production_settings()
