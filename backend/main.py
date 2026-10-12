import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Configure root logging once, at the app entrypoint, so module loggers
# (kryptolog.*) emit. Honors LOG_LEVEL (default INFO).
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("kryptolog.main")

from fastapi import Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from dependencies import limiter
from routers import (
    account,
    auth,
    conversations,
    groups,
    health,
    messenger,
    multisig,
    notifications,
    secrets,
    transfers,
    users,
)

# ── App & Middleware (initialised FIRST so CORS always works) ───


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Shared WebSocket fan-out + presence (Redis pub/sub, audit P0). No-op
    # without REDIS_URL — the manager stays in single-process local mode.
    from websocket_manager import manager as ws_manager

    await ws_manager.startup()
    # Message retention (audit 2026-09-11 M-6): a no-op loop unless
    # KRYPTOLOG_MESSAGE_RETENTION_DAYS is set. Not started for a configuration
    # without it, so the common case costs nothing.
    import retention
    from database import SessionLocal

    purge_task = (
        asyncio.create_task(retention.run_forever(SessionLocal))
        if config.message_retention_days() is not None
        else None
    )
    yield
    if purge_task:
        purge_task.cancel()
    await ws_manager.shutdown()


import config  # noqa: E402

app = FastAPI(lifespan=_lifespan, **config.api_docs_settings())
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Security headers for API responses (audit KRY-009).

    These are defence-in-depth for the API surface itself. The SPA's own
    headers — including the full CSP, HSTS and Permissions-Policy — are set by
    the reverse proxy in nginx.conf.example, which is the right place for them:
    HSTS is a property of the TLS terminator, and the SPA's CSP has to describe
    assets FastAPI never serves. What is set here still matters, because a
    deployment that exposes the API directly (or bypasses the proxy) would
    otherwise get nothing at all.

    X-XSS-Protection is deliberately NOT set. It is obsolete in every current
    browser, and its legacy auditor had bypasses of its own, so emitting it is
    at best noise and at worst harmful.
    """

    # The API returns JSON, never HTML or scripts, so it can afford the most
    # restrictive policy there is: deny everything and forbid framing. This is
    # not the SPA's CSP — see nginx.conf.example for that one.
    _API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = self._API_CSP
        # No API response should be embedded by another site, and none of these
        # browser features are ever needed by a JSON endpoint.
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        # HSTS only when the request actually arrived over TLS; sending it on a
        # plaintext dev request is meaningless and pins localhost to https.
        # In production the proxy sets this too — matching values, so whichever
        # one lands is correct.
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


# The body ceiling the reverse proxy used to be the only holder of (audit
# 2026-10-12 K-16). Added BEFORE the headers middleware so it sits INSIDE it,
# next to FastAPI: SecurityHeadersMiddleware is a BaseHTTPMiddleware, which
# relays the request stream through its own task and rewraps anything raised
# there, so from outside it a chunked body that overran the limit reached
# FastAPI as an unknown error and came back as a generic 400. Inside, the 413
# arrives intact, with the security headers on it. A declared Content-Length is
# still refused before any body byte is read: BaseHTTPMiddleware streams lazily.
from security.body_limit import BodySizeLimitMiddleware  # noqa: E402

app.add_middleware(BodySizeLimitMiddleware)

app.add_middleware(SecurityHeadersMiddleware)


# CORS configuration

origins = config.get_allowed_origins()
if origins:
    logger.info("Loaded ALLOWED_ORIGINS: %s", origins)
else:
    logger.warning("ALLOWED_ORIGINS not set. CORS will block all requests.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    # Auth is a Bearer token held in memory (no cookies), so credentialed CORS
    # isn't needed — leaving it off keeps the policy tighter.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    # The correlation id is only useful if the SPA can read it off a failure.
    expose_headers=["X-Request-ID"],
)

# Outermost, so it sees every refusal, the limiter's and CORS's included, and
# stamps every response with the id its audit lines carry (audit 2026-09-11 M-3).
from security import audit_log  # noqa: E402
from security.request_audit import RequestAuditMiddleware  # noqa: E402

audit_log.configure()
app.add_middleware(RequestAuditMiddleware)

# ── Database migrations ─────────────────────────────────────────
#
# Deliberately NOT run here (audit M-3). This module used to call
# `alembic upgrade head` at import time behind a bare `except Exception` that
# fell back to `create_all` + `stamp head`. Three problems compounded:
#
#   1. `create_all` only creates MISSING TABLES — it cannot add a column to a
#      table that already exists. So a migration failing halfway left a partial
#      schema, and `stamp head` then declared that schema up to date. The drift
#      was invisible and no later `alembic upgrade` would repair it.
#   2. At import time, every worker raced the same DDL with no advisory lock.
#   3. It coupled importing the app to mutating the database, which is why the
#      test suite has to set DATABASE_URL before importing this module.
#
# Migrations now run as an explicit deployment step (`alembic upgrade head`, see
# start_all.sh and the README). A refused start beats a drifted schema stamped
# "current".

# ── JWT secret validation (fail closed at boot in production) ──
# auth.py is imported here as `signing` because `auth` already refers to the
# router module above. In production this raises if no persistent JWT secret is
# set, so the process never starts serving with an ephemeral one.
import auth as signing

signing.get_jwt_secret()
# Same fail-closed rule for the two settings that decide who can reach the
# server at all — see config.check_production_settings.
config.check_production_settings()

# ── Routers ─────────────────────────────────────────────────────

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(account.router)
app.include_router(conversations.router)
app.include_router(users.router)
app.include_router(secrets.router)
app.include_router(multisig.router)
app.include_router(messenger.router)
app.include_router(messenger.ws_router)
app.include_router(groups.router)
app.include_router(notifications.router)
app.include_router(transfers.router)


@app.get("/")
def read_root():
    """Liveness only. For readiness — database, Redis, realtime — use `/healthz`."""
    return {"status": "running"}
