from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine
from models import Base
import logging
import os

# Configure root logging once, at the app entrypoint, so module loggers
# (kryptolog.*) emit. Honors LOG_LEVEL (default INFO).
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("kryptolog.main")

from routers import auth, users, secrets, multisig, messenger, groups, notifications, transfers
from dependencies import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

# ── App & Middleware (initialised FIRST so CORS always works) ───

@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Shared WebSocket fan-out + presence (Redis pub/sub, audit P0). No-op
    # without REDIS_URL — the manager stays in single-process local mode.
    from websocket_manager import manager as ws_manager
    await ws_manager.startup()
    yield
    await ws_manager.shutdown()

app = FastAPI(lifespan=_lifespan)
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
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS configuration
import config
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
)

# ── Database migrations (run AFTER app init) ────────────────────

try:
    from alembic.config import Config
    from alembic import command
    alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "alembic.ini"))
    command.upgrade(alembic_cfg, "head")
except Exception as e:
    logger.warning("Alembic upgrade failed: %s — falling back to create_all + stamp head", e)
    Base.metadata.create_all(bind=engine)
    try:
        command.stamp(alembic_cfg, "head")
    except Exception as e2:
        logger.warning("Alembic stamp also failed: %s", e2)

# ── JWT secret validation (fail closed at boot in production) ──
# auth.py is imported here as `signing` because `auth` already refers to the
# router module above. In production this raises if no persistent JWT secret is
# set, so the process never starts serving with an ephemeral one.
import auth as signing
signing.get_jwt_secret()

# ── Routers ─────────────────────────────────────────────────────

app.include_router(auth.router)
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
    return {"status": "running"}

