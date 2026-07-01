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

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
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

