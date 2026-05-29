from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base
import os

from routers import auth, users, secrets, multisig, messenger, groups, notifications
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
origins = []

env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    origins.extend([origin.strip().rstrip("/") for origin in env_origins.split(",")])
    print(f"INFO: Loaded ALLOWED_ORIGINS: {origins}")

if not origins:
    print("WARNING: ALLOWED_ORIGINS not set. CORS will block all requests.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
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
    print(f"WARNING: Alembic upgrade failed: {e}")
    print("Falling back to create_all + stamp head")
    Base.metadata.create_all(bind=engine)
    try:
        command.stamp(alembic_cfg, "head")
    except Exception as e2:
        print(f"WARNING: Alembic stamp also failed: {e2}")

# ── Routers ─────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(secrets.router)
app.include_router(multisig.router)
app.include_router(messenger.router)
app.include_router(messenger.ws_router)
app.include_router(groups.router)
app.include_router(notifications.router)

@app.get("/")
def read_root():
    return {"status": "running"}

