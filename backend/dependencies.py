import logging
import os

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

import auth
import models
from database import get_db
from security import authorization

logger = logging.getLogger("kryptolog.ratelimit")


def client_ip(request: Request) -> str:
    """Rate-limit key: the connecting client, as uvicorn resolved it.

    Behind a reverse proxy every request's TCP peer is the proxy, so the real
    client has to come from a forwarding header — and only when that peer is a
    trusted proxy. That resolution is uvicorn's job, not ours: `serve.sh` passes
    `--proxy-headers --forwarded-allow-ips "$TRUSTED_PROXY_IPS"`, and uvicorn
    rewrites `request.client` to the right-most UNTRUSTED X-Forwarded-For hop.

    This used to read X-Real-IP itself whenever the peer was trusted (audit
    2026-10-12 K-17). That header is only safe if the proxy overwrites it, and
    not every proxy does: Caddy relays a client-sent X-Real-IP untouched, so any
    client behind it chose its own rate-limit bucket — one fresh quota per
    request, on the login limit included. X-Forwarded-For has no such ambiguity:
    every proxy appends to it, and the walk from the right stops at the first
    hop no trusted proxy vouched for.
    """
    return get_remote_address(request)


def _ratelimit_storage_uri() -> str:
    """Resolve the rate-limit storage backend (audit F-3).

    A shared/persistent backend (Redis) makes throttles — notably the login
    limit — survive restarts and stay correct if the app ever runs more than one
    process. When unset we fall back to in-memory limiting: fine for a single
    process, but per-process and reset on every restart. `RATELIMIT_STORAGE_URI`
    is an explicit override; otherwise a plain `REDIS_URL` is reused."""
    return os.getenv("RATELIMIT_STORAGE_URI") or os.getenv("REDIS_URL") or "memory://"


_STORAGE_URI = _ratelimit_storage_uri()
if _STORAGE_URI.startswith("memory://"):
    # This is also the single-process guard (audit F-3): with in-memory limits,
    # running multiple workers/instances multiplies effective limits AND breaks
    # the in-memory WebSocket delivery + presence — keep the backend to ONE
    # process until a shared backend (Redis) and WS fan-out are configured.
    logger.warning(
        "Rate limiting uses in-memory storage: limits are per-process and reset on "
        "restart. Set REDIS_URL (or RATELIMIT_STORAGE_URI) for durable, shared limits. "
        "The backend assumes a SINGLE process — do not run multiple workers/instances "
        "with in-memory storage (it multiplies limits and breaks WebSocket delivery)."
    )
else:
    # Never log the full URI — it may carry credentials (redis://:pw@host).
    logger.info("Rate limiting storage backend: %s://…", _STORAGE_URI.split("://", 1)[0])

# in_memory_fallback_enabled: if the shared store (Redis) becomes unreachable,
# degrade to in-memory limiting rather than erroring out or dropping limits
# entirely — limits stay enforced (per-process) until Redis recovers.
#
# key_style="endpoint": slowapi's DEFAULT is "url", which buckets the counter by
# the CONCRETE url — so /auth/nonce/<a> and /auth/nonce/<b> were separate quotas
# and any limit on a path-parameterized route was bypassed by rotating the
# parameter (audit N-2). That silently voided most of the M-7 limits, including
# the two that exist to stop enumeration: GET /users/{address} (an account
# existence oracle) and the unauthenticated GET /auth/nonce/{address} (one row
# written per distinct address). Keying on the endpoint FUNCTION makes one
# quota per route per client, which is what every one of those decorators
# already claims to do. Routes with no path parameter were always correct,
# which is why the tests — all of which hit a fixed url — never caught it.
limiter = Limiter(
    key_func=client_ip,
    storage_uri=_STORAGE_URI,
    in_memory_fallback_enabled=True,
    key_style="endpoint",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def user_for_token(token: str, db: Session):
    """Decode + validate a JWT and return the (non-revoked) user, or None.

    Enforces token revocation: the token's `tv` claim must match the user's
    current token_version (bumped on logout / revoke-all). Shared by the HTTP
    dependency and the WebSocket handshake so both honor revocation."""
    payload = auth.decode_access_token(token)
    if payload is None:
        return None
    address = payload.get("sub")
    if not address:
        return None
    user = db.query(models.User).filter(models.User.address == address.lower()).first()
    if user is None:
        return None
    # A deleted identity cannot authenticate. Deletion already bumps
    # token_version, so the check below would refuse every token minted before
    # it — but this does not depend on that: a row stripped of its keys must
    # never carry a session, whatever its version happens to be.
    if not authorization.is_active(user):
        return None
    if payload.get("tv", 0) != (user.token_version or 0):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = user_for_token(token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
