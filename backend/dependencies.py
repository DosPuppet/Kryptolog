import os
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import auth
import models
from database import get_db
from slowapi import Limiter
from slowapi.util import get_remote_address

# Reverse-proxy awareness for rate limiting.
# Behind nginx (proxy_pass to 127.0.0.1), every request's direct peer is the
# proxy, so keying limits on request.client.host collapses everyone into one
# bucket. We trust forwarding headers ONLY when the direct peer is a configured
# proxy IP, then use nginx's X-Real-IP (set to $remote_addr — not client-spoofable)
# or, as a fallback, the right-most X-Forwarded-For entry (the hop nginx appended).
TRUSTED_PROXY_IPS = {
    ip.strip() for ip in (os.getenv("TRUSTED_PROXY_IPS") or "127.0.0.1").split(",") if ip.strip()
}


def client_ip(request: Request) -> str:
    """Rate-limit key: the real client IP, resolved safely behind a trusted proxy."""
    peer = request.client.host if request.client else None
    if peer in TRUSTED_PROXY_IPS:
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # Right-most entry is the hop our own proxy appended (least spoofable).
            return xff.split(",")[-1].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=client_ip)

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
