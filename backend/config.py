# Backend Configuration

import os
import re

# Maximum total size for a chunked file upload (50MB)
MAX_TOTAL_FILE_SIZE = 50 * 1024 * 1024

# Device-to-device key transfer relay (encrypted vault blob held briefly).
KEY_TRANSFER_TTL_MINUTES = 10


def is_production() -> bool:
    """KRYPTOLOG_ENV=production (or prod). Unset means development."""
    return (os.getenv("KRYPTOLOG_ENV") or "development").strip().lower() in ("production", "prod")


def invites_required() -> bool:
    """Whether creating a brand-new identity requires a valid invite code
    (access filter, audit §5). Read at call time so it can be toggled per-process
    / per-test. Unset means OFF in development; in production the setting must
    be explicit (see check_production_settings).

    Note: this only gates *account creation*. Existing users always log in
    normally, and an invalid/expired code yields a generic 403 (no enumeration)."""
    return (os.getenv("KRYPTOLOG_REQUIRE_INVITE") or "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def get_allowed_origins() -> list[str]:
    """Parse ALLOWED_ORIGINS (comma-separated) into a normalized list.

    Single source of truth for both the CORS middleware (main.py) and the
    WebSocket Origin allowlist (routers/messenger.py) — CORS does NOT apply to
    WebSocket handshakes, so the WS endpoint has to check Origin itself."""
    env_origins = os.getenv("ALLOWED_ORIGINS")
    if not env_origins:
        return []
    return [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]


# Development's deployment id when none is configured. Production refuses to
# start without a real one (check_production_settings).
DEV_DEPLOYMENT_ID = "dev"


def deployment_id() -> str:
    """This server's identity inside signed login and deletion bodies.

    Returned by GET /auth/nonce and checked at login (crypto-core 3.0.0, audit
    2026-10-12 K-02): a signature produced for another Kryptolog deployment —
    one the same identity also uses — does not open a session here, even when
    it names an origin this server accepts. KRYPTOLOG_DEPLOYMENT_ID; letters,
    digits, '-' and '_', at most 64 (the signed-identifier alphabet).
    """
    return (os.getenv("KRYPTOLOG_DEPLOYMENT_ID") or "").strip() or DEV_DEPLOYMENT_ID


def login_origin_allowed(origin: str) -> bool:
    """Whether a login or deletion signed for `origin` may be honoured here.

    The SPA origins are exactly ALLOWED_ORIGINS, the list CORS and the WebSocket
    Origin check already use. With no list (development only — production
    refuses to start without one) any canonical origin is accepted.
    """
    allowed = get_allowed_origins()
    return not allowed or origin in allowed


def api_docs_settings() -> dict:
    """FastAPI kwargs for /docs, /redoc and /openapi.json.

    The OpenAPI surface is a full map of the API and nothing about it needs to be
    public on a production server (audit 2026-10-12 K-18, 2026-09-11 F-1). Kept
    in development, where /docs is the quickest way to try an endpoint.
    """
    if is_production():
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {}


def check_production_settings() -> None:
    """Refuse to start a production server on a policy nobody chose.

    Two settings decide who can reach this server, and both used to default to
    the open answer silently (audit 2026-10-12 K-09, 2026-09-11 M-4):

    * KRYPTOLOG_REQUIRE_INVITE unset meant open signup — anyone who could reach
      the API could create an identity and start filling the disk. Production
      now has to say true or false; "false" is allowed, just never by omission.
    * ALLOWED_ORIGINS unset meant CORS refuses everything, but the WebSocket
      Origin check (routers/messenger._origin_allowed) accepts everything,
      since it only applies when an allowlist exists.

    No-op outside production, so development and the test suite are unaffected.
    """
    if not is_production():
        return
    problems = []
    if (os.getenv("KRYPTOLOG_REQUIRE_INVITE") or "").strip() == "":
        problems.append(
            "KRYPTOLOG_REQUIRE_INVITE must be set explicitly (true or false) in production"
        )
    if not get_allowed_origins():
        problems.append("ALLOWED_ORIGINS must list the SPA origin(s) in production")
    if deployment_id() == DEV_DEPLOYMENT_ID:
        problems.append("KRYPTOLOG_DEPLOYMENT_ID must be set in production")
    elif not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", deployment_id()):
        problems.append("KRYPTOLOG_DEPLOYMENT_ID must be 1-64 letters, digits, '-' or '_'")
    if problems:
        raise RuntimeError("Refusing to start: " + "; ".join(problems))
