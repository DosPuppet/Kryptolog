# Backend Configuration

import os

# Maximum total size for a chunked file upload (50MB)
MAX_TOTAL_FILE_SIZE = 50 * 1024 * 1024

# Device-to-device key transfer relay (encrypted vault blob held briefly).
KEY_TRANSFER_TTL_MINUTES = 10
# Generous ceiling for an encrypted multi-account vault blob (hex JSON).
MAX_KEY_TRANSFER_SIZE = 4 * 1024 * 1024


def invites_required() -> bool:
    """Whether creating a brand-new identity requires a valid invite code
    (access filter, audit §5). Read at call time so it can be toggled per-process
    / per-test. Default OFF — opt in with KRYPTOLOG_REQUIRE_INVITE=true.

    Note: this only gates *account creation*. Existing users always log in
    normally, and an invalid/expired code yields a generic 403 (no enumeration)."""
    return (os.getenv("KRYPTOLOG_REQUIRE_INVITE") or "false").strip().lower() in (
        "1", "true", "yes", "on",
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
