# Backend Configuration

import os

# Maximum total size for a chunked file upload (50MB)
MAX_TOTAL_FILE_SIZE = 50 * 1024 * 1024


def get_allowed_origins() -> list[str]:
    """Parse ALLOWED_ORIGINS (comma-separated) into a normalized list.

    Single source of truth for both the CORS middleware (main.py) and the
    WebSocket Origin allowlist (routers/messenger.py) — CORS does NOT apply to
    WebSocket handshakes, so the WS endpoint has to check Origin itself."""
    env_origins = os.getenv("ALLOWED_ORIGINS")
    if not env_origins:
        return []
    return [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]
