"""Correlation ids, and an audit line for every refused request (audit 2026-09-11 M-3).

Pure ASGI rather than BaseHTTPMiddleware: it only needs to watch the status
line go by, and BaseHTTPMiddleware relays the body through its own task (the
reason security/body_limit.py has to sit inside it, see main.py).

Added LAST in main.py, so it is the outermost layer: a 429 from the rate
limiter and a CORS refusal pass through it like everything else.
"""

import uuid

from starlette.requests import Request

from security.audit_log import audit_event

# The refusals worth an investigator's attention: unauthenticated, forbidden,
# and throttled. A 404 is deliberately absent — since the 2026-09-11 F-4 fix a
# stranger probing secret ids gets 404s, but so does every stale link.
AUDITED_STATUSES = frozenset({401, 403, 429})

# Addresses travel in some paths (`/users/{address}`, `/auth/nonce/{address}`);
# the audit stream carries 16 characters of an address, never all of them.
_LONG_SEGMENT = 32


def _loggable_path(path: str) -> str:
    return "/".join(seg[:16] + "…" if len(seg) > _LONG_SEGMENT else seg for seg in path.split("/"))


class RequestAuditMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["request_id"] = request_id
        status = None

        async def send_with_id(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", [])
                message["headers"] = [
                    *message["headers"],
                    (b"x-request-id", request_id.encode()),
                ]
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            if status in AUDITED_STATUSES:
                audit_event(
                    "http.denied",
                    request=Request(scope),
                    outcome="refused",
                    status=status,
                    method=scope.get("method"),
                    path=_loggable_path(scope.get("path", "")),
                )
