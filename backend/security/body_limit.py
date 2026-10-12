"""A ceiling on request body size, enforced by the application itself.

The only bound used to be nginx's `client_max_body_size`, so a deployment that
reached uvicorn any other way — directly (audit 2026-10-12 K-01), or behind a
proxy that sets no limit, like Caddy by default (K-16) — read an attacker's body
to the end before Pydantic refused it: 8 MB went in whole and came back as a 422
(audit 2026-09-11 F-9). Every field bound in schemas.py is checked only AFTER
that read.

Pure ASGI rather than BaseHTTPMiddleware, because the point is to stop reading:
a declared Content-Length over the limit is refused before a single body byte is
received, and a body that does not declare one (chunked) is counted as it
streams and cut off at the limit.
"""

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

# The largest legitimate body is a device-transfer blob (schemas.KeyTransferCreate,
# 4 000 000 chars) or a full erase round (1 000 redactions, ~3.3 MB). A file
# chunk is ~1.4 MB. 8 MiB clears all of them with room, and nginx.conf.example
# carries the same figure so neither layer is the looser one.
MAX_BODY_BYTES = 8 * 1024 * 1024


_DETAIL = f"Request body too large (max {MAX_BODY_BYTES // (1024 * 1024)} MB)"


class _BodyTooLarge(HTTPException):
    """An HTTPException on purpose: FastAPI catches any OTHER exception raised
    while it reads the body and answers a generic 400 "error parsing the body",
    but re-raises HTTPException untouched, so this one arrives as a 413."""

    def __init__(self):
        super().__init__(status_code=413, detail=_DETAIL)


def _too_large():
    return JSONResponse({"detail": _DETAIL}, status_code=413)


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True  # unparseable: refuse rather than guess
            if too_big:
                await _too_large()(scope, receive, send)
                return

        seen = 0
        started = False

        async def counting_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            # Reached only by an app that reads the body outside FastAPI's
            # handler; FastAPI itself turns the exception into the 413.
            if not started:
                await _too_large()(scope, receive, send)
