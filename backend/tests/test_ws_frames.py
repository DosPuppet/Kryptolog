"""Every WebSocket frame the server emits is one the SPA handles (audit 2026-09-23 Q-1).

GROUP_JOINED was broken from both ends for its whole life: the server could not
serialize it, and the SPA listened for a GROUP_CREATED the server never sent.
Neither half had a test that could see the other. Signed bodies are pinned
across languages by a shared fixture; server-to-client frames were not pinned
by anything. This reads both sides the way test_envelope_sizes pins the size
constants: the frame types the backend spells, against the handler keys the
SPA registers.

Serializability itself is enforced at the source: send_personal_message
json-encodes every frame before sending, in both modes, so a frame that cannot
be encoded fails the request that built it and that request's tests.
"""

import re
from pathlib import Path

import websocket_manager

BACKEND = Path(__file__).resolve().parent.parent
SPA = BACKEND.parent / "frontend" / "src"

# The handler maps the SPA registers with useMessengerSocket.
SPA_HANDLER_FILES = (
    SPA / "context" / "MessengerContext.jsx",
    SPA / "context" / "messenger" / "groupEvents.js",
)
FRAME_TYPE = re.compile(r'"type":\s*"([A-Z][A-Z_]+)"')
HANDLER_KEY = re.compile(r"^\s+([A-Z][A-Z_]+):", re.MULTILINE)


def _server_frame_types() -> set[str]:
    found = set(websocket_manager.HANGUP_TYPES)
    for path in [*BACKEND.glob("routers/*.py"), *BACKEND.glob("utils/*.py")]:
        found |= set(FRAME_TYPE.findall(path.read_text()))
    return found


def _spa_handled_types() -> set[str]:
    handled = set()
    for path in SPA_HANDLER_FILES:
        handled |= set(HANDLER_KEY.findall(path.read_text()))
    return handled


def test_the_scan_finds_the_frames_it_is_meant_to():
    # A regex that matched nothing would pass the real test vacuously.
    assert {"NEW_MESSAGE", "GROUP_JOINED", "SESSION_REVOKED"} <= _server_frame_types()
    assert {"NEW_MESSAGE", "GROUP_MEMBER_ADDED"} <= _spa_handled_types()


def test_every_frame_the_server_sends_has_an_spa_handler():
    missing = _server_frame_types() - _spa_handled_types()
    assert not missing, f"server frames the SPA ignores: {sorted(missing)}"


def test_the_spa_handles_no_frame_the_server_never_sends():
    """GROUP_CREATED sat in the handler map for a frame nobody sent, which is
    how a misnamed frame looks from this side."""
    dead = _spa_handled_types() - _server_frame_types()
    assert not dead, f"SPA handlers for frames the server never sends: {sorted(dead)}"
