"""Shared WebSocket fan-out + presence (audit P0).

Exercises ConnectionManager's Redis mode: delivery published through pub/sub
(so any worker's sockets are reached), presence tracked in TTL'd Redis keys,
and graceful fallback to in-process behavior when Redis is absent or fails.

Runs against fakeredis by default; set TEST_REDIS_URL to use a real Redis
(CI does, via its redis service container).
"""

import asyncio
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from websocket_manager import ConnectionManager, PRESENCE_PREFIX


@pytest.fixture
def addr():
    """Unique per test: against a real Redis (TEST_REDIS_URL), presence keys
    from one test must not bleed into the next (they carry a 90s TTL)."""
    return f"pqc_fanout_user_{uuid.uuid4().hex}"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeWebSocket:
    """Just enough of a WebSocket for the manager: hashable + send_json."""

    def __init__(self):
        self.sent = []

    async def send_json(self, message):
        self.sent.append(message)


async def _make_shared_manager():
    url = os.getenv("TEST_REDIS_URL")
    if url:
        mgr = ConnectionManager(redis_url=url)
        await mgr.startup()
    else:
        import fakeredis
        import fakeredis.aioredis

        server = fakeredis.FakeServer()
        mgr = ConnectionManager(redis_url="redis://fake")
        await mgr.startup(
            redis_client=fakeredis.aioredis.FakeRedis(server=server, decode_responses=True),
            redis_sync_client=fakeredis.FakeRedis(server=server, decode_responses=True),
        )
    assert mgr.shared, "shared mode failed to start"
    return mgr


async def _wait_for(condition, timeout=5.0):
    """Poll until `condition()` is truthy (pub/sub delivery is asynchronous)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.01)
    return False


@pytest.mark.anyio
async def test_fanout_delivers_via_pubsub_to_all_sockets(addr):
    mgr = await _make_shared_manager()
    try:
        ws1, ws2 = FakeWebSocket(), FakeWebSocket()
        await mgr.connect(ws1, addr)
        await mgr.connect(ws2, addr)

        await mgr.send_personal_message({"type": "TEST_EVENT", "n": 1}, addr)

        assert await _wait_for(lambda: ws1.sent and ws2.sent), \
            "message did not arrive through the pub/sub subscriber"
        assert ws1.sent[0] == {"type": "TEST_EVENT", "n": 1}
        assert ws2.sent[0] == {"type": "TEST_EVENT", "n": 1}
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_fanout_message_for_other_user_not_delivered(addr):
    mgr = await _make_shared_manager()
    try:
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)
        await mgr.send_personal_message({"type": "TEST_EVENT"}, "someone_else")
        # Give the subscriber a moment; nothing should land on ws.
        await asyncio.sleep(0.1)
        assert ws.sent == []
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_is_shared_through_redis(addr):
    mgr = await _make_shared_manager()
    try:
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)

        # Connected (blurred) — visible to the sync push-path readers.
        assert mgr.is_connected(addr) is True
        assert mgr.is_focused(addr) is False

        await mgr.set_focused(ws)
        assert mgr.is_focused(addr) is True

        await mgr.set_blurred(ws)
        assert mgr.is_focused(addr) is False

        await mgr.disconnect(ws, addr)
        assert mgr.is_connected(addr) is False
        # No presence keys left behind.
        assert mgr._presence_keys(addr) == []
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_readable_by_a_second_manager(addr):
    """The point of shared presence: another worker (second manager on the
    same Redis) sees this worker's focus state."""
    if not os.getenv("TEST_REDIS_URL"):
        import fakeredis
        import fakeredis.aioredis

        server = fakeredis.FakeServer()

        async def make():
            m = ConnectionManager(redis_url="redis://fake")
            await m.startup(
                redis_client=fakeredis.aioredis.FakeRedis(server=server, decode_responses=True),
                redis_sync_client=fakeredis.FakeRedis(server=server, decode_responses=True),
            )
            return m

        mgr_a, mgr_b = await make(), await make()
    else:
        mgr_a, mgr_b = await _make_shared_manager(), await _make_shared_manager()

    try:
        ws = FakeWebSocket()
        await mgr_a.connect(ws, addr)
        await mgr_a.set_focused(ws)

        # Worker B holds no socket for addr but must see the shared presence.
        assert mgr_b.is_connected(addr) is True
        assert mgr_b.is_focused(addr) is True

        await mgr_a.disconnect(ws, addr)
        assert mgr_b.is_connected(addr) is False
    finally:
        await mgr_a.shutdown()
        await mgr_b.shutdown()


@pytest.mark.anyio
async def test_publish_failure_falls_back_to_local_delivery(addr):
    mgr = await _make_shared_manager()
    try:
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)

        class Boom:
            async def publish(self, *a, **k):
                raise ConnectionError("redis gone")

            async def set(self, *a, **k):
                raise ConnectionError("redis gone")

            async def delete(self, *a, **k):
                raise ConnectionError("redis gone")

            async def aclose(self):
                pass

        mgr._redis = Boom()
        await mgr.send_personal_message({"type": "TEST_EVENT"}, addr)
        # Delivered synchronously via the local fallback, no pub/sub round-trip.
        assert ws.sent == [{"type": "TEST_EVENT"}]
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_local_mode_unchanged_without_redis(addr):
    """REDIS_URL unset ⇒ exactly the historical in-process behavior."""
    mgr = ConnectionManager(redis_url="")
    await mgr.startup()  # no-op
    assert mgr.shared is False

    ws = FakeWebSocket()
    await mgr.connect(ws, addr)
    assert mgr.is_connected(addr) is True
    assert mgr.is_focused(addr) is False

    await mgr.set_focused(ws)
    assert mgr.is_focused(addr) is True

    await mgr.send_personal_message({"type": "TEST_EVENT"}, addr)
    assert ws.sent == [{"type": "TEST_EVENT"}]

    await mgr.disconnect(ws, addr)
    assert mgr.is_connected(addr) is False


@pytest.mark.anyio
async def test_startup_with_unreachable_redis_degrades_to_local(addr):
    mgr = ConnectionManager(redis_url="redis://127.0.0.1:1/0")  # nothing listens
    await mgr.startup()
    assert mgr.shared is False

    ws = FakeWebSocket()
    await mgr.connect(ws, addr)
    await mgr.send_personal_message({"type": "TEST_EVENT"}, addr)
    assert ws.sent == [{"type": "TEST_EVENT"}]
