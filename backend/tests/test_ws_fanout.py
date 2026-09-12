"""Shared WebSocket fan-out + presence (audit P0).

Exercises ConnectionManager's Redis mode: delivery published through pub/sub
(so any worker's sockets are reached), presence tracked in one sorted set per
address scored by expiry (audit L-7), and graceful fallback to in-process
behavior when Redis is absent or fails.

Runs against fakeredis by default; set TEST_REDIS_URL to use a real Redis
(CI does, via its redis service container).
"""

import asyncio
import os
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from websocket_manager import ConnectionManager


@pytest.fixture
def addr():
    """Unique per test: against a real Redis (TEST_REDIS_URL), presence keys
    from one test must not bleed into the next (they carry a 90s TTL)."""
    return f"pqc_fanout_user_{uuid.uuid4().hex}"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class _CommandSpy:
    """Records the Redis commands a call issues (audit L-7).

    Wraps the sync client, the one the push path reads presence through, so
    a test can assert on *how* a lookup was answered and not only on what it
    answered — the scan it replaces returned the right result too.
    """

    def __init__(self, inner):
        self._inner = inner
        self.calls = []

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def record(*args, **kwargs):
            self.calls.append(name)
            return attr(*args, **kwargs)

        return record


class FakeWebSocket:
    """Just enough of a WebSocket for the manager: hashable + send_json + close."""

    def __init__(self):
        self.sent = []
        self.closed = False

    async def send_json(self, message):
        self.sent.append(message)

    async def close(self):
        self.closed = True


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

        assert await _wait_for(lambda: ws1.sent and ws2.sent), (
            "message did not arrive through the pub/sub subscriber"
        )
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
        # No presence entries left behind.
        assert mgr._presence_states(addr) == []
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_lookup_does_not_walk_the_keyspace(addr):
    """Audit L-7: the push path must not SCAN.

    `is_focused` runs once per push, so once per recipient of a group
    message. It used to scan the whole keyspace for `presence:{addr}:*`;
    it must now be a single keyed read.
    """
    mgr = await _make_shared_manager()
    try:
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)
        await mgr.set_focused(ws)

        spy = _CommandSpy(mgr._redis_sync)
        mgr._redis_sync = spy
        assert mgr.is_focused(addr) is True

        assert not [c for c in spy.calls if c in ("scan", "scan_iter", "keys")], (
            f"presence lookup walked the keyspace: {spy.calls}"
        )
        assert len(spy.calls) == 1, f"expected one keyed read, got {spy.calls}"
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_lookup_cost_is_independent_of_other_users(addr):
    """The scan was O(keyspace): every other user's presence slowed a push.

    A thousand unrelated presence keys must be invisible to this address —
    same single read, same answer.
    """
    mgr = await _make_shared_manager()
    try:
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)

        # Noise gets a TTL: against a real Redis (TEST_REDIS_URL) this would
        # otherwise be a thousand keys left behind on every run — and the next
        # run of THIS test would be measuring them.
        pipe = mgr._redis_sync.pipeline()
        for i in range(1000):
            key = mgr._presence_key(f"{addr}_noise_{i}")
            pipe.zadd(key, {f"c{i}:focused": time.time() + 60})
            pipe.expire(key, 60)
        pipe.execute()

        spy = _CommandSpy(mgr._redis_sync)
        mgr._redis_sync = spy
        assert mgr.is_connected(addr) is True
        assert mgr.is_focused(addr) is False, "read another user's presence"
        assert len(spy.calls) == 2, f"one read per query expected, got {spy.calls}"
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_entry_from_a_dead_worker_is_not_present(addr):
    """A worker that dies mid-connection stops refreshing its score.

    With per-connection keys this was Redis's own TTL. The set has one
    expiry for the whole key, so the score has to carry it instead —
    otherwise a crashed worker would keep a user "focused" (and silently
    swallow their push notifications) for as long as any other connection
    of theirs kept the key alive.
    """
    mgr = await _make_shared_manager()
    try:
        key = mgr._presence_key(addr)
        mgr._redis_sync.zadd(key, {"deadconn:focused": time.time() - 1})

        assert mgr.is_connected(addr) is False
        assert mgr.is_focused(addr) is False

        # A live connection on the same address must not resurrect it.
        ws = FakeWebSocket()
        await mgr.connect(ws, addr)
        assert mgr.is_connected(addr) is True
        assert mgr.is_focused(addr) is False, "stale entry counted as focused"
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_tracks_each_connection_separately(addr):
    """Two tabs: focus follows whichever one is in front, and closing one
    does not mark the user gone."""
    mgr = await _make_shared_manager()
    try:
        ws1, ws2 = FakeWebSocket(), FakeWebSocket()
        await mgr.connect(ws1, addr)
        await mgr.connect(ws2, addr)
        assert sorted(mgr._presence_states(addr)) == ["blurred", "blurred"]

        await mgr.set_focused(ws2)
        assert mgr.is_focused(addr) is True
        # The state replaces the entry, it does not add one.
        assert sorted(mgr._presence_states(addr)) == ["blurred", "focused"]

        await mgr.disconnect(ws2, addr)
        assert mgr.is_connected(addr) is True
        assert mgr.is_focused(addr) is False

        await mgr.disconnect(ws1, addr)
        assert mgr.is_connected(addr) is False
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


# ── Hanging up on a deleted account ─────────────────────────────────────────
#
# A database write does not close a socket that is already open. The deleted
# identity cannot RECONNECT — user_for_token refuses a deleted row and the WS
# handshake goes through the same dependency — so what these cover is the
# window where their current tabs would otherwise keep receiving other people's
# messages until something happened to reload them.


@pytest.mark.anyio
async def test_deleting_an_account_closes_its_sockets_and_clears_presence(addr):
    mgr = await _make_shared_manager()
    try:
        first, second = FakeWebSocket(), FakeWebSocket()
        await mgr.connect(first, addr)
        await mgr.connect(second, addr)
        assert mgr.is_connected(addr) is True

        await mgr.close_address(addr)

        assert first.closed and second.closed, "every socket for the address, not just the first"
        assert mgr.active_connections.get(addr) in (None, [])
        assert mgr.is_connected(addr) is False
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_presence_is_purged_even_for_connections_this_worker_never_held(addr):
    """Why close_address deletes the whole presence key rather than relying on
    disconnect().

    disconnect() removes the entry for a socket THIS worker holds. An entry left
    by a worker that died still sits in the set until its score expires, and the
    push path reads that set — so a deleted account would look online for up to
    the 90s TTL and be sent other people's notifications.
    """
    mgr = await _make_shared_manager()
    try:
        await mgr._redis.zadd(
            mgr._presence_key(addr), {"ghost-connection:focused": time.time() + 90}
        )
        assert mgr.is_connected(addr) is True

        await mgr.close_address(addr)

        assert mgr._presence_states(addr) == []
        assert mgr.is_connected(addr) is False
    finally:
        await mgr.shutdown()


@pytest.mark.anyio
async def test_the_hangup_reaches_sockets_held_by_another_worker(addr):
    """The reason it goes through pub/sub at all.

    In shared mode the deleted user's sockets may be on a worker that knows
    nothing about the request that deleted them, so a local-only close would
    leave those tabs live.
    """
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
        await mgr_b.connect(ws, addr)

        # Worker A handles the deletion and holds no socket for this address.
        await mgr_a.close_address(addr)

        assert await _wait_for(lambda: ws.closed), "worker B never hung up"
        # It is told why before the socket goes, so a client on an older build
        # (which will not be closed for it) can still log itself out.
        assert ws.sent and ws.sent[-1]["type"] == "ACCOUNT_DELETED"
    finally:
        await mgr_a.shutdown()
        await mgr_b.shutdown()


@pytest.mark.anyio
async def test_closing_works_without_redis(addr):
    """Single-process mode is the default for a dev box, and the deletion
    endpoint calls this unconditionally."""
    mgr = ConnectionManager(redis_url=None)
    assert not mgr.shared

    ws = FakeWebSocket()
    await mgr.connect(ws, addr)
    await mgr.close_address(addr)

    assert ws.closed
    assert mgr.active_connections.get(addr) in (None, [])
