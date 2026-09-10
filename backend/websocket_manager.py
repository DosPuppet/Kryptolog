"""WebSocket connection registry, delivery, and presence.

Two modes (audit P0 — lifting the single-process constraint):

- **Local** (default, ``REDIS_URL`` unset): registry, presence, and delivery
  are all in process memory. Correct only while the backend runs as exactly
  ONE process — a message for a user connected to another worker would be lost.

- **Shared** (``REDIS_URL`` set, enabled at app startup): every process
  subscribes to a Redis pub/sub channel and ``send_personal_message``
  *publishes* instead of delivering directly, so the event reaches the user's
  sockets on whichever worker holds them. Presence lives in ONE sorted set per
  address, holding ``{conn_id}:{state}`` scored by the moment the entry goes
  stale; a heartbeat pushes the score forward, so if a worker dies without
  cleaning up its connections simply fall out of range. Combined with
  Redis-backed rate limits (same ``REDIS_URL``, see dependencies.py), this
  makes multiple workers/instances safe.

If Redis is configured but unreachable, we log and stay in local mode rather
than failing the boot — a single process keeps working, it just must stay single.
"""
import asyncio
import json
import logging
import os
import time
import uuid
from typing import Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger("kryptolog.ws")

FANOUT_CHANNEL = "kryptolog:ws:fanout"
# Presence: ONE sorted set per address (audit L-7).
#   key    kryptolog:ws:presence:{address}
#   member "{conn_id}:{state}", state ∈ PRESENCE_STATES
#   score  epoch second at which that connection goes stale
# Scoring the members rather than giving each its own key is what lets a
# presence lookup be a single keyed read instead of a keyspace walk, while
# keeping per-connection (not per-user) expiry.
PRESENCE_PREFIX = "kryptolog:ws:presence:"
PRESENCE_STATES = ("focused", "blurred")
PRESENCE_TTL_SECONDS = 90        # entry lifetime without a heartbeat (worker death)
PRESENCE_HEARTBEAT_SECONDS = 30  # refresh cadence — keep well under the TTL


class ConnectionManager:
    def __init__(self, redis_url: Optional[str] = None):
        # A list per address: one identity may hold several tabs or devices.
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Focused = the app is in front of the user, so a push would be noise.
        self.focused_connections: Set[WebSocket] = set()
        # Shared mode: per-socket id + address for the Redis presence keys
        self._conn_ids: Dict[WebSocket, str] = {}
        self._conn_addr: Dict[WebSocket, str] = {}
        self._redis_url = redis_url if redis_url is not None else os.getenv("REDIS_URL")
        self._redis = None        # async client: pub/sub + presence writes
        self._redis_sync = None   # sync client: presence reads from sync code (push path)
        self._pubsub = None
        self._listener_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    # ---------- lifecycle ----------

    @property
    def shared(self) -> bool:
        """True when delivery/presence are shared through Redis."""
        return self._redis is not None

    async def startup(self, redis_client=None, redis_sync_client=None) -> None:
        """Enable shared mode. No-op without REDIS_URL (local mode).

        Clients can be injected (tests use fakeredis); otherwise they are
        created from REDIS_URL."""
        if redis_client is None and not self._redis_url:
            return
        try:
            if redis_client is None:
                import redis as redis_pkg
                import redis.asyncio as aioredis
                redis_client = aioredis.Redis.from_url(self._redis_url, decode_responses=True)
                redis_sync_client = redis_pkg.Redis.from_url(self._redis_url, decode_responses=True)
            await redis_client.ping()
            pubsub = redis_client.pubsub()
            await pubsub.subscribe(FANOUT_CHANNEL)
            self._redis = redis_client
            self._redis_sync = redis_sync_client
            self._pubsub = pubsub
            self._listener_task = asyncio.create_task(self._listen(pubsub))
            self._heartbeat_task = asyncio.create_task(self._heartbeat())
            logger.info("WebSocket fan-out: shared mode enabled (Redis pub/sub)")
        except Exception as e:
            logger.warning(
                "WebSocket fan-out: Redis unavailable (%s) — staying in in-process "
                "mode. Keep the backend to a SINGLE process.", e,
            )
            self._redis = None
            self._redis_sync = None

    async def shutdown(self) -> None:
        for task in (self._listener_task, self._heartbeat_task):
            if task:
                task.cancel()
        self._listener_task = None
        self._heartbeat_task = None
        for closer in (self._pubsub, self._redis):
            if closer is not None:
                try:
                    await closer.aclose()
                except Exception:
                    pass
        self._pubsub = None
        self._redis = None
        self._redis_sync = None

    # ---------- background tasks (shared mode) ----------

    async def _listen(self, pubsub) -> None:
        """Deliver fan-out events published by any worker (including this one)
        to the sockets THIS worker holds."""
        try:
            async for item in pubsub.listen():
                if item.get("type") != "message":
                    continue
                try:
                    event = json.loads(item["data"])
                    await self._deliver_local(event["message"], event["addr"])
                except Exception as e:
                    logger.warning("WS fan-out: ignoring malformed event: %s", e)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("WS fan-out listener stopped: %s", e)

    async def _heartbeat(self) -> None:
        """Push the expiry score of this worker's connections forward so they
        outlive the heartbeat interval but go stale if the worker dies."""
        try:
            while True:
                await asyncio.sleep(PRESENCE_HEARTBEAT_SECONDS)
                for ws in list(self._conn_ids):
                    state = "focused" if ws in self.focused_connections else "blurred"
                    await self._presence_write(ws, state)
        except asyncio.CancelledError:
            pass

    # ---------- presence (shared mode helpers) ----------

    @staticmethod
    def _presence_key(addr: str) -> str:
        return f"{PRESENCE_PREFIX}{addr}"

    @staticmethod
    def _presence_member(conn_id: str, state: str) -> str:
        """conn_id is a uuid4 hex, so it never contains the separator and the
        state splits back off unambiguously."""
        return f"{conn_id}:{state}"

    @classmethod
    def _presence_members(cls, conn_id: str) -> List[str]:
        """Every spelling one connection can have in the set.

        Its state is part of the member, so a focus change has to remove the
        previous spelling — and the caller does not always know which one it
        was (a heartbeat after a missed write, a reconnect).
        """
        return [cls._presence_member(conn_id, state) for state in PRESENCE_STATES]

    async def _presence_write(self, websocket: WebSocket, state: str) -> None:
        conn_id = self._conn_ids.get(websocket)
        addr = self._conn_addr.get(websocket)
        if not (self.shared and conn_id and addr):
            return
        key = self._presence_key(addr)
        now = time.time()
        try:
            # One round trip: replace this connection's entry, drop the ones
            # nobody is refreshing any more, and re-arm the whole-key backstop.
            pipe = self._redis.pipeline()
            pipe.zrem(key, *self._presence_members(conn_id))
            pipe.zadd(
                key,
                {self._presence_member(conn_id, state): now + PRESENCE_TTL_SECONDS},
            )
            # A worker that dies stops refreshing its scores; without this the
            # set would keep every connection it ever held, since each new
            # socket gets a fresh conn_id.
            pipe.zremrangebyscore(key, "-inf", now)
            # Reads already ignore stale members, so this only stops an
            # abandoned address from occupying a key forever.
            pipe.expire(key, PRESENCE_TTL_SECONDS)
            await pipe.execute()
        except Exception as e:
            logger.warning("WS presence write failed: %s", e)

    def _presence_states(self, addr: str) -> List[str]:
        """The states of `addr`'s live connections, in ONE keyed read.

        This was `scan_iter(match=f"{PRESENCE_PREFIX}{addr}:*")` — a walk of
        the entire keyspace, run on every push and therefore once per
        recipient of a group message (audit L-7). Now the address names the
        key directly and the score range does the expiry filtering, so cost
        depends on that one user's connection count, not on how much is in
        Redis.
        """
        return [
            member.rpartition(":")[2]
            for member in self._redis_sync.zrangebyscore(
                self._presence_key(addr), time.time(), "+inf"
            )
        ]

    # ---------- registry ----------

    async def connect(self, websocket: WebSocket, user_address: str):
        # WebSocket is already accepted in main.py
        if user_address not in self.active_connections:
            self.active_connections[user_address] = []
        self.active_connections[user_address].append(websocket)
        if self.shared:
            self._conn_ids[websocket] = uuid.uuid4().hex
            self._conn_addr[websocket] = user_address
            await self._presence_write(websocket, "blurred")

    async def disconnect(self, websocket: WebSocket, user_address: Optional[str]):
        self.focused_connections.discard(websocket)
        if user_address in self.active_connections:
            if websocket in self.active_connections[user_address]:
                self.active_connections[user_address].remove(websocket)
            if not self.active_connections[user_address]:
                del self.active_connections[user_address]
        conn_id = self._conn_ids.pop(websocket, None)
        addr = self._conn_addr.pop(websocket, None)
        if self.shared and conn_id and addr:
            try:
                await self._redis.zrem(
                    self._presence_key(addr), *self._presence_members(conn_id)
                )
            except Exception as e:
                # The score expiry reaps it if this fails.
                logger.warning("WS presence delete failed: %s", e)

    async def set_focused(self, websocket: WebSocket):
        self.focused_connections.add(websocket)
        await self._presence_write(websocket, "focused")

    async def set_blurred(self, websocket: WebSocket):
        self.focused_connections.discard(websocket)
        await self._presence_write(websocket, "blurred")

    # ---------- presence queries (sync: called from the push path) ----------

    def is_connected(self, user_address: str) -> bool:
        """Check if a user has any active WebSocket connections (i.e. app is open)."""
        addr = user_address.lower()
        if self.shared:
            try:
                return bool(self._presence_states(addr))
            except Exception as e:
                logger.warning("WS presence read failed (%s) — using local state", e)
        return bool(self.active_connections.get(addr))

    def is_focused(self, user_address: str) -> bool:
        """Check if any of the user's connections are focused (actively viewing the app)."""
        addr = user_address.lower()
        if self.shared:
            try:
                return "focused" in self._presence_states(addr)
            except Exception as e:
                logger.warning("WS presence read failed (%s) — using local state", e)
        connections = self.active_connections.get(addr, [])
        return any(ws in self.focused_connections for ws in connections)

    # ---------- delivery ----------

    async def send_personal_message(self, message: dict, user_address: str):
        if self.shared:
            try:
                await self._redis.publish(
                    FANOUT_CHANNEL,
                    json.dumps({"addr": user_address, "message": message}),
                )
                # Local sockets are served when the event comes back through
                # the subscriber, same as on every other worker.
                return
            except Exception as e:
                logger.warning(
                    "WS fan-out publish failed (%s) — delivering to local sockets only", e
                )
        await self._deliver_local(message, user_address)

    async def _deliver_local(self, message: dict, user_address: str):
        for connection in self.active_connections.get(user_address, []):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning("Sending WS message failed: %s", e)

manager = ConnectionManager()
