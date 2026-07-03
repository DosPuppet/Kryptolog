"""WebSocket connection registry, delivery, and presence.

Two modes (audit P0 — lifting the single-process constraint):

- **Local** (default, ``REDIS_URL`` unset): registry, presence, and delivery
  are all in process memory. Correct only while the backend runs as exactly
  ONE process — a message for a user connected to another worker would be lost.

- **Shared** (``REDIS_URL`` set, enabled at app startup): every process
  subscribes to a Redis pub/sub channel and ``send_personal_message``
  *publishes* instead of delivering directly, so the event reaches the user's
  sockets on whichever worker holds them. Presence lives in per-connection
  Redis keys (``focused``/``blurred``) with a TTL refreshed by a heartbeat —
  if a worker dies without cleaning up, its keys expire on their own. Combined
  with Redis-backed rate limits (same ``REDIS_URL``, see dependencies.py),
  this makes multiple workers/instances safe.

If Redis is configured but unreachable, we log and stay in local mode rather
than failing the boot — a single process keeps working, it just must stay single.
"""
import asyncio
import json
import logging
import os
import uuid
from typing import Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger("kryptolog.ws")

FANOUT_CHANNEL = "kryptolog:ws:fanout"
# Presence keys: kryptolog:ws:presence:{address}:{conn_id} -> "focused"|"blurred"
PRESENCE_PREFIX = "kryptolog:ws:presence:"
PRESENCE_TTL_SECONDS = 90        # key lifetime without a heartbeat (worker death)
PRESENCE_HEARTBEAT_SECONDS = 30  # refresh cadence — keep well under the TTL


class ConnectionManager:
    def __init__(self, redis_url: Optional[str] = None):
        # Map: user_address -> List[WebSocket] (Support multiple tabs/devices)
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Track which connections are focused (user is actively viewing the app)
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
        """Refresh the TTL of this worker's presence keys so they outlive the
        heartbeat interval but expire if the worker dies."""
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
    def _presence_key(addr: str, conn_id: str) -> str:
        return f"{PRESENCE_PREFIX}{addr}:{conn_id}"

    async def _presence_write(self, websocket: WebSocket, state: str) -> None:
        conn_id = self._conn_ids.get(websocket)
        addr = self._conn_addr.get(websocket)
        if not (self.shared and conn_id and addr):
            return
        try:
            await self._redis.set(
                self._presence_key(addr, conn_id), state, ex=PRESENCE_TTL_SECONDS
            )
        except Exception as e:
            logger.warning("WS presence write failed: %s", e)

    def _presence_keys(self, addr: str) -> list:
        return list(
            self._redis_sync.scan_iter(match=f"{PRESENCE_PREFIX}{addr}:*", count=100)
        )

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
                await self._redis.delete(self._presence_key(addr, conn_id))
            except Exception as e:
                # The TTL reaps it if this fails.
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
                return bool(self._presence_keys(addr))
            except Exception as e:
                logger.warning("WS presence read failed (%s) — using local state", e)
        return bool(self.active_connections.get(addr))

    def is_focused(self, user_address: str) -> bool:
        """Check if any of the user's connections are focused (actively viewing the app)."""
        addr = user_address.lower()
        if self.shared:
            try:
                keys = self._presence_keys(addr)
                return bool(keys) and "focused" in self._redis_sync.mget(keys)
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
