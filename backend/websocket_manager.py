from fastapi import WebSocket
from typing import Dict, List, Set

class ConnectionManager:
    def __init__(self):
        # Map: user_address -> List[WebSocket] (Support multiple tabs/devices)
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Track which connections are focused (user is actively viewing the app)
        self.focused_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket, user_address: str):
        # WebSocket is already accepted in main.py
        if user_address not in self.active_connections:
            self.active_connections[user_address] = []
        self.active_connections[user_address].append(websocket)

    def disconnect(self, websocket: WebSocket, user_address: str):
        self.focused_connections.discard(websocket)
        if user_address in self.active_connections:
            if websocket in self.active_connections[user_address]:
                self.active_connections[user_address].remove(websocket)
            if not self.active_connections[user_address]:
                del self.active_connections[user_address]

    def set_focused(self, websocket: WebSocket):
        self.focused_connections.add(websocket)

    def set_blurred(self, websocket: WebSocket):
        self.focused_connections.discard(websocket)

    def is_connected(self, user_address: str) -> bool:
        """Check if a user has any active WebSocket connections (i.e. app is open)."""
        addr = user_address.lower()
        return bool(self.active_connections.get(addr))

    def is_focused(self, user_address: str) -> bool:
        """Check if any of the user's connections are focused (actively viewing the app)."""
        addr = user_address.lower()
        connections = self.active_connections.get(addr, [])
        return any(ws in self.focused_connections for ws in connections)

    async def send_personal_message(self, message: dict, user_address: str):
        if user_address in self.active_connections:
            for connection in self.active_connections[user_address]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"ERROR: Sending WS message failed: {e}")

manager = ConnectionManager()

