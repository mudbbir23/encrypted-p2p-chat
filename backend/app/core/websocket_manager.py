"""
WebSocket Connection Manager.

Manages all active WebSocket connections, organized by user_id.
Handles message fan-out, connection limits, heartbeats, and graceful cleanup.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app.config import settings
from app.core.exceptions import ConnectionLimitExceededError

logger = logging.getLogger(__name__)


class WebSocketConnection:
    """Wraps a FastAPI WebSocket with extra metadata."""

    def __init__(self, websocket: WebSocket, user_id: uuid.UUID, username: str) -> None:
        self.websocket = websocket
        self.user_id = user_id
        self.username = username
        self.connected_at = datetime.now(timezone.utc)

    async def send_json(self, data: dict[str, Any]) -> None:
        """Send JSON data; silently ignore errors on closed connections."""
        try:
            await self.websocket.send_text(json.dumps(data, default=str))
        except Exception:
            pass  # Connection may have closed; cleanup handled by the main loop


class WebSocketManager:
    """
    Manages a registry of active WebSocket connections keyed by user_id.

    Thread safety: asyncio is single-threaded, but we document that
    add/remove must always be awaited on the event loop.
    """

    def __init__(self) -> None:
        # user_id → list of active connections (multiple tabs/devices)
        self._connections: dict[uuid.UUID, list[WebSocketConnection]] = defaultdict(list)

    # -----------------------------------------------------------------------
    # Connection management
    # -----------------------------------------------------------------------

    def add_connection(self, conn: WebSocketConnection) -> None:
        """Register a new WebSocket connection for a user."""
        user_conns = self._connections[conn.user_id]

        if len(user_conns) >= settings.WS_MAX_CONNECTIONS_PER_USER:
            raise ConnectionLimitExceededError(
                f"Maximum of {settings.WS_MAX_CONNECTIONS_PER_USER} simultaneous WebSocket "
                f"connections reached for user {conn.user_id}."
            )

        user_conns.append(conn)
        logger.info(
            "WebSocket connected: user=%s connections=%d",
            conn.user_id,
            len(user_conns),
        )

    def remove_connection(self, conn: WebSocketConnection) -> None:
        """Unregister a WebSocket connection."""
        user_conns = self._connections.get(conn.user_id, [])
        if conn in user_conns:
            user_conns.remove(conn)
        if not user_conns:
            self._connections.pop(conn.user_id, None)
        logger.info(
            "WebSocket disconnected: user=%s remaining=%d",
            conn.user_id,
            len(user_conns),
        )

    def is_online(self, user_id: uuid.UUID) -> bool:
        """Return True if the user has at least one active connection."""
        return bool(self._connections.get(user_id))

    def get_online_user_ids(self) -> list[uuid.UUID]:
        """Return list of user IDs with at least one active connection."""
        return list(self._connections.keys())

    # -----------------------------------------------------------------------
    # Message sending
    # -----------------------------------------------------------------------

    async def send_to_user(
        self, user_id: uuid.UUID, message: dict[str, Any]
    ) -> bool:
        """
        Send a message to all connections for a user.

        Returns True if the user has at least one active connection,
        False if they are offline (message should be queued/stored).
        """
        conns = self._connections.get(user_id)
        if not conns:
            return False

        tasks = [conn.send_json(message) for conn in list(conns)]
        await asyncio.gather(*tasks, return_exceptions=True)
        return True

    async def broadcast_to_users(
        self, user_ids: list[uuid.UUID], message: dict[str, Any]
    ) -> None:
        """Broadcast a message to multiple users concurrently."""
        tasks = [self.send_to_user(uid, message) for uid in user_ids]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def send_error(
        self, conn: WebSocketConnection, code: str, message: str
    ) -> None:
        """Send an error frame to a specific connection."""
        await conn.send_json({"type": "error", "code": code, "message": message})

    # -----------------------------------------------------------------------
    # Heartbeat
    # -----------------------------------------------------------------------

    async def send_heartbeat(self, conn: WebSocketConnection) -> None:
        """Send a heartbeat pong to a specific connection."""
        await conn.send_json({
            "type": "pong",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # -----------------------------------------------------------------------
    # Stats
    # -----------------------------------------------------------------------

    @property
    def total_connections(self) -> int:
        return sum(len(conns) for conns in self._connections.values())

    @property
    def total_users_online(self) -> int:
        return len(self._connections)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

ws_manager = WebSocketManager()
