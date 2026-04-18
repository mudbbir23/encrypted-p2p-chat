"""
SurrealDB Manager — real-time message storage and live query subscriptions.

SurrealDB is chosen for its live query push capabilities:
when a message is inserted with recipient_id = Bob, SurrealDB pushes
the record to the server's subscriber without polling.

All message CRUD, room management, and presence operations live here.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable, Coroutine
from datetime import datetime, timezone
from typing import Any, Optional

from surrealdb import AsyncSurrealDB as AsyncSurreal

from app.config import settings

logger = logging.getLogger(__name__)


class SurrealDBManager:
    """
    Async SurrealDB client manager.

    connect() must be called during app startup. All methods are async
    and use the single persistent connection.
    """

    def __init__(self) -> None:
        self._client: Optional[AsyncSurreal] = None
        self._available: bool = False
        self._live_query_handlers: dict[str, Callable] = {}

    async def connect(self) -> None:
        """Establish WebSocket connection to SurrealDB. Non-fatal on failure."""
        try:
            self._client = AsyncSurreal(settings.SURREAL_URL)
            await self._client.connect()
            await self._client.sign_in(
                username=settings.SURREAL_USER,
                password=settings.SURREAL_PASS,
            )
            await self._client.use(
                namespace=settings.SURREAL_NS,
                database=settings.SURREAL_DB,
            )
            await self._initialize_schema()
            self._available = True
            logger.info("SurrealDB connected to %s", settings.SURREAL_URL)
        except Exception as exc:
            self._available = False
            logger.warning("SurrealDB unavailable: %s", exc)

    async def disconnect(self) -> None:
        """Close the SurrealDB connection."""
        if self._client:
            try:
                await self._client.close()
            except Exception:
                pass
            self._client = None
            self._available = False
            logger.info("SurrealDB disconnected")

    @property
    def client(self) -> Optional[AsyncSurreal]:
        return self._client if self._available else None

    async def _initialize_schema(self) -> None:
        """
        Define SurrealDB tables and indexes if they don't already exist.
        SurrealDB uses schema-less mode by default; we define field types for validation.
        """
        schema_queries = [
            # Messages table
            """
            DEFINE TABLE IF NOT EXISTS messages SCHEMAFULL;
            DEFINE FIELD IF NOT EXISTS sender_id ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS sender_username ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS recipient_id ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS room_id ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS ciphertext ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS nonce ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS header ON TABLE messages TYPE string;
            DEFINE FIELD IF NOT EXISTS ephemeral_pub_key ON TABLE messages TYPE option<string>;
            DEFINE FIELD IF NOT EXISTS created_at ON TABLE messages TYPE datetime;
            DEFINE INDEX IF NOT EXISTS idx_messages_recipient ON TABLE messages COLUMNS recipient_id;
            DEFINE INDEX IF NOT EXISTS idx_messages_room ON TABLE messages COLUMNS room_id;
            """,
            # Presence table
            """
            DEFINE TABLE IF NOT EXISTS presence SCHEMAFULL;
            DEFINE FIELD IF NOT EXISTS user_id ON TABLE presence TYPE string;
            DEFINE FIELD IF NOT EXISTS status ON TABLE presence TYPE string;
            DEFINE FIELD IF NOT EXISTS last_seen ON TABLE presence TYPE datetime;
            DEFINE INDEX IF NOT EXISTS idx_presence_user ON TABLE presence COLUMNS user_id UNIQUE;
            """,
            # Rooms table
            """
            DEFINE TABLE IF NOT EXISTS rooms SCHEMAFULL;
            DEFINE FIELD IF NOT EXISTS name ON TABLE rooms TYPE option<string>;
            DEFINE FIELD IF NOT EXISTS is_group ON TABLE rooms TYPE bool;
            DEFINE FIELD IF NOT EXISTS participant_ids ON TABLE rooms TYPE array<string>;
            DEFINE FIELD IF NOT EXISTS created_by ON TABLE rooms TYPE string;
            DEFINE FIELD IF NOT EXISTS created_at ON TABLE rooms TYPE datetime;
            DEFINE FIELD IF NOT EXISTS last_message_at ON TABLE rooms TYPE option<datetime>;
            """,
        ]

        for query in schema_queries:
            try:
                await self.client.query(query)
            except Exception as e:
                logger.warning("Schema initialization warning (may be safe): %s", e)

    # -----------------------------------------------------------------------
    # Message operations
    # -----------------------------------------------------------------------

    async def create_message(
        self,
        sender_id: str,
        sender_username: str,
        recipient_id: str,
        room_id: str,
        ciphertext: str,
        nonce: str,
        header: str,
        ephemeral_pub_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Store an encrypted message. No-op (returns empty) if SurrealDB unavailable."""
        if not self._available or not self._client:
            return {"id": str(uuid.uuid4()), "room_id": room_id}
        result = await self._client.create(
            "messages",
            {
                "sender_id": sender_id,
                "sender_username": sender_username,
                "recipient_id": recipient_id,
                "room_id": room_id,
                "ciphertext": ciphertext,
                "nonce": nonce,
                "header": header,
                "ephemeral_pub_key": ephemeral_pub_key,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        if isinstance(result, list) and result:
            return result[0]
        return result or {}

    async def get_messages_for_room(
        self,
        room_id: str,
        limit: int = 50,
        before_timestamp: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve paginated messages for a room. Returns [] if SurrealDB unavailable."""
        if not self._available or not self._client:
            return []
        if before_timestamp:
            query = """
                SELECT * FROM messages
                WHERE room_id = $room_id AND created_at < $before
                ORDER BY created_at DESC
                LIMIT $limit
            """
            result = await self._client.query(
                query,
                {
                    "room_id": room_id,
                    "before": before_timestamp.isoformat(),
                    "limit": limit,
                },
            )
        else:
            query = """
                SELECT * FROM messages
                WHERE room_id = $room_id
                ORDER BY created_at DESC
                LIMIT $limit
            """
            result = await self._client.query(
                query,
                {"room_id": room_id, "limit": limit},
            )

        if result and isinstance(result, list):
            first = result[0]
            if isinstance(first, dict) and "result" in first:
                return first["result"] or []
            return result
        return []

    # -----------------------------------------------------------------------
    # Live query subscriptions
    # -----------------------------------------------------------------------

    async def live_messages_for_user(
        self,
        user_id: str,
        callback: Callable[[dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> str:
        """Subscribe to real-time messages. Returns empty string if SurrealDB unavailable."""
        if not self._available or not self._client:
            return ""
        query = f"LIVE SELECT * FROM messages WHERE recipient_id = '{user_id}'"
        live_id = await self._client.live(query, callback)
        logger.debug("Live query started for user %s: %s", user_id, live_id)
        self._live_query_handlers[str(live_id)] = callback
        return str(live_id)

    async def kill_live_query(self, live_query_id: str) -> None:
        """Cancel a live query subscription."""
        if not self._available or not self._client or not live_query_id:
            return
        try:
            await self._client.kill(live_query_id)
            self._live_query_handlers.pop(live_query_id, None)
        except Exception as e:
            logger.warning("Error killing live query %s: %s", live_query_id, e)

    # -----------------------------------------------------------------------
    # Presence operations
    # -----------------------------------------------------------------------

    async def set_user_online(self, user_id: str) -> None:
        if not self._available or not self._client:
            return
        try:
            await self._client.query(
                "UPSERT presence SET user_id=$u, status='online', last_seen=time::now() WHERE user_id=$u",
                {"u": user_id},
            )
        except Exception as e:
            logger.warning("set_user_online: %s", e)

    async def set_user_offline(self, user_id: str) -> None:
        if not self._available or not self._client:
            return
        try:
            await self._client.query(
                "UPSERT presence SET user_id=$u, status='offline', last_seen=time::now() WHERE user_id=$u",
                {"u": user_id},
            )
        except Exception as e:
            logger.warning("set_user_offline: %s", e)

    async def get_user_presence(self, user_id: str) -> Optional[dict[str, Any]]:
        if not self._available or not self._client:
            return None
        result = await self._client.query(
            "SELECT * FROM presence WHERE user_id = $user_id LIMIT 1",
            {"user_id": user_id},
        )
        if result and isinstance(result, list):
            first = result[0]
            if isinstance(first, dict) and "result" in first:
                rows = first["result"]
                return rows[0] if rows else None
        return None

    # -----------------------------------------------------------------------
    # Room operations
    # -----------------------------------------------------------------------

    async def create_room(
        self,
        room_id: str,
        name: Optional[str],
        is_group: bool,
        participant_ids: list[str],
        created_by: str,
    ) -> dict[str, Any]:
        if not self._available or not self._client:
            return {"id": room_id, "participant_ids": participant_ids}
        result = await self._client.create(
            f"rooms:{room_id}",
            {
                "name": name,
                "is_group": is_group,
                "participant_ids": participant_ids,
                "created_by": created_by,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_message_at": None,
            },
        )
        return result or {}

    async def get_rooms_for_user(self, user_id: str) -> list[dict[str, Any]]:
        if not self._available or not self._client:
            return []
        result = await self._client.query(
            "SELECT * FROM rooms WHERE $user_id INSIDE participant_ids ORDER BY last_message_at DESC",
            {"user_id": user_id},
        )
        if result and isinstance(result, list):
            first = result[0]
            if isinstance(first, dict) and "result" in first:
                return first["result"] or []
        return []

    async def update_room_last_message(self, room_id: str) -> None:
        if not self._available or not self._client:
            return
        try:
            await self._client.query(
                "UPDATE $room_id SET last_message_at = time::now()",
                {"room_id": f"rooms:{room_id}"},
            )
        except Exception as e:
            logger.warning("update_room_last_message: %s", e)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

surreal_db = SurrealDBManager()
