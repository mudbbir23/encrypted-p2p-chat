"""
WebSocket Service — handles the main WebSocket lifecycle for a connected user.

This is the heart of the real-time layer:
1. Authenticates the user via query param token (session-based)
2. Registers the connection with WebSocketManager
3. Starts a SurrealDB live query for the user's incoming messages
4. Enters the message processing loop reading from the WebSocket
5. Routes inbound messages to the correct handlers
6. Cleans up on disconnect
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from app.config import settings
from app.core.exceptions import AppError
from app.core.surreal_manager import surreal_db, SurrealDBManager
from app.core.websocket_manager import WebSocketConnection, WebSocketManager, ws_manager
from app.services.message_service import message_service

logger = structlog.get_logger(__name__)


class WebSocketService:
    """
    Manages the lifecycle of a single WebSocket connection.
    Instantiated per connection.
    """

    def __init__(
        self,
        websocket: WebSocket,
        user_id: uuid.UUID,
        username: str,
    ) -> None:
        self.ws = websocket
        self.user_id = user_id
        self.username = username
        self.conn: WebSocketConnection | None = None
        self._live_query_id: str | None = None
        self._heartbeat_task: asyncio.Task | None = None

    async def run(self) -> None:
        """
        Main entry point: accept the WebSocket and enter the message loop.
        """
        await self.ws.accept()

        self.conn = WebSocketConnection(
            websocket=self.ws,
            user_id=self.user_id,
            username=self.username,
        )

        # Register connection
        ws_manager.add_connection(self.conn)

        # Mark user as online in SurrealDB
        await surreal_db.set_user_online(str(self.user_id))

        # Start SurrealDB live query for incoming messages
        try:
            self._live_query_id = await surreal_db.live_messages_for_user(
                user_id=str(self.user_id),
                callback=self._on_surreal_message,
            )
        except Exception as e:
            logger.warning("Live query failed to start: %s", e)

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info("WebSocket session started for user %s", self.user_id)

        try:
            await self._message_loop()
        except WebSocketDisconnect:
            logger.info("WebSocket disconnected cleanly for user %s", self.user_id)
        except Exception as e:
            logger.exception("WebSocket error for user %s: %s", self.user_id, e)
        finally:
            await self._cleanup()

    async def _message_loop(self) -> None:
        """
        Read messages from the WebSocket until disconnected.
        Routes each message to the appropriate handler.
        """
        assert self.conn is not None

        while True:
            try:
                raw = await asyncio.wait_for(
                    self.ws.receive_text(),
                    timeout=settings.WS_HEARTBEAT_INTERVAL * 2,
                )
            except asyncio.TimeoutError:
                # No message for too long — send heartbeat and continue
                await ws_manager.send_heartbeat(self.conn)
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws_manager.send_error(self.conn, "invalid_json", "Message is not valid JSON")
                continue

            await self._dispatch(data)

    async def _dispatch(self, data: dict[str, Any]) -> None:
        """Route an inbound WebSocket message to the correct handler."""
        msg_type = data.get("type")

        handlers = {
            settings.WS_MESSAGE_TYPE_ENCRYPTED: self._handle_encrypted_message,
            settings.WS_MESSAGE_TYPE_TYPING: self._handle_typing,
            settings.WS_MESSAGE_TYPE_PRESENCE: self._handle_presence,
            settings.WS_MESSAGE_TYPE_RECEIPT: self._handle_receipt,
            settings.WS_MESSAGE_TYPE_HEARTBEAT: self._handle_heartbeat,
        }

        handler = handlers.get(msg_type)
        if handler is None:
            await ws_manager.send_error(
                self.conn,
                "unknown_message_type",
                f"Unknown message type: {msg_type}",
            )
            return

        try:
            await handler(data)
        except AppError as e:
            await ws_manager.send_error(self.conn, e.error_code, e.message)
        except Exception as e:
            logger.exception("Handler error for type %s: %s", msg_type, e)
            await ws_manager.send_error(self.conn, "handler_error", "Message could not be processed")

    # -----------------------------------------------------------------------
    # Message handlers
    # -----------------------------------------------------------------------

    async def _handle_encrypted_message(self, data: dict[str, Any]) -> None:
        """Route an encrypted message to the recipient."""
        try:
            recipient_id = uuid.UUID(data["recipient_id"])
            room_id = uuid.UUID(data["room_id"])
            ciphertext = str(data["ciphertext"])
            nonce = str(data["nonce"])
            header = str(data["header"])
            temp_id = data.get("temp_id")
            ephemeral_pub_key = data.get("ephemeral_pub_key")
        except (KeyError, ValueError) as e:
            from app.core.exceptions import InvalidMessageFormatError
            raise InvalidMessageFormatError(f"Missing required field: {e}") from e

        await message_service.store_and_deliver(
            sender_id=self.user_id,
            sender_username=self.username,
            recipient_id=recipient_id,
            room_id=room_id,
            ciphertext=ciphertext,
            nonce=nonce,
            header=header,
            temp_id=temp_id,
            ephemeral_pub_key=ephemeral_pub_key,
        )

    async def _handle_typing(self, data: dict[str, Any]) -> None:
        """Broadcast typing indicator to room participants."""
        try:
            room_id = uuid.UUID(data["room_id"])
            is_typing = bool(data.get("is_typing", False))
        except (KeyError, ValueError):
            return

        # Get room participants from SurrealDB
        rooms = await surreal_db.get_rooms_for_user(str(self.user_id))
        target_room = next((r for r in rooms if str(r.get("id", "")) == str(room_id)), None)
        if target_room is None:
            return

        payload = {
            "type": settings.WS_MESSAGE_TYPE_TYPING,
            "user_id": str(self.user_id),
            "username": self.username,
            "room_id": str(room_id),
            "is_typing": is_typing,
        }

        participant_ids = target_room.get("participant_ids", [])
        for pid in participant_ids:
            if pid != str(self.user_id):
                try:
                    await ws_manager.send_to_user(uuid.UUID(pid), payload)
                except ValueError:
                    pass

    async def _handle_presence(self, data: dict[str, Any]) -> None:
        """Update presence status."""
        status = data.get("status", "online")
        if status not in ("online", "away", "busy"):
            status = "online"
        await surreal_db.set_user_online(str(self.user_id))

    async def _handle_receipt(self, data: dict[str, Any]) -> None:
        """Forward a read receipt to the original sender."""
        try:
            message_id = str(data["message_id"])
            sender_id = uuid.UUID(data["sender_id"])
        except (KeyError, ValueError):
            return

        payload = {
            "type": settings.WS_MESSAGE_TYPE_RECEIPT,
            "message_id": message_id,
            "user_id": str(self.user_id),
            "read_at": datetime.now(timezone.utc).isoformat(),
        }
        await ws_manager.send_to_user(sender_id, payload)

    async def _handle_heartbeat(self, _data: dict[str, Any]) -> None:
        """Respond to client heartbeat."""
        assert self.conn is not None
        await ws_manager.send_heartbeat(self.conn)

    # -----------------------------------------------------------------------
    # SurrealDB live query callback
    # -----------------------------------------------------------------------

    async def _on_surreal_message(self, message: dict[str, Any]) -> None:
        """
        Called by SurrealDB when a new message is inserted for this user.

        Forwards the message payload to the user's active WebSocket connections.
        SurrealDB live queries work with the action field:
        - CREATE: new record inserted
        - UPDATE: record modified
        - DELETE: record deleted
        """
        action = message.get("action") or message.get("type")
        if action not in ("CREATE", "create"):
            return

        record = message.get("result") or message.get("data", {})
        if not record:
            return

        ws_payload = {
            "type": settings.WS_MESSAGE_TYPE_ENCRYPTED,
            "id": str(record.get("id", "")),
            "sender_id": record.get("sender_id", ""),
            "sender_username": record.get("sender_username", ""),
            "room_id": record.get("room_id", ""),
            "ciphertext": record.get("ciphertext", ""),
            "nonce": record.get("nonce", ""),
            "header": record.get("header", ""),
            "timestamp": record.get("created_at", datetime.now(timezone.utc).isoformat()),
            "ephemeral_pub_key": record.get("ephemeral_pub_key"),
        }
        await ws_manager.send_to_user(self.user_id, ws_payload)

    # -----------------------------------------------------------------------
    # Heartbeat loop
    # -----------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to the client."""
        while True:
            await asyncio.sleep(settings.WS_HEARTBEAT_INTERVAL)
            if self.conn is not None:
                await ws_manager.send_heartbeat(self.conn)

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------

    async def _cleanup(self) -> None:
        """Release all resources when the connection closes."""
        # Cancel heartbeat
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Kill live query
        if self._live_query_id:
            await surreal_db.kill_live_query(self._live_query_id)

        # Unregister connection
        if self.conn is not None:
            ws_manager.remove_connection(self.conn)

        # Mark user offline if no more connections
        if not ws_manager.is_online(self.user_id):
            await surreal_db.set_user_offline(str(self.user_id))

        logger.info("WebSocket session cleaned up for user %s", self.user_id)
