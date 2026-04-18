"""
Message Service — routes encrypted messages to recipients.

The server's role here is ZERO KNOWLEDGE:
- It validates that the payload is structurally valid (has required fields)
- It stores the ciphertext blob in SurrealDB WITHOUT decrypting it
- It routes the blob to the recipient's WebSocket connection
- It does NOT have access to message keys or plaintext at any point

This file is intentionally short — complex logic belongs in the crypto layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from app.config import settings
from app.core.exceptions import (
    InvalidMessageFormatError,
    MessageTooLargeError,
    UnauthorizedRoomAccessError,
)
from app.core.surreal_manager import surreal_db
from app.core.websocket_manager import ws_manager

logger = structlog.get_logger(__name__)


class MessageService:
    """
    Routes encrypted message blobs from sender to recipient.
    """

    def validate_message_payload(
        self,
        ciphertext: str,
        nonce: str,
        header: str,
    ) -> None:
        """
        Structural validation only — no decryption.

        Checks:
        - Ciphertext length within limits
        - Nonce is non-empty
        - Header is non-empty
        """
        if len(ciphertext) > settings.ENCRYPTED_CONTENT_MAX_LENGTH:
            raise MessageTooLargeError(
                f"Encrypted message exceeds maximum size of {settings.ENCRYPTED_CONTENT_MAX_LENGTH} bytes"
            )
        if not nonce or len(nonce) < 16:
            raise InvalidMessageFormatError("Nonce is missing or too short")
        if not header or len(header) < 2:
            raise InvalidMessageFormatError("Message header is missing or invalid")

    async def store_and_deliver(
        self,
        sender_id: uuid.UUID,
        sender_username: str,
        recipient_id: uuid.UUID,
        room_id: uuid.UUID,
        ciphertext: str,
        nonce: str,
        header: str,
        temp_id: str | None = None,
        ephemeral_pub_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Store the encrypted message in SurrealDB and attempt live delivery.

        Returns the stored message record (with its SurrealDB ID).
        """
        self.validate_message_payload(ciphertext, nonce, header)

        # Store in SurrealDB (zero-knowledge: we store ciphertext verbatim)
        stored = await surreal_db.create_message(
            sender_id=str(sender_id),
            sender_username=sender_username,
            recipient_id=str(recipient_id),
            room_id=str(room_id),
            ciphertext=ciphertext,
            nonce=nonce,
            header=header,
            ephemeral_pub_key=ephemeral_pub_key,
        )

        # Bump the room's last_message_at timestamp
        await surreal_db.update_room_last_message(str(room_id))

        # Attempt live delivery to recipient if they are connected
        message_id = stored.get("id", "")
        timestamp = datetime.now(timezone.utc).isoformat()

        ws_payload = {
            "type": settings.WS_MESSAGE_TYPE_ENCRYPTED,
            "id": str(message_id),
            "sender_id": str(sender_id),
            "sender_username": sender_username,
            "room_id": str(room_id),
            "ciphertext": ciphertext,
            "nonce": nonce,
            "header": header,
            "timestamp": timestamp,
            "temp_id": temp_id,
            "ephemeral_pub_key": ephemeral_pub_key,
        }
        delivered = await ws_manager.send_to_user(recipient_id, ws_payload)

        if not delivered:
            logger.debug(
                "Recipient %s offline; message %s stored for later retrieval",
                recipient_id,
                message_id,
            )

        # Send acknowledgement back to the sender
        ack_payload = {
            "type": "message_sent",
            "temp_id": temp_id,
            "message_id": str(message_id),
            "status": "sent",
            "timestamp": timestamp,
        }
        await ws_manager.send_to_user(sender_id, ack_payload)

        return stored


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

message_service = MessageService()
