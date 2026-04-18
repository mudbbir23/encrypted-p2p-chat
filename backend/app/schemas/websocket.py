"""
WebSocket message schemas — typed payloads for the real-time channel.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Inbound (client → server)
# ---------------------------------------------------------------------------

class EncryptedMessageInbound(BaseModel):
    """Client sends an encrypted message to a recipient."""
    type: Literal["encrypted_message"]
    recipient_id: uuid.UUID
    room_id: uuid.UUID
    # AES-256-GCM ciphertext, base64url encoded
    ciphertext: str = Field(max_length=70_000)
    # 12-byte AES-GCM nonce, base64url encoded
    nonce: str = Field(max_length=32)
    # JSON-encoded Double Ratchet header {dh_public_key, message_number, prev_chain_count}
    header: str = Field(max_length=1024)
    # Client-assigned temporary ID for optimistic UI reconciliation
    temp_id: Optional[str] = Field(default=None, max_length=128)
    ephemeral_pub_key: Optional[str] = Field(default=None, max_length=128)


class TypingIndicatorInbound(BaseModel):
    """Client signals that the user is (or is not) typing."""
    type: Literal["typing"]
    room_id: uuid.UUID
    is_typing: bool


class PresenceUpdateInbound(BaseModel):
    """Client signals a manual presence status change."""
    type: Literal["presence"]
    status: Literal["online", "away", "busy"]


class ReadReceiptInbound(BaseModel):
    """Client confirms that a message was read."""
    type: Literal["receipt"]
    message_id: str  # SurrealDB record ID (e.g., "messages:abc123")
    sender_id: uuid.UUID  # The user who originally sent the message


class HeartbeatInbound(BaseModel):
    """Client heartbeat — server responds with pong."""
    type: Literal["heartbeat"]


# ---------------------------------------------------------------------------
# Outbound (server → client)
# ---------------------------------------------------------------------------

class EncryptedMessageWS(BaseModel):
    """Server forwards an encrypted message to the recipient."""
    type: Literal["encrypted_message"] = "encrypted_message"
    id: str  # SurrealDB message ID
    sender_id: uuid.UUID
    sender_username: str
    room_id: uuid.UUID
    ciphertext: str
    nonce: str
    header: str
    timestamp: datetime
    temp_id: Optional[str] = None
    ephemeral_pub_key: Optional[str] = None


class TypingIndicatorWS(BaseModel):
    """Server broadcasts typing status to room members."""
    type: Literal["typing"] = "typing"
    user_id: uuid.UUID
    username: str
    room_id: uuid.UUID
    is_typing: bool


class PresenceUpdateWS(BaseModel):
    """Server notifies about a user's presence change."""
    type: Literal["presence"] = "presence"
    user_id: uuid.UUID
    status: str  # "online" | "offline" | "away"
    last_seen: Optional[datetime] = None


class ReadReceiptWS(BaseModel):
    """Server forwards a read receipt to the message sender."""
    type: Literal["receipt"] = "receipt"
    message_id: str
    user_id: uuid.UUID
    read_at: datetime


class ErrorWS(BaseModel):
    """Server sends an error notification to the client."""
    type: Literal["error"] = "error"
    code: str
    message: str


class MessageSentAck(BaseModel):
    """Acknowledgement sent to the sender after the message is stored."""
    type: Literal["message_sent"] = "message_sent"
    temp_id: Optional[str] = None
    message_id: str
    status: Literal["sent"] = "sent"
    timestamp: datetime


class HeartbeatAck(BaseModel):
    """Pong response to client heartbeat."""
    type: Literal["pong"] = "pong"
    timestamp: datetime


# ---------------------------------------------------------------------------
# Prekey Bundle (served via HTTP but typed here for reuse)
# ---------------------------------------------------------------------------

class PreKeyBundleResponse(BaseModel):
    """X3DH prekey bundle returned to an initiating client."""
    user_id: uuid.UUID
    # X25519 identity key, base64url
    identity_key_x25519: str
    # Ed25519 identity key (for SPK signature verification), base64url
    identity_key_ed25519: str
    # Current signed prekey, base64url
    signed_prekey: str
    # Ed25519 signature over signed_prekey bytes, base64url
    signed_prekey_signature: str
    # One-time prekey (may be absent if all OPKs are consumed), base64url
    one_time_prekey: Optional[str] = None
    # Server-side one-time prekey DB id (to confirm consumption)
    one_time_prekey_id: Optional[int] = None
