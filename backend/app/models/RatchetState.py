"""
Double Ratchet state model — persists the ratchet state between messages.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import String, UniqueConstraint
from sqlmodel import Field

from app.models.Base import BaseDBModel


class RatchetState(BaseDBModel, table=True):
    """
    Serialized Double Ratchet state for a conversation between two users.

    The ratchet state changes with every message sent or received.
    It is stored in PostgreSQL for the server-side encryption fallback only.
    In the client-side production path, this state lives in the browser's IndexedDB.

    Fields map 1-to-1 with the DoubleRatchetState dataclass in double_ratchet.py.
    """

    __tablename__ = "ratchet_states"
    __table_args__ = (
        UniqueConstraint("user_id", "peer_user_id", name="uq_ratchet_state_pair"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)

    # Identifies this conversation side
    user_id: uuid.UUID = Field(foreign_key="users.id", nullable=False, index=True)
    peer_user_id: uuid.UUID = Field(foreign_key="users.id", nullable=False, index=True)

    # Root chain key, base64url encoded
    root_key: str = Field(max_length=64, nullable=False, sa_type=String(64))

    # Sending chain state
    sending_chain_key: Optional[str] = Field(
        default=None, max_length=64, nullable=True, sa_type=String(64)
    )
    sending_message_number: int = Field(default=0, nullable=False)
    # DH keypair for the current sending ratchet (base64url)
    dh_sending_private: Optional[str] = Field(
        default=None, max_length=256, nullable=True, sa_type=String(256)
    )
    dh_sending_public: Optional[str] = Field(
        default=None, max_length=256, nullable=True, sa_type=String(256)
    )

    # Receiving chain state
    receiving_chain_key: Optional[str] = Field(
        default=None, max_length=64, nullable=True, sa_type=String(64)
    )
    receiving_message_number: int = Field(default=0, nullable=False)
    # Peer's current DH public key (base64url)
    dh_peer_public: Optional[str] = Field(
        default=None, max_length=256, nullable=True, sa_type=String(256)
    )

    # Number of messages in the previous sending chain (for header)
    previous_sending_chain_count: int = Field(default=0, nullable=False)

    # JSON-encoded skipped message key cache: {dh_pub:msg_num → message_key}
    skipped_message_keys_json: Optional[str] = Field(
        default=None, nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<RatchetState user={self.user_id} peer={self.peer_user_id} "
            f"send_n={self.sending_message_number} recv_n={self.receiving_message_number}>"
        )
