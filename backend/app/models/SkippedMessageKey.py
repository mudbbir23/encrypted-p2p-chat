"""
Skipped message key model — cached keys for out-of-order message decryption.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import String, UniqueConstraint
from sqlmodel import Field

from app.models.Base import BaseDBModel


class SkippedMessageKey(BaseDBModel, table=True):
    """
    Stores individual skipped message keys for the Double Ratchet.

    When a message is received out-of-order (e.g., message 5 before message 3),
    the ratchet must advance past the missing messages, storing a derived key for
    each skipped message number so they can be decrypted when they eventually arrive.

    Each row is keyed by (ratchet_state_id, dh_public_key, message_number).
    The dh_public_key is necessary because message numbers reset with each DH ratchet step.

    Security limits (from config.py):
    - MAX_SKIP_MESSAGE_KEYS: maximum gap size in a single chain
    - MAX_CACHED_MESSAGE_KEYS: total cached keys, oldest evicted when exceeded
    """

    __tablename__ = "skipped_message_keys"
    __table_args__ = (
        UniqueConstraint(
            "ratchet_state_id", "dh_public_key", "message_number",
            name="uq_skipped_msg_key",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)

    ratchet_state_id: int = Field(
        foreign_key="ratchet_states.id",
        nullable=False,
        index=True,
    )

    # The DH public key that identifies the ratchet epoch
    dh_public_key: str = Field(
        max_length=256,
        nullable=False,
        sa_type=String(256),
    )

    # The message number within this DH epoch
    message_number: int = Field(nullable=False)

    # The derived AES-256-GCM message key, base64url encoded
    message_key: str = Field(
        max_length=64,
        nullable=False,
        sa_type=String(64),
    )

    def __repr__(self) -> str:
        return (
            f"<SkippedMessageKey state_id={self.ratchet_state_id} "
            f"msg_num={self.message_number}>"
        )
