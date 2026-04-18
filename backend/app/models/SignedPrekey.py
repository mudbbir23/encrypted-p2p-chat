"""
Signed Prekey model — medium-term X25519 keypair, rotated every 48 hours.
The public key is signed with the Ed25519 identity key to prevent MITM substitution.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String
from sqlmodel import Field

from app.models.Base import BaseDBModel


class SignedPrekey(BaseDBModel, table=True):
    """
    Signed prekey (SPK) for X3DH.

    Lifecycle:
    - Generated per user, rotated every SIGNED_PREKEY_ROTATION_HOURS (48h)
    - Old SPKs are retained for SIGNED_PREKEY_RETENTION_DAYS (7d) then deleted
    - is_active=True marks the current active SPK; at most one per user
    """

    __tablename__ = "signed_prekeys"

    id: Optional[int] = Field(default=None, primary_key=True)

    user_id: uuid.UUID = Field(
        foreign_key="users.id",
        nullable=False,
        index=True,
    )

    # The X25519 public key, base64url encoded
    public_key: str = Field(
        max_length=256,
        nullable=False,
        sa_type=String(256),
    )
    # Ed25519 signature over the public key bytes, base64url encoded
    signature: str = Field(
        max_length=512,
        nullable=False,
        sa_type=String(512),
    )
    # Private key stored ONLY in server-side fallback mode. NULL in production.
    private_key: Optional[str] = Field(
        default=None,
        max_length=256,
        nullable=True,
        sa_type=String(256),
    )

    # Lifecycle management
    is_active: bool = Field(default=True, nullable=False, index=True)
    # When this SPK was deactivated (set when a newer SPK becomes active)
    deactivated_at: Optional[datetime] = Field(default=None, nullable=True)

    def __repr__(self) -> str:
        return f"<SignedPrekey id={self.id} user_id={self.user_id} active={self.is_active}>"
