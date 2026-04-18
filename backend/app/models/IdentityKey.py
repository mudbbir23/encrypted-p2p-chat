"""
Identity key model — stores the X25519 and Ed25519 keypairs for each user.

CRITICAL SECURITY NOTE:
In client-side encryption mode (production), the private keys are stored
in the browser's IndexedDB and NEVER sent to the server. The private_key_x25519
and private_key_ed25519 columns exist for server-side fallback only and should
be NULL for all users in a properly operating deployment.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import String, UniqueConstraint
from sqlmodel import Field

from app.models.Base import BaseDBModel


class IdentityKey(BaseDBModel, table=True):
    """
    X3DH identity keys for a user.

    The X25519 key participates in DH operations.
    The Ed25519 key signs signed prekeys to prove ownership.
    """

    __tablename__ = "identity_keys"
    __table_args__ = (UniqueConstraint("user_id", name="uq_identity_keys_user_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)

    user_id: uuid.UUID = Field(
        foreign_key="users.id",
        nullable=False,
        unique=True,
        index=True,
    )

    # X25519 keypair — base64url encoded
    public_key_x25519: str = Field(
        max_length=256,
        nullable=False,
        sa_type=String(256),
    )
    # Private key stored ONLY in server-side fallback mode. NULL in production.
    private_key_x25519: Optional[str] = Field(
        default=None,
        max_length=256,
        nullable=True,
        sa_type=String(256),
    )

    # Ed25519 keypair — base64url encoded
    public_key_ed25519: str = Field(
        max_length=256,
        nullable=False,
        sa_type=String(256),
    )
    # Private key stored ONLY in server-side fallback mode. NULL in production.
    private_key_ed25519: Optional[str] = Field(
        default=None,
        max_length=256,
        nullable=True,
        sa_type=String(256),
    )

    def __repr__(self) -> str:
        return f"<IdentityKey user_id={self.user_id}>"
