"""
One-time prekey model — single-use X25519 keys for the optional 4th DH in X3DH.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import String
from sqlmodel import Field

from app.models.Base import BaseDBModel


class OneTimePrekey(BaseDBModel, table=True):
    """
    One-time prekey (OPK) for X3DH.

    Each OPK is consumed exactly once. When a new session is established,
    the server atomically marks one OPK as used and returns it in the
    prekey bundle. After use, the OPK is never returned again.

    OPKs are generated in batches of DEFAULT_ONE_TIME_PREKEY_COUNT (100)
    and replenished when the unused count drops below half.
    """

    __tablename__ = "one_time_prekeys"

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
    # Private key stored ONLY in server-side fallback mode. NULL in production.
    private_key: Optional[str] = Field(
        default=None,
        max_length=256,
        nullable=True,
        sa_type=String(256),
    )

    # is_used is set to True atomically when the OPK is returned in a prekey bundle.
    # Once True, the OPK will never be fetched again.
    is_used: bool = Field(default=False, nullable=False, index=True)

    # A client-assigned integer ID to distinguish OPKs when multiple are generated.
    key_id: Optional[int] = Field(default=None, nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<OneTimePrekey id={self.id} user_id={self.user_id} used={self.is_used}>"
