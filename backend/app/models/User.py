"""
User model — core identity record for authenticated users.
"""
import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Index, String
from sqlmodel import Field, Relationship, SQLModel

from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    from app.models.Credential import Credential


class User(BaseDBModel, table=True):
    """
    Represents an authenticated user.

    identity_key, signed_prekey, signed_prekey_sig, one_time_prekeys are the
    PUBLIC keys uploaded by the client after successful WebAuthn registration.
    The server NEVER stores private key material in this table when operating
    in client-side encryption mode.
    """

    __tablename__ = "users"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        nullable=False,
    )
    username: str = Field(
        max_length=50,
        unique=True,
        nullable=False,
        index=True,
        sa_type=String(50),
    )
    display_name: str = Field(
        max_length=100,
        nullable=False,
        sa_type=String(100),
    )
    is_active: bool = Field(default=True, nullable=False)
    is_verified: bool = Field(default=False, nullable=False)

    # Public key material (stored by the client after key generation).
    # These are base64url-encoded X25519/Ed25519 public keys.
    identity_key: Optional[str] = Field(
        default=None,
        max_length=500,
        nullable=True,
        sa_type=String(500),
    )
    signed_prekey: Optional[str] = Field(
        default=None,
        max_length=500,
        nullable=True,
        sa_type=String(500),
    )
    signed_prekey_sig: Optional[str] = Field(
        default=None,
        max_length=500,
        nullable=True,
        sa_type=String(500),
    )
    # JSON-encoded list of OPK public keys (legacy / simple clients only)
    one_time_prekeys: Optional[str] = Field(
        default=None,
        nullable=True,
    )

    # Relationships
    credentials: list["Credential"] = Relationship(back_populates="user")

    __table_args__ = (
        Index("ix_users_username_lower", "username"),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"


class UserPublic(SQLModel):
    """Safe public view — never exposes keys or internal flags."""
    id: uuid.UUID
    username: str
    display_name: str
    is_active: bool
