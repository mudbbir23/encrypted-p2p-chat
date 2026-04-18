"""
WebAuthn credential model — one row per registered authenticator device.
"""
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import String
from sqlmodel import Field, Relationship

from app.models.Base import BaseDBModel

if TYPE_CHECKING:
    from app.models.User import User


class Credential(BaseDBModel, table=True):
    """
    Stores the WebAuthn credential for a single authenticator (TouchID, YubiKey, etc.).
    One user may have multiple credentials (one per device they register).

    The sign_count is incremented each time the authenticator signs a challenge.
    If a new sign_count is not greater than the stored one, we reject the authentication
    as a cloned authenticator signal.
    """

    __tablename__ = "credentials"

    id: Optional[int] = Field(default=None, primary_key=True)

    # The raw credential ID returned by the authenticator (bytes, base64url-encoded for storage)
    credential_id: str = Field(
        max_length=512,
        unique=True,
        nullable=False,
        index=True,
        sa_type=String(512),
    )
    # COSE-encoded public key returned during registration
    public_key: str = Field(
        max_length=1024,
        nullable=False,
        sa_type=String(1024),
    )
    # Monotonically increasing counter from the authenticator
    sign_count: int = Field(default=0, nullable=False)
    # AAGUID identifies the authenticator model (optional, used for attestation)
    aaguid: Optional[str] = Field(
        default=None,
        max_length=64,
        nullable=True,
        sa_type=String(64),
    )
    # Whether the credential is eligible for backup (cloud passkeys)
    backup_eligible: bool = Field(default=False, nullable=False)
    backup_state: bool = Field(default=False, nullable=False)
    # Attestation type returned during registration
    attestation_type: Optional[str] = Field(
        default=None,
        max_length=50,
        nullable=True,
        sa_type=String(50),
    )
    # Comma-separated transport hints (usb, nfc, ble, internal, hybrid)
    transports: Optional[str] = Field(
        default=None,
        max_length=200,
        nullable=True,
        sa_type=String(200),
    )

    # Foreign key to users table
    user_id: uuid.UUID = Field(foreign_key="users.id", nullable=False, index=True)

    # Human-readable name for the credential (e.g., "iPhone 15")
    device_name: Optional[str] = Field(
        default=None,
        max_length=100,
        nullable=True,
        sa_type=String(100),
    )
    last_used_at: Optional[datetime] = Field(default=None, nullable=True)

    # Relationships
    user: Optional["User"] = Relationship(back_populates="credentials")

    def __repr__(self) -> str:
        return f"<Credential id={self.id} user_id={self.user_id} device={self.device_name!r}>"
