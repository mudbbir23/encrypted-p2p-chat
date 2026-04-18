"""
WebAuthn / Passkey request and response schemas.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class RegisterBeginRequest(BaseModel):
    """Initial registration request from client."""
    username: str = Field(min_length=3, max_length=50)
    display_name: str = Field(min_length=1, max_length=100)

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError(
                "Username may only contain letters, numbers, underscores, dots, and hyphens"
            )
        return v.lower()


class RegisterCompleteRequest(BaseModel):
    """Complete registration with the authenticator credential."""
    username: str
    display_name: Optional[str] = None  # If provided, overrides the begin-step display_name
    credential: dict[str, Any]  # Raw WebAuthn credential from navigator.credentials.create()


class AuthenticateBeginRequest(BaseModel):
    """Initial authentication request — provide username to get challenge."""
    username: str


class AuthenticateCompleteRequest(BaseModel):
    """Complete authentication with the signed challenge."""
    username: str
    credential: dict[str, Any]  # Raw WebAuthn credential from navigator.credentials.get()


class UserSearchRequest(BaseModel):
    """Search for users by username or display name."""
    query: str = Field(min_length=2, max_length=50)
    limit: int = Field(default=10, ge=1, le=50)


class UserSearchResult(BaseModel):
    """Single result from user search."""
    id: uuid.UUID
    username: str
    display_name: str
    has_keys: bool


class AuthSession(BaseModel):
    """Minimal session response after successful authentication."""
    user_id: uuid.UUID
    username: str
    display_name: str
    session_token: Optional[str] = None  # Future: JWT or opaque token


class UploadKeysRequest(BaseModel):
    """Client uploads its public keys after registration."""
    identity_key_x25519: str  # base64url X25519 public key
    identity_key_ed25519: str  # base64url Ed25519 public key
    signed_prekey: str          # base64url X25519 public key
    signed_prekey_sig: str      # base64url Ed25519 signature
    one_time_prekeys: list[str]  # list of base64url X25519 public keys (OPKs)

    @field_validator("one_time_prekeys")
    @classmethod
    def validate_opk_count(cls, v: list[str]) -> list[str]:
        if len(v) > 200:
            raise ValueError("Cannot upload more than 200 one-time prekeys at once")
        return v
