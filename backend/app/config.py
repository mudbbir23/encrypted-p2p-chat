"""
Application configuration using pydantic-settings.
All values are loaded from environment variables or .env file.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "Encrypted P2P Chat"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_hex(32)

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    ALLOWED_ORIGINS: list[str] = ["http://localhost", "http://localhost:3000", "http://localhost:5173"]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "postgresql+asyncpg://e2echat:changeme@localhost:5432/e2echat"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    DB_POOL_TIMEOUT: int = 30

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://:changeme@localhost:6379/0"
    REDIS_POOL_SIZE: int = 50

    # -------------------------------------------------------------------------
    # SurrealDB
    # -------------------------------------------------------------------------
    SURREAL_URL: str = "ws://localhost:8001/rpc"
    SURREAL_USER: str = "root"
    SURREAL_PASS: str = "changeme"
    SURREAL_NS: str = "e2echat"
    SURREAL_DB: str = "messages"

    # -------------------------------------------------------------------------
    # WebAuthn / Passkeys
    # -------------------------------------------------------------------------
    RP_ID: str = "localhost"
    RP_NAME: str = "Encrypted P2P Chat"
    RP_ORIGIN: str = "http://localhost"

    # Challenge TTL in seconds; challenges expire after this period
    WEBAUTHN_CHALLENGE_TTL_SECONDS: int = 600
    # Number of random bytes for the challenge (256 bits)
    WEBAUTHN_CHALLENGE_BYTES: int = 32

    # -------------------------------------------------------------------------
    # Signal Protocol limits
    # -------------------------------------------------------------------------
    # Maximum number of out-of-order message keys that can be skipped
    MAX_SKIP_MESSAGE_KEYS: int = 1000
    # Maximum total skipped message keys cached per ratchet state
    MAX_CACHED_MESSAGE_KEYS: int = 2000
    # AES-GCM nonce size in bytes (96-bit / 12 bytes per NIST recommendation)
    AES_GCM_NONCE_SIZE: int = 12
    # HKDF output size in bytes (256-bit keys)
    HKDF_OUTPUT_SIZE: int = 32
    # X25519 key size in bytes
    X25519_KEY_SIZE: int = 32
    # Default number of one-time prekeys to generate per user
    DEFAULT_ONE_TIME_PREKEY_COUNT: int = 100
    # Signed prekey rotation interval in hours
    SIGNED_PREKEY_ROTATION_HOURS: int = 48
    # Retain old signed prekeys for this many days (for in-flight messages)
    SIGNED_PREKEY_RETENTION_DAYS: int = 7

    # -------------------------------------------------------------------------
    # Message limits
    # -------------------------------------------------------------------------
    # Maximum size of inline encrypted content in bytes
    ENCRYPTED_CONTENT_MAX_LENGTH: int = 50_000

    # -------------------------------------------------------------------------
    # WebSocket
    # -------------------------------------------------------------------------
    WS_MAX_CONNECTIONS_PER_USER: int = 5
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds

    # WebSocket message type constants
    WS_MESSAGE_TYPE_ENCRYPTED: str = "encrypted_message"
    WS_MESSAGE_TYPE_TYPING: str = "typing"
    WS_MESSAGE_TYPE_PRESENCE: str = "presence"
    WS_MESSAGE_TYPE_RECEIPT: str = "receipt"
    WS_MESSAGE_TYPE_HEARTBEAT: str = "heartbeat"

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    @model_validator(mode="after")
    def warn_insecure_secret(self) -> "Settings":
        if self.SECRET_KEY.startswith("change_this"):
            import warnings
            warnings.warn(
                "SECRET_KEY is set to a placeholder value. "
                "Generate a secure key with: python -c \"import secrets; print(secrets.token_hex(32))\"",
                stacklevel=2,
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Module-level singleton for import convenience
settings = get_settings()
