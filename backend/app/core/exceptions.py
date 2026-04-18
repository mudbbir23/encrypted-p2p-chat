"""
Custom exception classes for the encrypted P2P chat application.

All exceptions map to specific HTTP status codes in exception_handlers.py.
Using typed exceptions makes error handling explicit and intent-clear.
"""
from __future__ import annotations


class AppError(Exception):
    """Base class for all application exceptions."""
    status_code: int = 500
    error_code: str = "internal_error"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# Auth / WebAuthn
# ---------------------------------------------------------------------------

class UserNotFoundError(AppError):
    status_code = 404
    error_code = "user_not_found"


class UserAlreadyExistsError(AppError):
    status_code = 409
    error_code = "user_already_exists"


class ChallengeExpiredError(AppError):
    status_code = 400
    error_code = "challenge_expired"

    def __init__(self) -> None:
        super().__init__(
            "WebAuthn challenge has expired or was already used. Please restart the authentication flow."
        )


class RegistrationVerificationError(AppError):
    status_code = 400
    error_code = "registration_verification_failed"


class AuthenticationVerificationError(AppError):
    status_code = 401
    error_code = "authentication_failed"


class ClonedAuthenticatorError(AppError):
    status_code = 403
    error_code = "cloned_authenticator"


# ---------------------------------------------------------------------------
# Encryption / Key Management
# ---------------------------------------------------------------------------

class KeysNotFoundError(AppError):
    status_code = 404
    error_code = "keys_not_found"


class InvalidSignedPrekeyError(AppError):
    status_code = 400
    error_code = "invalid_signed_prekey"


class EncryptionError(AppError):
    status_code = 500
    error_code = "encryption_error"


class DecryptionError(AppError):
    status_code = 400
    error_code = "decryption_failed"


class RatchetStateNotFoundError(AppError):
    status_code = 404
    error_code = "ratchet_state_not_found"


# ---------------------------------------------------------------------------
# Messaging
# ---------------------------------------------------------------------------

class MessageTooLargeError(AppError):
    status_code = 413
    error_code = "message_too_large"


class InvalidMessageFormatError(AppError):
    status_code = 400
    error_code = "invalid_message_format"


# ---------------------------------------------------------------------------
# Rooms
# ---------------------------------------------------------------------------

class RoomNotFoundError(AppError):
    status_code = 404
    error_code = "room_not_found"


class UnauthorizedRoomAccessError(AppError):
    status_code = 403
    error_code = "unauthorized_room_access"


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

class ConnectionLimitExceededError(AppError):
    status_code = 429
    error_code = "connection_limit_exceeded"


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

class RateLimitExceededError(AppError):
    status_code = 429
    error_code = "rate_limit_exceeded"

    def __init__(self) -> None:
        super().__init__("Rate limit exceeded. Please slow down your requests.")
