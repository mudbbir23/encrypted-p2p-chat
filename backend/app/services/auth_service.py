"""
Auth Service — orchestrates WebAuthn registration and authentication flows.

Coordinates between PasskeyManager, RedisManager, and PostgreSQL models.
This is the only place where User and Credential records are written.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from app.config import settings
from app.core.exceptions import (
    AuthenticationVerificationError,
    ChallengeExpiredError,
    ClonedAuthenticatorError,
    RegistrationVerificationError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.core.passkey.passkey_manager import passkey_manager
from app.core.redis_manager import redis_manager
from app.models.Credential import Credential
from app.models.IdentityKey import IdentityKey
from app.models.User import User
from app.schemas.auth import (
    AuthSession,
    RegisterBeginRequest,
    UploadKeysRequest,
)

logger = structlog.get_logger(__name__)


class AuthService:
    """
    Orchestrates WebAuthn registration and authentication.

    Stateless — all state is passed via arguments or retrieved from DB/Redis.
    """

    # -----------------------------------------------------------------------
    # Registration flow
    # -----------------------------------------------------------------------

    async def begin_registration(
        self,
        db: AsyncSession,
        request: RegisterBeginRequest,
    ) -> dict:
        """
        Step 1 of registration: generate WebAuthn options and store challenge.

        Returns the options dict to send to the browser.
        Does NOT create a user record yet (that happens in complete_registration).
        """
        # Check if username is already taken
        existing = await db.scalar(
            select(User).where(User.username == request.username)
        )
        if existing is not None:
            raise UserAlreadyExistsError(
                f"Username '{request.username}' is already taken."
            )

        # Generate a temporary user_id bytes for the credential
        # The real UUID is created in complete_registration
        user_id_bytes = uuid.uuid4().bytes

        # Gather existing credentials (empty for new users, but safe to include)
        existing_cred_ids: list[bytes] = []

        options, challenge = passkey_manager.generate_registration_options(
            user_id_bytes=user_id_bytes,
            username=request.username,
            display_name=request.display_name,
            existing_credential_ids=existing_cred_ids,
        )

        # Store challenge in Redis with TTL
        await redis_manager.store_registration_challenge(
            username=request.username,
            challenge_bytes=challenge,
        )

        # Convert options to dict for JSON serialization
        from webauthn.helpers import options_to_json
        import json
        return json.loads(options_to_json(options))

    async def complete_registration(
        self,
        db: AsyncSession,
        username: str,
        display_name: str,
        credential: dict,
    ) -> User:
        """
        Step 2 of registration: verify the authenticator response and create user.

        Returns the newly created User record.

        Raises:
            ChallengeExpiredError: If the challenge has expired or was already used.
            RegistrationVerificationError: If the credential fails WebAuthn verification.
        """
        # Atomically retrieve and delete the challenge (single-use)
        challenge = await redis_manager.get_registration_challenge(username)
        if challenge is None:
            raise ChallengeExpiredError()

        # Verify the credential with py_webauthn
        try:
            verified = passkey_manager.verify_registration(
                credential=credential,
                challenge=challenge,
                require_user_verification=True,
            )
        except Exception as exc:
            logger.error("Registration verification failed", username=username, error=str(exc))
            raise RegistrationVerificationError(
                f"Registration verification failed: {exc}"
            ) from exc

        # Create User record
        new_user = User(
            username=username,
            display_name=display_name,
            is_active=True,
            is_verified=True,
        )
        db.add(new_user)
        await db.flush()  # Get the auto-generated id

        # Store the WebAuthn credential
        # verified.credential_public_key is CBOR-encoded bytes
        credential_record = Credential(
            user_id=new_user.id,
            credential_id=bytes_to_base64url(verified.credential_id),
            public_key=verified.credential_public_key.hex(),  # Store as hex
            sign_count=verified.sign_count,
            aaguid=str(verified.aaguid) if verified.aaguid else None,
            backup_eligible=verified.credential_backed_up,
            backup_state=verified.credential_backed_up,
            attestation_type=verified.fmt if hasattr(verified, "fmt") else None,
        )
        db.add(credential_record)
        await db.commit()
        await db.refresh(new_user)

        logger.info("User registered", username=username, user_id=str(new_user.id))
        return new_user

    # -----------------------------------------------------------------------
    # Authentication flow
    # -----------------------------------------------------------------------

    async def begin_authentication(
        self,
        db: AsyncSession,
        username: str,
    ) -> dict:
        """
        Step 1 of authentication: generate a challenge and return options.

        Returns the options dict to send to the browser.
        """
        # Load user — raises if not found
        user = await self.get_user_by_username(db, username)

        # Load all credentials for this user
        creds = (await db.scalars(
            select(Credential).where(Credential.user_id == user.id)
        )).all()

        if not creds:
            raise AuthenticationVerificationError(
                "No credentials registered for this user."
            )

        cred_id_list = [base64url_to_bytes(c.credential_id) for c in creds]

        options, challenge = passkey_manager.generate_authentication_options(
            existing_credential_ids=cred_id_list,
        )

        # Store challenge
        await redis_manager.store_authentication_challenge(
            username=username,
            challenge_bytes=challenge,
        )

        from webauthn.helpers import options_to_json
        import json
        return json.loads(options_to_json(options))

    async def complete_authentication(
        self,
        db: AsyncSession,
        username: str,
        credential: dict,
    ) -> AuthSession:
        """
        Step 2 of authentication: verify the signed challenge and return a session.

        Returns an AuthSession with the user's identity.

        Raises:
            ChallengeExpiredError: If the challenge has expired.
            AuthenticationVerificationError: If verification fails.
            ClonedAuthenticatorError: If the sign_count indicates a cloned device.
        """
        # Consume challenge
        challenge = await redis_manager.get_authentication_challenge(username)
        if challenge is None:
            raise ChallengeExpiredError()

        # Find user
        user = await self.get_user_by_username(db, username)

        # Find the credential being used (by credential ID in the response)
        credential_id_b64 = credential.get("id") or credential.get("rawId")
        if not credential_id_b64:
            raise AuthenticationVerificationError("Credential ID missing from response")

        cred_record = await db.scalar(
            select(Credential).where(
                Credential.credential_id == credential_id_b64,
                Credential.user_id == user.id,
            )
        )
        if cred_record is None:
            raise AuthenticationVerificationError(
                "Credential not found. Please register this device first."
            )

        # Decode stored public key from hex
        stored_public_key = bytes.fromhex(cred_record.public_key)

        try:
            verified, new_sign_count = passkey_manager.verify_authentication(
                credential=credential,
                challenge=challenge,
                stored_public_key=stored_public_key,
                stored_sign_count=cred_record.sign_count,
                require_user_verification=True,
            )
        except ValueError as exc:
            # Sign count mismatch → cloned authenticator
            if "clone" in str(exc).lower():
                raise ClonedAuthenticatorError(str(exc)) from exc
            raise AuthenticationVerificationError(str(exc)) from exc
        except Exception as exc:
            logger.error("Authentication failed", username=username, error=str(exc))
            raise AuthenticationVerificationError(str(exc)) from exc

        # Update the sign_count and last_used_at
        cred_record.sign_count = new_sign_count
        cred_record.last_used_at = datetime.now(timezone.utc)
        await db.commit()

        logger.info("User authenticated", username=username, user_id=str(user.id))

        return AuthSession(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
        )

    # -----------------------------------------------------------------------
    # Key upload
    # -----------------------------------------------------------------------

    async def upload_keys(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        request: UploadKeysRequest,
    ) -> None:
        """
        Store the user's public encryption keys after registration.

        Only the public keys are uploaded. Private keys never leave the client.
        """
        user = await db.get(User, user_id)
        if user is None:
            raise UserNotFoundError(f"User {user_id} not found")

        # Update user's key fields
        user.identity_key = request.identity_key_x25519
        user.signed_prekey = request.signed_prekey
        user.signed_prekey_sig = request.signed_prekey_sig

        # Store one-time prekey list as JSON
        import json
        user.one_time_prekeys = json.dumps(request.one_time_prekeys)

        # Persist identity keys to the IdentityKey table as well
        ik_record = await db.scalar(
            select(IdentityKey).where(IdentityKey.user_id == user_id)
        )
        if ik_record is None:
            ik_record = IdentityKey(
                user_id=user_id,
                public_key_x25519=request.identity_key_x25519,
                public_key_ed25519=request.identity_key_ed25519,
            )
            db.add(ik_record)
        else:
            ik_record.public_key_x25519 = request.identity_key_x25519
            ik_record.public_key_ed25519 = request.identity_key_ed25519

        # CRITICAL FIX: Also insert OPKs into the OneTimePrekey table.
        # The PrekeyService queries one_time_prekeys table — not user.one_time_prekeys.
        # Delete any existing unused OPKs first to avoid duplicates on re-upload.
        from sqlalchemy import delete
        from app.models.OneTimePrekey import OneTimePrekey
        await db.execute(
            delete(OneTimePrekey).where(
                OneTimePrekey.user_id == user_id,
                OneTimePrekey.is_used == False,  # noqa: E712
            )
        )
        for idx, pub_key in enumerate(request.one_time_prekeys):
            opk = OneTimePrekey(
                user_id=user_id,
                public_key=pub_key,
                is_used=False,
                key_id=idx,
            )
            db.add(opk)

        await db.commit()
        logger.info("Keys uploaded for user %s (%d OPKs)", user_id, len(request.one_time_prekeys))

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    async def get_user_by_username(self, db: AsyncSession, username: str) -> User:
        user = await db.scalar(
            select(User).where(User.username == username.lower())
        )
        if user is None:
            raise UserNotFoundError(f"User '{username}' not found")
        return user


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

auth_service = AuthService()
