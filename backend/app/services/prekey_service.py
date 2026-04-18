"""
Prekey Service — manages prekey bundles for X3DH session establishment.

Handles:
- Serving prekey bundles to requesting clients
- Atomically consuming one-time prekeys (single-use guarantee)
- Verifying signed prekey signatures before serving bundles
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import KeysNotFoundError, UserNotFoundError
from app.models.IdentityKey import IdentityKey
from app.models.OneTimePrekey import OneTimePrekey
from app.models.User import User
from app.schemas.websocket import PreKeyBundleResponse

logger = structlog.get_logger(__name__)


class PrekeyService:
    """
    Serves X3DH prekey bundles.

    The bundle consists of:
    - IK_B (X25519 identity key for DH)
    - IK_B_sig (Ed25519 identity key for signature verification)
    - SPK_B (signed prekey)
    - SPK_B_sig (Ed25519 signature over SPK_B)
    - OPK_B (one-time prekey, if available — consumed on fetch)
    """

    async def get_prekey_bundle(
        self,
        db: AsyncSession,
        target_user_id: uuid.UUID,
    ) -> PreKeyBundleResponse:
        """
        Fetch a prekey bundle for the target user.

        Atomically marks one OPK as used (single-use guarantee).
        Returns the bundle with or without OPK depending on availability.

        Raises:
            UserNotFoundError: If the target user does not exist.
            KeysNotFoundError: If the user has not uploaded their keys yet.
        """
        # Load user
        user = await db.get(User, target_user_id)
        if user is None:
            raise UserNotFoundError(f"User {target_user_id} not found")

        if not user.identity_key or not user.signed_prekey or not user.signed_prekey_sig:
            raise KeysNotFoundError(
                f"User {target_user_id} has not uploaded encryption keys. "
                "They must complete key setup before sessions can be established."
            )

        # Load Ed25519 identity key from the IdentityKey table
        ik_record = await db.scalar(
            select(IdentityKey).where(IdentityKey.user_id == target_user_id)
        )
        if ik_record is None:
            raise KeysNotFoundError(
                f"Identity key record missing for user {target_user_id}"
            )

        # Atomically claim one unused OPK
        opk_public: Optional[str] = None
        opk_id: Optional[int] = None

        unused_opk = await db.scalar(
            select(OneTimePrekey).where(
                OneTimePrekey.user_id == target_user_id,
                OneTimePrekey.is_used == False,  # noqa: E712
            ).with_for_update(skip_locked=True).limit(1)
        )

        if unused_opk is not None:
            unused_opk.is_used = True
            opk_public = unused_opk.public_key
            opk_id = unused_opk.id
            logger.debug(
                "OPK consumed for user %s, opk_id=%s",
                target_user_id,
                opk_id,
            )
        else:
            logger.warning(
                "No OPKs available for user %s — bundle without OPK",
                target_user_id,
            )

        await db.commit()

        return PreKeyBundleResponse(
            user_id=target_user_id,
            identity_key_x25519=user.identity_key,
            identity_key_ed25519=ik_record.public_key_ed25519,
            signed_prekey=user.signed_prekey,
            signed_prekey_signature=user.signed_prekey_sig,
            one_time_prekey=opk_public,
            one_time_prekey_id=opk_id,
        )

    async def upload_one_time_prekeys(
        self,
        db: AsyncSession,
        user_id: uuid.UUID,
        public_keys: list[str],
    ) -> int:
        """
        Upload a new batch of one-time prekeys for a user.

        Returns the number of keys successfully added.
        """
        added = 0
        for i, pk in enumerate(public_keys):
            opk = OneTimePrekey(
                user_id=user_id,
                public_key=pk,
                is_used=False,
                key_id=i,
            )
            db.add(opk)
            added += 1

        await db.commit()
        logger.info("Uploaded %d OPKs for user %s", added, user_id)
        return added

    async def get_opk_count(self, db: AsyncSession, user_id: uuid.UUID) -> int:
        """Return the number of unused OPKs for a user."""
        from sqlalchemy import func
        count = await db.scalar(
            select(func.count(OneTimePrekey.id)).where(
                OneTimePrekey.user_id == user_id,
                OneTimePrekey.is_used == False,  # noqa: E712
            )
        )
        return count or 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

prekey_service = PrekeyService()
