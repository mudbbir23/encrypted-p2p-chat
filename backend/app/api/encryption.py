"""
Encryption API router — prekey bundle endpoints for X3DH session initiation.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import BaseModel

from app.models.Base import get_session
from app.schemas.websocket import PreKeyBundleResponse
from app.services.prekey_service import prekey_service

router = APIRouter(prefix="/api/encryption", tags=["encryption"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


class OPKUploadRequest(BaseModel):
    """Request body for uploading a batch of one-time prekeys."""
    public_keys: list[str]

@router.get("/prekey-bundle/{user_id}", response_model=PreKeyBundleResponse)
async def get_prekey_bundle(
    user_id: uuid.UUID,
    db: DBSession,
) -> PreKeyBundleResponse:
    """
    Fetch a prekey bundle for the target user.

    Used by the initiating client (Alice) to establish an X3DH session
    with the target user (Bob) asynchronously.

    One OPK is atomically consumed per request.
    If no OPKs are available, the bundle is returned without one
    (the X3DH still works with 3 DH operations instead of 4).
    """
    bundle = await prekey_service.get_prekey_bundle(db=db, target_user_id=user_id)
    return bundle


@router.post("/one-time-prekeys/{user_id}")
async def upload_one_time_prekeys(
    user_id: uuid.UUID,
    request: OPKUploadRequest,
    db: DBSession,
) -> dict:
    """
    Replenish one-time prekeys for a user.

    Called when the OPK count drops below the replenishment threshold.
    Only the public components are uploaded; private keys stay in the browser.
    """
    count = await prekey_service.upload_one_time_prekeys(
        db=db, user_id=user_id, public_keys=request.public_keys
    )
    return {"uploaded": count}


@router.get("/opk-count/{user_id}")
async def get_opk_count(user_id: uuid.UUID, db: DBSession) -> dict:
    """Return the number of unused OPKs available for a user."""
    count = await prekey_service.get_opk_count(db=db, user_id=user_id)
    return {"user_id": str(user_id), "available_opks": count}
