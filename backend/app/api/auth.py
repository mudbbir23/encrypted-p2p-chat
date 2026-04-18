"""
Auth API router — WebAuthn registration and authentication endpoints.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.Base import get_session
from app.schemas.auth import (
    AuthenticateBeginRequest,
    AuthenticateCompleteRequest,
    RegisterBeginRequest,
    RegisterCompleteRequest,
    UploadKeysRequest,
)
from app.schemas.common import MessageResponse, UserResponse
from app.services.auth_service import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


@router.post("/register/begin")
async def register_begin(
    request: RegisterBeginRequest,
    db: DBSession,
) -> Any:
    """
    Step 1 of WebAuthn registration.

    Returns PublicKeyCredentialCreationOptions for the browser to pass to
    navigator.credentials.create(). A challenge is stored in Redis with a
    10-minute TTL.
    """
    options = await auth_service.begin_registration(db=db, request=request)
    return options


@router.post("/register/complete")
async def register_complete(
    request: RegisterCompleteRequest,
    db: DBSession,
) -> UserResponse:
    """
    Step 2 of WebAuthn registration.

    Verifies the authenticator's attestation response, creates the user and
    credential records, and returns the new user's public profile.
    """
    user = await auth_service.complete_registration(
        db=db,
        username=request.username,
        display_name=request.display_name or request.username,
        credential=request.credential,
    )
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_active=user.is_active,
        has_keys=bool(user.identity_key),
    )


@router.get("/users/{username}")
async def get_user(
    username: str,
    db: DBSession,
) -> UserResponse:
    """
    Look up a user by their exact username to start a chat.
    """
    try:
        user = await auth_service.get_user_by_username(db, username=username)
    except Exception as e:
        raise HTTPException(status_code=404, detail="User not found")
        
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_active=user.is_active,
        has_keys=bool(user.identity_key),
    )


@router.post("/authenticate/begin")
async def authenticate_begin(
    request: AuthenticateBeginRequest,
    db: DBSession,
) -> Any:
    """
    Step 1 of WebAuthn authentication.

    Returns PublicKeyCredentialRequestOptions for navigator.credentials.get().
    """
    options = await auth_service.begin_authentication(db=db, username=request.username)
    return options


@router.post("/authenticate/complete")
async def authenticate_complete(
    request: AuthenticateCompleteRequest,
    db: DBSession,
) -> dict:
    """
    Step 2 of WebAuthn authentication.

    Verifies the authenticator signature and returns a session object.
    """
    session = await auth_service.complete_authentication(
        db=db,
        username=request.username,
        credential=request.credential,
    )
    return {
        "user_id": str(session.user_id),
        "username": session.username,
        "display_name": session.display_name,
    }


@router.post("/keys/{user_id}")
async def upload_keys(
    user_id: uuid.UUID,
    request: UploadKeysRequest,
    db: DBSession,
) -> MessageResponse:
    """
    Upload public encryption keys after registration.

    Called by the client after generating X25519 and Ed25519 keypairs
    in the browser. Private keys NEVER leave the client.
    """
    await auth_service.upload_keys(db=db, user_id=user_id, request=request)
    return MessageResponse(message="Keys uploaded successfully")
