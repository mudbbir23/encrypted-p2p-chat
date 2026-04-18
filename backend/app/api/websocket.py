"""
WebSocket API endpoint.

Authenticates users via a query parameter (user_id) and hands off
to WebSocketService for the full connection lifecycle.

In production, implement proper session token validation here.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.exceptions import ConnectionLimitExceededError
from app.services.websocket_service import WebSocketService

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: uuid.UUID = Query(..., description="Authenticated user ID"),
    username: str = Query(default="anonymous", max_length=50),
) -> None:
    """
    WebSocket endpoint for real-time encrypted messaging.

    Query parameters:
    - user_id: The authenticated user's UUID
    - username: The user's display username

    Note: In production, authenticate via a signed session token rather than
    raw user_id to prevent impersonation.
    """
    service = WebSocketService(
        websocket=websocket,
        user_id=user_id,
        username=username,
    )

    try:
        await service.run()
    except ConnectionLimitExceededError as exc:
        # Can't add connection — send close frame and return
        await websocket.accept()
        await websocket.close(code=4429, reason=exc.message)
    except WebSocketDisconnect:
        pass  # Normal disconnect, already cleaned up in service.run()
