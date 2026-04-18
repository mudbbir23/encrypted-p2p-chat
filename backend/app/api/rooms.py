"""
Rooms API router — room creation and management.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.surreal_manager import surreal_db
from app.models.Base import get_session
from app.schemas.rooms import CreateRoomRequest, RoomListResponse, RoomResponse

router = APIRouter(prefix="/api/rooms", tags=["rooms"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


@router.post("/", response_model=RoomResponse)
async def create_room(
    request: CreateRoomRequest,
    db: DBSession,
) -> RoomResponse:
    """
    Create a new chat room.

    For 1:1 chats, the room is keyed by the sorted pair of participant IDs
    so that a duplicate room is never created for the same two users.
    """
    room_id = uuid.uuid4()

    # For 1:1 chats, generate a deterministic room ID from the participant pair
    if not request.is_group and len(request.participant_ids) == 2:
        sorted_ids = sorted(str(p) for p in request.participant_ids)
        import hashlib
        deterministic_bytes = hashlib.sha256(
            "|".join(sorted_ids).encode()
        ).digest()[:16]
        room_id = uuid.UUID(bytes=deterministic_bytes)

    participant_strs = [str(p) for p in request.participant_ids]

    await surreal_db.create_room(
        room_id=str(room_id),
        name=request.name,
        is_group=request.is_group,
        participant_ids=participant_strs,
        created_by=participant_strs[0],  # First participant is the creator
    )

    return RoomResponse(
        id=room_id,
        name=request.name,
        is_group=request.is_group,
        participant_ids=request.participant_ids,
        created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )


@router.get("/user/{user_id}", response_model=RoomListResponse)
async def get_rooms_for_user(user_id: uuid.UUID) -> RoomListResponse:
    """Get all rooms the user participates in."""
    rooms_raw = await surreal_db.get_rooms_for_user(str(user_id))
    rooms = []
    for r in rooms_raw:
        try:
            rooms.append(RoomResponse(
                id=uuid.UUID(str(r.get("id", uuid.uuid4())).replace("rooms:", "")),
                name=r.get("name"),
                is_group=r.get("is_group", False),
                participant_ids=[uuid.UUID(p) for p in r.get("participant_ids", [])],
                created_at=r.get("created_at"),
                last_message_at=r.get("last_message_at"),
            ))
        except Exception:
            continue

    return RoomListResponse(rooms=rooms, total=len(rooms))


@router.get("/{room_id}/messages")
async def get_room_messages(
    room_id: uuid.UUID,
    limit: int = 50,
) -> dict:
    """
    Retrieve paginated message history for a room.

    Messages are returned as encrypted blobs — the server does NOT decrypt.
    The client decrypts using its local ratchet state.
    """
    messages = await surreal_db.get_messages_for_room(
        room_id=str(room_id),
        limit=min(limit, 200),
    )
    return {"messages": messages, "count": len(messages)}
