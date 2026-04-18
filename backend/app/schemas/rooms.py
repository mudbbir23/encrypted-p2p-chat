"""
Room-related request/response schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CreateRoomRequest(BaseModel):
    """Create a new 1:1 or group chat room."""
    name: Optional[str] = Field(default=None, max_length=100)
    participant_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    is_group: bool = False


class RoomResponse(BaseModel):
    """Public view of a chat room."""
    id: uuid.UUID
    name: Optional[str] = None
    is_group: bool
    participant_ids: list[uuid.UUID]
    created_at: datetime
    last_message_at: Optional[datetime] = None


class RoomListResponse(BaseModel):
    rooms: list[RoomResponse]
    total: int
