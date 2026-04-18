"""
Common Pydantic response models shared across multiple endpoints.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class MessageResponse(BaseModel):
    """Generic success message response."""
    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Generic error response."""
    detail: str
    error_code: Optional[str] = None


class PaginatedResponse(BaseModel):
    """Wrapper for paginated list responses."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    items: list[Any]
    total: int
    page: int
    page_size: int
    has_next: bool


class UserResponse(BaseModel):
    """Public user data returned after auth or search."""
    id: uuid.UUID
    username: str
    display_name: str
    is_active: bool
    has_keys: bool = False  # True if the user has uploaded encryption keys
