"""
Exception handlers — converts typed exceptions to JSON HTTP responses.
Registered in factory.py during app creation.
"""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import ORJSONResponse

from app.core.exceptions import AppError

logger = logging.getLogger(__name__)


async def app_error_handler(request: Request, exc: AppError) -> ORJSONResponse:
    """Convert AppError subclasses to JSON responses with the appropriate status code."""
    logger.error(
        "AppError [%s] on %s %s: %s",
        exc.error_code,
        request.method,
        request.url.path,
        exc.message,
    )
    return ORJSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.message,
            "error_code": exc.error_code,
        },
    )


async def validation_error_handler(request: Request, exc: Exception) -> ORJSONResponse:
    """Handle Pydantic validation errors."""
    from pydantic import ValidationError
    if isinstance(exc, ValidationError):
        return ORJSONResponse(
            status_code=422,
            content={
                "detail": "Request validation failed",
                "errors": exc.errors(include_url=False),
            },
        )
    return ORJSONResponse(
        status_code=422,
        content={"detail": str(exc)},
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> ORJSONResponse:
    """
    Catch-all for unexpected exceptions.

    Logs the full traceback but returns a generic error to clients
    to avoid leaking internal details.
    """
    logger.exception(
        "Unhandled exception on %s %s",
        request.method,
        request.url.path,
        exc_info=exc,
    )
    return ORJSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please try again.",
            "error_code": "internal_error",
        },
    )


def register_exception_handlers(app) -> None:
    """Register all exception handlers with the FastAPI app."""
    from pydantic import ValidationError
    from fastapi.exceptions import RequestValidationError

    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(ValidationError, validation_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
