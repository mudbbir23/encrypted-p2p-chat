"""
FastAPI application factory — creates the app with full configuration.

Registers:
- CORS middleware
- Lifespan (startup/shutdown hooks)
- All API routers
- Exception handlers

Gracefully degrades when Redis / SurrealDB are unavailable (local dev).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.config import settings
from app.core.exception_handlers import register_exception_handlers
from app.models.Base import init_db

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan: startup before yield, shutdown after.
    """
    # --- STARTUP ---
    logger.info("Starting %s v%s (debug=%s)", settings.APP_NAME, settings.APP_VERSION, settings.DEBUG)

    # Initialize SQLite / PostgreSQL schema
    await init_db()
    logger.info("Database schema initialized")

    # Connect to Redis (optional for local dev)
    try:
        from app.core.redis_manager import redis_manager
        await redis_manager.connect()
        logger.info("Redis connected")
    except Exception as exc:
        logger.warning("Redis unavailable — auth challenges will use in-memory store: %s", exc)

    # Connect to SurrealDB (optional for local dev)
    try:
        from app.core.surreal_manager import surreal_db
        await surreal_db.connect()
        logger.info("SurrealDB connected")
    except Exception as exc:
        logger.warning("SurrealDB unavailable — messages won't persist to SurrealDB: %s", exc)

    logger.info("Application ready — listening for connections")

    yield  # Application is running

    # --- SHUTDOWN ---
    logger.info("Shutting down...")

    try:
        from app.core.surreal_manager import surreal_db
        await surreal_db.disconnect()
    except Exception:
        pass

    try:
        from app.core.redis_manager import redis_manager
        await redis_manager.disconnect()
    except Exception:
        pass

    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    """
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "End-to-end encrypted P2P chat using Signal Protocol "
            "(X3DH + Double Ratchet) and WebAuthn/Passkeys."
        ),
        docs_url="/api/docs",      # always expose in dev
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # -----------------------------------------------------------------------
    # CORS
    # -----------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # -----------------------------------------------------------------------
    # Exception handlers
    # -----------------------------------------------------------------------
    register_exception_handlers(app)

    # -----------------------------------------------------------------------
    # Routers
    # -----------------------------------------------------------------------
    from app.api.auth import router as auth_router
    from app.api.encryption import router as encryption_router
    from app.api.rooms import router as rooms_router
    from app.api.websocket import router as ws_router

    app.include_router(auth_router)
    app.include_router(encryption_router)
    app.include_router(rooms_router)
    app.include_router(ws_router)

    # -----------------------------------------------------------------------
    # Health check
    # -----------------------------------------------------------------------
    @app.get("/health", tags=["health"])
    async def health() -> dict:
        return {
            "status": "ok",
            "version": settings.APP_VERSION,
            "debug": settings.DEBUG,
        }

    return app
