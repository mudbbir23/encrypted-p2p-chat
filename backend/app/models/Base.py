"""
SQLModel base class and async engine/session factory.
All ORM models inherit from BaseDBModel.

Supports:
- PostgreSQL (asyncpg) for production
- SQLite (aiosqlite) for local development — auto-detected by DATABASE_URL prefix
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import Field, SQLModel

from app.config import settings


# ---------------------------------------------------------------------------
# Base model with audit timestamps
# ---------------------------------------------------------------------------

class BaseDBModel(SQLModel):
    """
    All ORM models inherit from this class.
    Provides timezone-aware created_at and updated_at fields.
    """
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
        sa_column_kwargs={"onupdate": lambda: datetime.now(timezone.utc)},
    )


# ---------------------------------------------------------------------------
# Async engine — auto-detects SQLite vs PostgreSQL
# ---------------------------------------------------------------------------

_db_url = str(settings.DATABASE_URL)
_is_sqlite = _db_url.startswith("sqlite")

if _is_sqlite:
    # SQLite: no connection pool settings (StaticPool for single-thread dev)
    from sqlalchemy.pool import StaticPool
    engine = create_async_engine(
        _db_url,
        echo=settings.DEBUG,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    # PostgreSQL: full connection pool
    engine = create_async_engine(
        _db_url,
        echo=settings.DEBUG,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,
    )

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

async def init_db() -> None:
    """Create all tables defined via SQLModel metadata."""
    # Import all models so their metadata is registered before create_all
    import app.models.Credential  # noqa: F401
    import app.models.IdentityKey  # noqa: F401
    import app.models.OneTimePrekey  # noqa: F401
    import app.models.RatchetState  # noqa: F401
    import app.models.SignedPrekey  # noqa: F401
    import app.models.SkippedMessageKey  # noqa: F401
    import app.models.User  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


# ---------------------------------------------------------------------------
# Dependency injection helper
# ---------------------------------------------------------------------------

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
