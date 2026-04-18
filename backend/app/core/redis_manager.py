"""
Redis Manager — ephemeral state for WebAuthn challenges and rate limiting.

When Redis is unavailable (local dev), silently falls back to an in-memory
dict-based store. In-memory store is NOT suitable for production (single-process,
no TTL enforcement, no persistence) but allows zero-dependency local testing.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory fallback store (local dev / testing)
# ---------------------------------------------------------------------------

class _InMemoryStore:
    """Thread-safe-enough (asyncio is single-threaded) challene store."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}  # key → (value, expires_at)

    def set(self, key: str, value: str, ttl: int = 600) -> None:
        self._data[key] = (value, time.monotonic() + ttl)

    def get(self, key: str) -> Optional[str]:
        rec = self._data.get(key)
        if rec is None:
            return None
        value, expires_at = rec
        if time.monotonic() > expires_at:
            del self._data[key]
            return None
        return value

    def get_del(self, key: str) -> Optional[str]:
        val = self.get(key)
        if val is not None:
            self._data.pop(key, None)
        return val

    def incr(self, key: str, ttl: int = 60) -> int:
        rec = self._data.get(key)
        if rec is None or time.monotonic() > rec[1]:
            self._data[key] = ("1", time.monotonic() + ttl)
            return 1
        count = int(rec[0]) + 1
        self._data[key] = (str(count), rec[1])
        return count


_mem_store = _InMemoryStore()


class RedisManager:
    """
    Async Redis client manager with in-memory fallback for local dev.
    """

    def __init__(self) -> None:
        self._client = None
        self._available = False

    async def connect(self) -> None:
        """Initialize the Redis connection pool. Falls back to memory if unavailable."""
        try:
            import redis.asyncio as aioredis
            from redis.asyncio.connection import ConnectionPool

            pool = ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=settings.REDIS_POOL_SIZE,
                decode_responses=False,
            )
            client = aioredis.Redis(connection_pool=pool)
            await client.ping()
            self._client = client
            self._available = True
            logger.info("Redis connected successfully")
        except Exception as exc:
            logger.warning(
                "Redis unavailable (%s) — using in-memory challenge store (dev only)", exc
            )
            self._available = False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
            self._available = False

    # -----------------------------------------------------------------------
    # WebAuthn challenge storage
    # -----------------------------------------------------------------------

    def _reg_key(self, username: str) -> str:
        return f"webauthn:reg_challenge:{username.lower()}"

    def _auth_key(self, username: str) -> str:
        return f"webauthn:auth_challenge:{username.lower()}"

    async def store_registration_challenge(self, username: str, challenge_bytes: bytes) -> None:
        key = self._reg_key(username)
        hex_val = challenge_bytes.hex()
        if self._available and self._client:
            await self._client.set(key, hex_val, ex=settings.WEBAUTHN_CHALLENGE_TTL_SECONDS)
        else:
            _mem_store.set(key, hex_val, ttl=settings.WEBAUTHN_CHALLENGE_TTL_SECONDS)

    async def get_registration_challenge(self, username: str) -> Optional[bytes]:
        key = self._reg_key(username)
        if self._available and self._client:
            async with self._client.pipeline(transaction=True) as pipe:
                await pipe.get(key)
                await pipe.delete(key)
                results = await pipe.execute()
            raw = results[0]
            if raw is None:
                return None
            return bytes.fromhex(raw.decode() if isinstance(raw, bytes) else raw)
        else:
            raw = _mem_store.get_del(key)
            return bytes.fromhex(raw) if raw else None

    async def store_authentication_challenge(self, username: str, challenge_bytes: bytes) -> None:
        key = self._auth_key(username)
        hex_val = challenge_bytes.hex()
        if self._available and self._client:
            await self._client.set(key, hex_val, ex=settings.WEBAUTHN_CHALLENGE_TTL_SECONDS)
        else:
            _mem_store.set(key, hex_val, ttl=settings.WEBAUTHN_CHALLENGE_TTL_SECONDS)

    async def get_authentication_challenge(self, username: str) -> Optional[bytes]:
        key = self._auth_key(username)
        if self._available and self._client:
            async with self._client.pipeline(transaction=True) as pipe:
                await pipe.get(key)
                await pipe.delete(key)
                results = await pipe.execute()
            raw = results[0]
            if raw is None:
                return None
            return bytes.fromhex(raw.decode() if isinstance(raw, bytes) else raw)
        else:
            raw = _mem_store.get_del(key)
            return bytes.fromhex(raw) if raw else None

    # -----------------------------------------------------------------------
    # Rate limiting
    # -----------------------------------------------------------------------

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int = settings.RATE_LIMIT_REQUESTS,
        window_seconds: int = settings.RATE_LIMIT_WINDOW_SECONDS,
    ) -> bool:
        if self._available and self._client:
            rate_key = f"rate_limit:{key}"
            async with self._client.pipeline(transaction=True) as pipe:
                await pipe.incr(rate_key)
                await pipe.expire(rate_key, window_seconds)
                results = await pipe.execute()
            return results[0] <= max_requests
        else:
            count = _mem_store.incr(f"rate_limit:{key}", ttl=window_seconds)
            return count <= max_requests

    # -----------------------------------------------------------------------
    # Generic helpers
    # -----------------------------------------------------------------------

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        if self._available and self._client:
            if ttl_seconds:
                await self._client.set(key, value, ex=ttl_seconds)
            else:
                await self._client.set(key, value)
        else:
            _mem_store.set(key, value, ttl=ttl_seconds or 86400)

    async def get(self, key: str) -> Optional[str]:
        if self._available and self._client:
            val = await self._client.get(key)
            if val is None:
                return None
            return val.decode() if isinstance(val, bytes) else val
        else:
            return _mem_store.get(key)

    async def delete(self, key: str) -> None:
        if self._available and self._client:
            await self._client.delete(key)
        else:
            _mem_store._data.pop(key, None)

    async def exists(self, key: str) -> bool:
        if self._available and self._client:
            return bool(await self._client.exists(key))
        else:
            return _mem_store.get(key) is not None


# Module-level singleton
redis_manager = RedisManager()
