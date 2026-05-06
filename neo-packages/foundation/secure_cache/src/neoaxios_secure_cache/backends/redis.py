# Copyright 2026 NeoAxios LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Redis cache backend implementation.

This module implements RedisCacheBackend - a Redis-backed distributed cache
with TTL-based expiration and async operations. Extracted from neoaxios_fastapi_kit
and adapted to implement the secure_cache.protocols.CacheBackend protocol.

Usage:
    from neoaxios_secure_cache.backends.redis import create_redis_backend

    # Using factory function (recommended for 3-parameter constructor)
    cache = create_redis_backend(
        default_ttl_seconds=300,
        pool_size=10,
    )
    await cache.set("key", {"data": "value"}, ttl_seconds=300)
    value = await cache.get("key")

Implementation Notes:
    - Requires redis>=5.0.0 package
    - Uses redis.asyncio for async operations
    - Lazy connection initialization (thread-safe)
    - JSON serialization for complex values
    - SETEX for atomic set-with-TTL
    - Factory function for clean instantiation (4+ parameters)
"""

import asyncio
import json
from typing import Any, Optional

from neoaxios_logging import auto_trace, get_telemetry, TraceDisabledReason

from neoaxios_secure_cache.defaults import (
    CACHE_TTL_SHORT,
    REDIS_POOL_SIZE_CLIENT,
    REDIS_POOL_WAIT_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
)

logger = get_telemetry(__name__)

_BATCH_SIZE = 100


async def scan_and_unlink(client: Any, pattern: str) -> int:
    """SCAN for keys matching pattern and batch-delete via pipelined UNLINKs.

    Shared utility used by RedisCacheBackend.invalidate_by_prefix and
    SequenceTracker.clear_tenant to avoid duplicating the scan+batch+unlink
    pattern.

    Uses pipelined individual DELETEs (cluster-safe) instead of variadic
    ``client.unlink(*batch)`` to avoid CROSSSLOT errors under Redis Cluster.

    Note: Uses DELETE instead of UNLINK because ClusterPipeline.unlink is
    async while Pipeline.unlink is sync (redis-py inconsistency). DELETE is
    sync on both. In a pipeline context the two are functionally identical —
    UNLINK's only advantage (background memory reclamation) is irrelevant
    when commands batch-execute together.

    Args:
        client: Redis async client
        pattern: SCAN match pattern (e.g., "prefix:*")

    Returns:
        Number of keys deleted
    """
    deleted_count = 0
    batch: list[str] = []

    async for key in client.scan_iter(match=pattern, count=_BATCH_SIZE):
        batch.append(key)
        if len(batch) >= _BATCH_SIZE:
            pipe = client.pipeline(transaction=False)
            for k in batch:
                pipe.delete(k)
            results = await pipe.execute()
            deleted_count += sum(r for r in results if isinstance(r, int))
            batch = []

    if batch:
        pipe = client.pipeline(transaction=False)
        for k in batch:
            pipe.delete(k)
        results = await pipe.execute()
        deleted_count += sum(r for r in results if isinstance(r, int))

    return deleted_count


class RedisCacheBackend:
    """Redis-backed cache implementation.

    Uses Redis for distributed caching with TTL-based expiration.
    Implements CacheBackend protocol for compatibility with secure_cache
    security wrappers (signing, encryption).

    Requires `redis` package: pip install redis>=5.0.0

    Attributes:
        default_ttl_seconds: Default time-to-live in seconds
        pool_size: Connection pool size
        socket_timeout: Socket timeout in seconds
        _redis: Redis async client instance (lazy initialized)
        _lock: Asyncio lock for thread-safe initialization

    Example:
        # Use factory function for instantiation
        cache = create_redis_backend(
            default_ttl_seconds=300,
            pool_size=10,
        )
        await cache.set("key", {"data": "value"}, ttl_seconds=300)
        value = await cache.get("key")
    """

    @auto_trace(logger)
    def __init__(
        self,
        default_ttl_seconds: int = CACHE_TTL_SHORT,
        pool_size: int = REDIS_POOL_SIZE_CLIENT,
        socket_timeout: float = REDIS_SOCKET_TIMEOUT,
        pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT,
    ) -> None:
        """Initialize Redis cache backend.

        Args:
            default_ttl_seconds: Default time-to-live in seconds
            pool_size: Connection pool size
            socket_timeout: Socket timeout in seconds
            pool_wait_timeout: How long to wait for a free pool connection (seconds)
        """
        self.default_ttl_seconds = default_ttl_seconds
        self.pool_size = pool_size
        self.socket_timeout = socket_timeout
        self.pool_wait_timeout = pool_wait_timeout
        self._redis: Optional[Any] = None
        self._lock = asyncio.Lock()

        logger.info(
            "redis_cache_backend_initialized",
            default_ttl_seconds=default_ttl_seconds,
            pool_size=pool_size,
            socket_timeout=socket_timeout,
            pool_wait_timeout=pool_wait_timeout,
        )

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    async def _get_client(self) -> Any:
        """Get or create Redis client (lazy initialization).

        Thread-safe lazy initialization of Redis connection using
        double-checked locking pattern. Uses the centralized factory.

        Returns:
            Redis async client instance

        Raises:
            ConnectionError: If unable to connect to Redis
        """
        if self._redis is None:
            async with self._lock:
                # Double-check after acquiring lock
                if self._redis is None:
                    # All Redis connections via gateway
                    from neoaxios_secure_cache.gateway import get_gateway

                    self._redis = get_gateway().get_async_client(
                        "cache", pool_size=self.pool_size,
                        decode_responses=True,
                        socket_timeout=self.socket_timeout,
                        pool_wait_timeout=self.pool_wait_timeout,
                    )
                    logger.info("redis_cache_backend_client_created")

        return self._redis

    @staticmethod
    def _serialize_value(value: Any) -> str:
        """Serialize a value to JSON, converting frozensets/sets to lists."""
        if isinstance(value, (frozenset, set)):
            value = list(value)
        return json.dumps(value, default=str)

    @auto_trace(logger)
    async def get(self, key: str) -> Optional[Any]:
        """Retrieve value from Redis cache.

        Args:
            key: Cache key

        Returns:
            Deserialized cached value or None if missing/expired

        Raises:
            ConnectionError: If Redis connection fails
            TimeoutError: If Redis operation times out

        Note:
            Returns None on JSON decode errors (corrupt data).
        """
        try:
            client = await self._get_client()
            data = await client.get(key)

            if data is None:
                logger.debug(f"Cache miss for key '{key}'")
                return None

            # Deserialize JSON data
            value = json.loads(data)
            logger.debug(f"Cache hit for key '{key}'")

            return value

        except json.JSONDecodeError as e:
            logger.log_error(
                Exception(f"Failed to deserialize cache value for key '{key}': {e}")
            )
            return None
        except (ConnectionError, TimeoutError):
            raise
        except Exception as e:
            logger.log_error(Exception(f"Redis GET error for key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value in Redis cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time-to-live in seconds

        Raises:
            Exception: If Redis operation fails
        """
        try:
            client = await self._get_client()
            data = self._serialize_value(value)

            # Set with expiration using SETEX (atomic operation)
            await client.setex(key, ttl_seconds, data)
            logger.debug(f"Cached key '{key}' with TTL={ttl_seconds}s")

        except Exception as e:
            logger.log_error(Exception(f"Redis SET error for key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def delete(self, key: str) -> None:
        """Remove key from Redis cache.

        Args:
            key: Cache key to remove

        Raises:
            Exception: If Redis operation fails
        """
        try:
            client = await self._get_client()
            deleted = await client.unlink(key)
            logger.debug(f"Deleted key '{key}' (removed={deleted})")
        except Exception as e:
            logger.log_error(Exception(f"Redis DELETE error for key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists, False otherwise

        Raises:
            ConnectionError: If Redis connection fails
            TimeoutError: If Redis operation times out
        """
        try:
            client = await self._get_client()
            result = await client.exists(key)
            return bool(result)
        except Exception as e:
            logger.log_error(Exception(f"Redis EXISTS error for key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def ping(self) -> bool:
        """Check Redis connection health.

        Returns:
            True if Redis is reachable, False otherwise
        """
        try:
            client = await self._get_client()
            await client.ping()
            return True
        except Exception as e:
            logger.log_error(Exception(f"Redis ping failed: {e}"))
            return False

    @auto_trace(logger)
    async def mget(self, keys: list[str]) -> list[Any | None]:
        """Retrieve multiple values from Redis via pipelined individual GETs.

        Uses pipelined individual GETs (cluster-safe) instead of native
        ``MGET`` to avoid CROSSSLOT errors under Redis Cluster topology.
        Keys are chunked into batches of 100 to bound per-pipeline size.

        Args:
            keys: List of cache keys to retrieve

        Returns:
            List aligned with input keys; None for missing or failed entries

        Raises:
            ConnectionError: If Redis connection fails
            TimeoutError: If Redis operation times out
        """
        if not keys:
            return []

        try:
            client = await self._get_client()
            batch_size = 100
            raw_values: list[Any] = []
            for offset in range(0, len(keys), batch_size):
                batch = keys[offset:offset + batch_size]
                pipe = client.pipeline(transaction=False)
                for key in batch:
                    pipe.get(key)
                raw_values.extend(await pipe.execute())

            results: list[Any | None] = []
            for i, data in enumerate(raw_values):
                if data is None:
                    results.append(None)
                    continue
                try:
                    results.append(json.loads(data))
                except json.JSONDecodeError as e:
                    logger.log_error(
                        Exception(f"Failed to deserialize cache value for key '{keys[i]}': {e}")
                    )
                    results.append(None)

            return results

        except Exception as e:
            logger.log_error(Exception(f"Redis MGET error: {e}"))
            raise

    @auto_trace(logger)
    async def mset(self, items: list[tuple[str, Any, int]]) -> None:
        """Store multiple values in Redis using a pipeline with per-key SETEX.

        Native MSET does not support per-key TTL, so a pipeline of SETEX
        commands is used to achieve batch set with individual TTLs.
        Items are chunked into batches of 100 to bound per-pipeline size.

        Args:
            items: List of (key, value, ttl_seconds) tuples to store

        Raises:
            Exception: If pipeline execution fails
        """
        if not items:
            return

        try:
            client = await self._get_client()

            for offset in range(0, len(items), _BATCH_SIZE):
                batch = items[offset:offset + _BATCH_SIZE]
                pipe = client.pipeline(transaction=False)

                for key, value, ttl_seconds in batch:
                    data = self._serialize_value(value)
                    pipe.setex(key, ttl_seconds, data)

                await pipe.execute()

            logger.debug(f"Batch set {len(items)} keys via pipeline")

        except Exception as e:
            logger.log_error(Exception(f"Redis MSET pipeline error: {e}"))
            raise

    @auto_trace(logger)
    async def mdelete(self, keys: list[str]) -> int:
        """Delete multiple keys from Redis via pipelined individual UNLINKs.

        Uses pipelined individual UNLINKs (cluster-safe) instead of
        variadic ``client.unlink(*keys)`` to avoid CROSSSLOT errors
        under Redis Cluster topology. Keys are chunked into batches
        of 100 to bound per-pipeline size.

        Args:
            keys: List of cache keys to delete

        Returns:
            Count of keys that were successfully deleted

        Raises:
            ConnectionError: If Redis connection fails
            TimeoutError: If Redis operation times out
        """
        if not keys:
            return 0

        try:
            client = await self._get_client()
            batch_size = 100
            deleted = 0
            for offset in range(0, len(keys), batch_size):
                batch = keys[offset:offset + batch_size]
                pipe = client.pipeline(transaction=False)
                for key in batch:
                    pipe.delete(key)
                results = await pipe.execute()
                deleted += sum(r for r in results if isinstance(r, int))
            logger.debug(f"Batch deleted {deleted} of {len(keys)} keys")
            return deleted

        except Exception as e:
            logger.log_error(Exception(f"Redis MDELETE error: {e}"))
            raise

    @auto_trace(logger)
    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries matching a key prefix.

        Uses SCAN for memory-efficient pattern matching instead of KEYS.

        Args:
            prefix: Key prefix to match

        Returns:
            Number of entries removed
        """
        try:
            client = await self._get_client()
            deleted_count = await scan_and_unlink(client, f"{prefix}*")

            logger.debug(f"Invalidated {deleted_count} Redis keys matching prefix '{prefix}'")
            return deleted_count

        except Exception as e:
            logger.log_error(Exception(f"Redis invalidate_by_prefix error for '{prefix}': {e}"))
            raise

    @auto_trace(logger)
    async def keys_by_prefix(self, prefix: str) -> list[str]:
        """Return all keys matching a key prefix.

        Uses SCAN for memory-efficient pattern matching instead of KEYS.

        Args:
            prefix: Key prefix to match

        Returns:
            List of matching keys
        """
        try:
            client = await self._get_client()
            keys: list[str] = []
            scan_pattern = f"{prefix}*"

            async for key in client.scan_iter(match=scan_pattern, count=_BATCH_SIZE):
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="ignore")
                keys.append(key)

            return keys

        except Exception as e:
            logger.log_error(Exception(f"Redis keys_by_prefix error for '{prefix}': {e}"))
            raise

    @auto_trace(logger)
    async def close(self) -> None:
        """Release Redis client reference.

        The gateway owns client lifecycle. This method
        clears the local reference so the next operation re-acquires from
        the gateway. Actual connection shutdown happens via
        ``get_gateway().close_all()`` at process shutdown.
        """
        if self._redis is not None:
            self._redis = None
            logger.info("Cleared Redis client reference")


@auto_trace(logger)
def create_redis_backend(
    default_ttl_seconds: int = CACHE_TTL_SHORT,
    pool_size: int = REDIS_POOL_SIZE_CLIENT,
    socket_timeout: float = REDIS_SOCKET_TIMEOUT,
    pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT,
) -> RedisCacheBackend:
    """Factory function for RedisCacheBackend.

    Creates a RedisCacheBackend instance with validated parameters.
    Redis connections are obtained from the centralized gateway —
    no URL is needed here.

    Args:
        default_ttl_seconds: Default time-to-live in seconds
        pool_size: Connection pool size
        socket_timeout: Socket timeout in seconds for Redis operations
        pool_wait_timeout: How long to wait for a free pool connection (seconds)

    Returns:
        Configured RedisCacheBackend instance

    Example:
        cache = create_redis_backend(
            default_ttl_seconds=300,
            pool_size=10,
        )
    """
    # Validate numeric parameters
    if default_ttl_seconds <= 0:
        raise ValueError(f"default_ttl_seconds must be positive (got: {default_ttl_seconds})")

    if pool_size <= 0:
        raise ValueError(f"pool_size must be positive (got: {pool_size})")

    return RedisCacheBackend(
        default_ttl_seconds=default_ttl_seconds,
        pool_size=pool_size,
        socket_timeout=socket_timeout,
        pool_wait_timeout=pool_wait_timeout,
    )
