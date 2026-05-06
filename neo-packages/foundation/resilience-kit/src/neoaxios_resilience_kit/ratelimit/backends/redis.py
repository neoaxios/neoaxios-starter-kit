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

"""Redis backend for rate limit state storage with key isolation.

IMPORTANT: This backend extends secure_cache.RedisCacheBackend to reuse:
- Connection pooling (lazy initialization via _get_client())
- TLS validation
- Health checks
- Error handling

Key Features:
- CacheNamespace(domain="ratelimit"): Enforces key prefix isolation
- atomic_check_and_add(): Single Lua script eliminates race conditions
- scoped_cleanup(): Only deletes keys within backend's namespace

TLS is required in production (rediss://). The factory function exists to keep
constructor argument counts bounded.
"""

from __future__ import annotations

import asyncio
import time
from typing import NoReturn

import redis.exceptions
from neoaxios_secure_cache import RedisCacheBackend as SecureCacheRedisBackend
from neoaxios_secure_cache.defaults import (
    CACHE_TTL_MEDIUM,
    REDIS_POOL_SIZE_RATELIMIT,
    REDIS_POOL_WAIT_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
)
from neoaxios_secure_cache import CacheNamespace
from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from ..exceptions import RateLimitBackendError
from ..protocols import RateLimitResult
from ..utils import _generate_window_members

logger = get_telemetry(__name__)

# Batch size for scoped_cleanup delete operations.
_CLEANUP_DELETE_BATCH_SIZE = 100

# Lua script for atomic token bucket operations
# Parameters: KEYS[1]=key, ARGV[1]=now, ARGV[2]=capacity, ARGV[3]=window, ARGV[4]=cost, ARGV[5]=timeout
_ATOMIC_TOKEN_BUCKET_SCRIPT = """
-- Token bucket Lua script for atomic operations
-- Parameters:
--   key: Rate limit key
--   now: Current timestamp (unix seconds, sub-second precision)
--   capacity: Burst capacity in tokens
--   window: Refill window in seconds
--   cost: Tokens to consume
--   timeout: Bucket expiry time (seconds)

local key = KEYS[1]
local now = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local timeout = tonumber(ARGV[5])

-- Fetch current bucket state from hash fields
local raw_last_refill = redis.call('HGET', key, 'last_refill')
local raw_tokens = redis.call('HGET', key, 'tokens')

local last_refill = 0
local tokens = capacity

if raw_last_refill and raw_tokens then
    last_refill = tonumber(raw_last_refill)
    tokens = tonumber(raw_tokens)
end

-- Calculate refill rate: tokens per second
local refill_rate = capacity / window

-- Calculate tokens gained since last refill
local elapsed = math.max(0, now - last_refill)
local tokens_gained = elapsed * refill_rate

-- Refill bucket (capped at capacity)
tokens = math.min(capacity, tokens + tokens_gained)

-- Check if request can be allowed
local allowed = 0
if tokens >= cost then
    allowed = 1
    tokens = tokens - cost
end

-- Update bucket with new state
if allowed == 1 or tokens > 0 then
    redis.call('HSET', key, 'last_refill', now, 'tokens', tokens)
    redis.call('EXPIRE', key, timeout)
end

-- Calculate reset time (when bucket will be full again if empty)
-- If tokens < capacity, reset = now + (capacity - tokens) / refill_rate
local reset_at = now
if tokens < capacity then
    reset_at = now + math.ceil((capacity - tokens) / refill_rate)
end

-- Calculate retry-after (seconds until request would be allowed)
-- If denied: retry_after = ceil(cost / refill_rate)
local retry_after = 0
if allowed == 0 then
    retry_after = math.ceil(cost / refill_rate)
end

-- Return: {allowed, remaining_tokens, reset_at, retry_after}
return {allowed, math.floor(tokens), reset_at, retry_after}
"""


# Lua script for atomic check-and-add operation
# Eliminates race conditions between sliding_window_check and sliding_window_add
_ATOMIC_CHECK_AND_ADD_SCRIPT = """
-- KEYS[1]: Rate limit key
-- ARGV[1]: window_start (remove entries older than this)
-- ARGV[2]: limit (max allowed in window)
-- ARGV[3]: cost (number of entries to add)
-- ARGV[4]: now (current timestamp for new entries)
-- ARGV[5]: window_seconds (for TTL)
-- ARGV[6..]: member strings to add (pre-generated for uniqueness)

local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local window_seconds = tonumber(ARGV[5])

-- Step 1: Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Step 2: Count current entries
local current_count = redis.call('ZCARD', key)

-- Step 3: Check if adding cost would exceed limit
local allowed = (current_count + cost) <= limit
local remaining = 0

if allowed then
    -- Step 4: Add new entries atomically
    local members = {}
    for i = 6, #ARGV do
        members[#members + 1] = now  -- score
        members[#members + 1] = ARGV[i]  -- member
    end
    if #members > 0 then
        redis.call('ZADD', key, unpack(members))
    end

    -- Step 5: Set TTL
    redis.call('EXPIRE', key, window_seconds + 1)

    remaining = limit - current_count - cost
else
    remaining = 0
end

-- Calculate retry_after for denied requests (avoids extra RTT)
local retry_after = 0
if not allowed then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    if #oldest >= 2 then
        retry_after = math.max(1, math.floor(tonumber(oldest[2]) + window_seconds - now) + 1)
    else
        retry_after = window_seconds
    end
end

-- Return: allowed (0/1), remaining, current_count, reset_at, retry_after
local reset_at = math.floor(now + window_seconds)
return {allowed and 1 or 0, remaining, current_count, reset_at, retry_after}
"""


class RedisRateLimitBackend(SecureCacheRedisBackend):
    """Redis-backed storage for rate limiting with key namespace isolation.

    Extends secure_cache.RedisCacheBackend to reuse connection pooling,
    TLS validation, and health check infrastructure.

    Key Features:
        - CacheNamespace(domain="ratelimit"): Mandatory isolation
          prevents cross-client interference
        - atomic_check_and_add(): Lua script eliminates race conditions
        - scoped_cleanup(): Only deletes keys in this backend's namespace

    Implementation Details:
        - Uses Redis ZSET (Sorted Set) for sliding window storage
        - ZSET members: "{timestamp}:{random_token}:{index}" for uniqueness
        - ZSET scores: Unix timestamp (for range queries)
        - TTL set to window_seconds + 1 to handle edge cases
        - All pipeline() calls use transaction=False for Redis Cluster safety
        - scoped_cleanup() uses per-key delete for Redis Cluster safety

    Example:
        backend = create_redis_ratelimit_backend(
            org="neo",
            app="gateway",
            service="api-gateway",
            environment="prod",
        )

        # Atomic rate limit check (preferred).
        # Key suffixes are automatically namespaced by the backend.
        result = await backend.atomic_check_and_add(
            key="user:123:endpoint",
            limit=100,
            window_seconds=60,
            cost=1,
        )

        if not result.allowed:
            raise RateLimitExceeded(retry_after=result.retry_after)
    """

    def __init__(
        self,
        namespace: CacheNamespace,
        default_ttl_seconds: int = CACHE_TTL_MEDIUM,
        pool_size: int = REDIS_POOL_SIZE_RATELIMIT,
        socket_timeout: float = REDIS_SOCKET_TIMEOUT,
        pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT,
    ) -> None:
        """Initialize with mandatory namespace.

        Redis connections are obtained from the centralized cache gateway
        -- no URL is needed here.

        Args:
            namespace: CacheNamespace for key isolation (required)
            default_ttl_seconds: Default TTL for keys
            pool_size: Connection pool size
            socket_timeout: Socket timeout in seconds
            pool_wait_timeout: How long to wait for a free pool connection (seconds)
        """
        super().__init__(
            default_ttl_seconds=default_ttl_seconds,
            pool_size=pool_size,
            socket_timeout=socket_timeout,
            pool_wait_timeout=pool_wait_timeout,
        )
        self._namespace = namespace

    @property
    def namespace(self) -> CacheNamespace:
        """Get the key namespace for this backend."""
        return self._namespace

    @classmethod
    @auto_trace(logger)
    def create(
        cls,
        namespace: CacheNamespace,
        max_connections: int = REDIS_POOL_SIZE_RATELIMIT,
        socket_timeout: float = REDIS_SOCKET_TIMEOUT,
        pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT,
    ) -> "RedisRateLimitBackend":
        """Create backend with namespace isolation.

        Redis connections are obtained from the centralized cache gateway
        -- no URL is needed here.

        Args:
            namespace: CacheNamespace for key isolation (required)
            max_connections: Connection pool size
            socket_timeout: Socket timeout in seconds
            pool_wait_timeout: How long to wait for a free pool connection (seconds)

        Returns:
            Configured RedisRateLimitBackend instance

        Example:
            from neoaxios_secure_cache import CacheNamespace

            namespace = CacheNamespace(
                org="neo", env="prod", service="api", app="checkout",
                domain="ratelimit",
            )

            backend = RedisRateLimitBackend.create(
                namespace=namespace,
            )
        """
        instance = cls(
            namespace=namespace,
            pool_size=max_connections,
            socket_timeout=socket_timeout,
            pool_wait_timeout=pool_wait_timeout,
        )

        logger.info(
            "Initialized RedisRateLimitBackend",
            namespace=namespace.domain_scope(),
            max_connections=max_connections,
        )

        return instance

    def _raise_backend_error(
        self, message: str, error: Exception
    ) -> NoReturn:
        """Log the original exception and raise RateLimitBackendError.

        Centralizes the error-handling pattern used across all Redis
        operations to eliminate duplication.

        Args:
            message: Human-readable message for the RateLimitBackendError
            error: The original caught exception (logged and chained)

        Raises:
            RateLimitBackendError: Always raised with original error chained
        """
        logger.log_error(error)
        raise RateLimitBackendError(
            message=message,
            original_error=error,
            backend_type="redis",
        ) from error

    @staticmethod
    def _parse_lua_result(
        result: list | tuple, full_key: str
    ) -> RateLimitResult:
        """Validate and unpack the Lua script return value.

        Args:
            result: Raw return from Redis EVAL (expected 5-element array)
            full_key: The namespaced key (for debug logging)

        Returns:
            Parsed RateLimitResult

        Raises:
            ValueError: If result structure is unexpected.
        """
        if not isinstance(result, (list, tuple)) or len(result) != 5:
            result_len = (
                len(result) if hasattr(result, "__len__") else "N/A"
            )
            raise ValueError(
                f"Unexpected Lua script return: expected "
                f"5-element array, got "
                f"{type(result).__name__} with "
                f"{result_len} elements"
            )

        allowed = bool(result[0])
        remaining = int(result[1])
        current_count = int(result[2])
        reset_at = int(result[3])
        retry_after = int(result[4])

        logger.debug(
            "Atomic rate limit check completed",
            key=full_key,
            allowed=allowed,
            remaining=remaining,
            current_count=current_count,
        )

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _make_full_key(self, key_suffix: str) -> str:
        """Create full namespaced key from suffix.

        All public methods call this to transparently namespace keys,
        so callers pass logical key suffixes (consistent with InMemoryRateLimitBackend).

        Args:
            key_suffix: Logical key suffix (e.g., "user:123:endpoint")

        Returns:
            Full namespaced key via CacheNamespace.make_key()
            (e.g., "org:neo:env:prod:svc:api:app:api:v1:d:ratelimit:user:123:endpoint")

        Raises:
            ValueError: If suffix contains forbidden characters
        """
        return self._namespace.make_key(key_suffix)

    @auto_trace(logger)
    async def atomic_check_and_add(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Atomically check rate limit and add entries if allowed.

        This is the PRIMARY method for rate limiting. It uses a Lua script
        to ensure the entire check-and-add operation is atomic, preventing
        race conditions that could occur with separate check/add calls.

        The key suffix is automatically namespaced by the backend to ensure
        key isolation between services sharing a Redis instance.

        Args:
            key: Rate limit key suffix (e.g., "user:123:api").
                 Automatically namespaced by the backend.
            limit: Maximum requests allowed in window
            window_seconds: Window duration in seconds
            cost: Number of requests to add (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata

        Example:
            result = await backend.atomic_check_and_add(
                key="user:123:api",
                limit=100,
                window_seconds=60,
                cost=1,
            )
            if not result.allowed:
                raise RateLimitExceeded(retry_after=result.retry_after)
        """
        # Namespace the key before any Redis operations.
        # ValueError from make_key (forbidden chars) propagates to caller.
        full_key = self._make_full_key(key)

        try:
            client = await self._get_client()

            # Capture timestamp AFTER acquiring client to avoid drift
            # under pool contention.
            now = time.time()
            window_start = now - window_seconds

            # Generate unique members for this request
            entries = _generate_window_members(now, cost)
            members = [member for member, _ in entries]

            # Execute atomic Lua script
            result = await client.eval(
                _ATOMIC_CHECK_AND_ADD_SCRIPT,
                1,  # Number of keys
                full_key,  # KEYS[1]
                window_start,  # ARGV[1]
                limit,  # ARGV[2]
                cost,  # ARGV[3]
                now,  # ARGV[4]
                window_seconds,  # ARGV[5]
                *members,  # ARGV[6..]
            )

            return self._parse_lua_result(result, full_key)

        except Exception as e:
            # Fail-closed: deny request if Redis fails.
            self._raise_backend_error("Rate limit backend unavailable", e)

    @auto_trace(logger)
    async def atomic_token_bucket_check(
        self,
        key: str,
        capacity: int,
        window_seconds: int,
        cost: int,
        now: float,
        timeout_seconds: int,
    ) -> tuple[int, int, float, int]:
        """Atomically check and consume tokens from a token bucket.

        Executes the token bucket Lua script as a single atomic operation,
        preventing TOCTOU race conditions between read and write.

        The key suffix is automatically namespaced by the backend.

        Args:
            key: Rate limit key suffix (automatically namespaced)
            capacity: Burst capacity (max tokens)
            window_seconds: Refill window in seconds
            cost: Tokens to consume
            now: Current timestamp
            timeout_seconds: Expiry time for the bucket key in seconds.
                Passed through from the algorithm's configured value.

        Returns:
            Tuple of (allowed, remaining, reset_at, retry_after)
        """
        full_key = self._make_full_key(key)
        timeout = timeout_seconds

        try:
            client = await self._get_client()
            result = await client.eval(
                _ATOMIC_TOKEN_BUCKET_SCRIPT,
                1,  # Number of keys
                full_key,
                now,
                capacity,
                window_seconds,
                cost,
                timeout,
            )
            return (result[0], result[1], result[2], result[3])
        except Exception as e:
            self._raise_backend_error("Rate limit backend unavailable", e)

    @auto_trace(logger)
    async def atomic_fixed_window_check(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Check and update a fixed-window rate limit counter using native Redis pipeline.

        Uses SET NX EX + DECRBY pipeline (no Lua). Cluster-safe: single key per call.
        The counter is initialized at ``limit`` on first request (via SET NX with EX TTL),
        then atomically decremented by ``cost`` (via DECRBY). The request is allowed when
        the post-decrement value is >= 0. Denied requests leave the counter negative until
        the window expires; the window TTL self-heals any under-counting.

        Pipeline commands (executed via ``pipeline(transaction=False)``):
            1. ``SET {full_key} {limit} NX EX {window_seconds}`` — create counter if absent
            2. ``DECRBY {full_key} {cost}`` — decrement and return new value
            3. ``TTL {full_key}`` — remaining window lifetime for retry_after (read-only)

        Args:
            key: Rate limit key suffix (automatically namespaced via _make_full_key)
            limit: Maximum number of requests allowed in the window
            window_seconds: Duration of the window in seconds
            cost: Request cost (default 1)

        Returns:
            RateLimitResult with allowed status, remaining count, reset time, retry_after
        """
        full_key = self._make_full_key(key)

        try:
            client = await self._get_client()

            # Capture timestamp once before the pipeline to avoid drift
            # across branches.
            now = int(time.time())

            pipe = client.pipeline(transaction=False)
            pipe.set(full_key, limit, nx=True, ex=window_seconds)
            pipe.decrby(full_key, cost)
            pipe.ttl(full_key)
            results = await pipe.execute()

            decrby_result = int(results[1])
            ttl = int(results[2])  # Remaining TTL from pipeline (no extra round-trip)
            allowed = decrby_result >= 0
            remaining = max(0, decrby_result)

            # Compute reset_at from TTL captured in the pipeline.
            # For new windows (SET NX succeeded), TTL == window_seconds.
            # For existing windows, TTL reflects the remaining lifetime.
            # Fallback to window_seconds if TTL is non-positive (edge case:
            # key expired between DECRBY and TTL within the pipeline).
            reset_at = now + (ttl if ttl > 0 else window_seconds)

            retry_after = 0 if allowed else (ttl if ttl > 0 else window_seconds)
            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_at=reset_at,
                retry_after=retry_after,
            )

        except Exception as e:
            self._raise_backend_error("Rate limit backend unavailable", e)

    @auto_trace(logger)
    async def scoped_cleanup(self) -> int:
        """Clean up all keys in this backend's namespace only.

        SAFE: Only deletes keys that match this namespace's prefix.
        Cannot affect keys from other namespaces/services.

        Deletes one key per call for Redis Cluster safety — keys from
        scan_iter hash to arbitrary slots, so multi-key delete() would
        cause CROSSSLOT errors. Yields to the event loop every
        _CLEANUP_DELETE_BATCH_SIZE deletions to avoid monopolizing the
        shared connection pool.

        Returns:
            Number of keys deleted

        Example:
            # Only deletes keys matching this namespace's cleanup_pattern()
            # e.g., "org:neo:env:prod:svc:api:app:api:v1:d:ratelimit:*"
            deleted = await backend.scoped_cleanup()
        """
        pattern = self._namespace.cleanup_pattern()
        deleted_count = 0

        try:
            client = await self._get_client()

            batch_counter = 0
            async for key in client.scan_iter(match=pattern, count=100):
                deleted_count += await client.delete(key)
                batch_counter += 1
                if batch_counter >= _CLEANUP_DELETE_BATCH_SIZE:
                    await asyncio.sleep(0)
                    batch_counter = 0

            logger.info(
                "Scoped cleanup completed",
                namespace=self._namespace.domain_scope(),
                deleted_count=deleted_count,
            )

            return deleted_count

        except Exception as e:
            self._raise_backend_error(
                "Rate limit backend unavailable during cleanup", e
            )

    @auto_trace(logger)
    async def get_oldest_entry(self, key: str) -> float | None:
        """Get timestamp of oldest entry in window.

        Args:
            key: Rate limit key suffix (automatically namespaced)

        Returns:
            Timestamp of oldest entry, or None if window is empty

        Raises:
            ValueError: If key suffix contains forbidden characters
            RateLimitBackendError: If Redis is unavailable
        """
        full_key = self._make_full_key(key)

        try:
            client = await self._get_client()
            result = await client.zrange(full_key, 0, 0, withscores=True)
            if result:
                return result[0][1]
            return None

        except Exception as e:
            self._raise_backend_error("Rate limit backend unavailable", e)

    @auto_trace(logger)
    async def _execute_script(
        self,
        script: str,
        keys: list[str],
        args: list[int | float | str],
    ) -> list:
        """Execute a Lua script against Redis (private, single-key only).

        Internal helper for algorithm implementations (e.g. TokenBucketAlgorithm)
        to run atomic Lua scripts via the backend without coupling to redis-py
        internals. Key suffixes are automatically namespaced via
        ``_make_full_key`` to match the behaviour of other backend methods.

        **Single-key enforcement:** Exactly one key must be provided.
        Redis Cluster distributes keys across hash slots; a Lua script that
        touches multiple keys will fail with CROSSSLOT unless all keys hash
        to the same slot. Enforcing a single key eliminates this class of
        errors entirely.

        Callers MUST include an algorithm discriminator prefix in key suffixes
        (e.g. ``tb:`` for token bucket, ``sw:`` for sliding window) to prevent
        WRONGTYPE collisions between algorithms that use different Redis data
        structures on the same logical key.

        Args:
            script: Lua script source
            keys: Logical key suffixes (namespaced automatically).
                  Must contain exactly one key for Redis Cluster safety.
                  Must include algorithm discriminator prefix.
            args: Arguments passed to the script

        Returns:
            Script return value (typically a list)

        Raises:
            ValueError: If ``keys`` does not contain exactly one key
            RateLimitBackendError: If Redis is unavailable
        """
        if len(keys) != 1:
            raise ValueError(
                f"_execute_script requires exactly 1 key for Redis Cluster "
                f"safety, got {len(keys)}"
            )
        try:
            client = await self._get_client()
            full_keys = [self._make_full_key(k) for k in keys]
            return await client.eval(script, len(full_keys), *full_keys, *args)
        except Exception as e:
            self._raise_backend_error("Rate limit backend unavailable", e)

    @auto_trace(logger)
    async def health_check(self) -> bool:
        """Check Redis backend health.

        Returns:
            True if Redis is reachable and operational, False otherwise
        """
        try:
            client = await self._get_client()
            await client.ping()
            return True
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, OSError) as e:
            logger.log_error(e)
            return False


@auto_trace(logger)
def create_redis_ratelimit_backend(
    org: str,
    app: str,
    service: str,
    environment: str,
    max_connections: int = REDIS_POOL_SIZE_RATELIMIT,
    socket_timeout: float = REDIS_SOCKET_TIMEOUT,
    pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT,
) -> RedisRateLimitBackend:
    """Factory function for RedisRateLimitBackend with namespace isolation.

    Creates a backend with CacheNamespace(domain="ratelimit") to prevent
    cross-client interference when multiple services share Redis.

    Redis connections are obtained from the centralized cache gateway
    -- no URL is needed here.

    Args:
        org: Organization identifier (e.g., "neo")
        app: Application name (e.g., "gateway", "worker")
        service: Service name (e.g., "api-gateway", "order-service")
        environment: Environment (e.g., "prod", "staging", "test")
        max_connections: Connection pool size
        socket_timeout: Socket timeout in seconds
        pool_wait_timeout: How long to wait for a free pool connection (seconds)

    Returns:
        Configured RedisRateLimitBackend with namespace isolation

    Example:
        backend = create_redis_ratelimit_backend(
            org="neo",
            app="gateway",
            service="api-gateway",
            environment="prod",
        )

        # Atomic rate limit check (preferred).
        # Key suffixes are automatically namespaced by the backend.
        result = await backend.atomic_check_and_add(
            key="user:123",
            limit=100,
            window_seconds=60,
        )

        # Cleanup only this service's keys
        await backend.scoped_cleanup()
    """
    namespace = CacheNamespace(
        org=org,
        env=environment,
        service=service,
        app=app,
        domain="ratelimit",
    )
    return RedisRateLimitBackend.create(
        namespace=namespace,
        max_connections=max_connections,
        socket_timeout=socket_timeout,
        pool_wait_timeout=pool_wait_timeout,
    )
