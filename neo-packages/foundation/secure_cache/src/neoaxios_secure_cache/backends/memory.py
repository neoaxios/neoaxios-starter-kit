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

"""In-memory cache backend implementation.

This module implements InMemoryCacheBackend - a thread-safe in-memory cache
with TTL-based expiration. Suitable for development, testing, and single-process
deployments.

Usage:
    from neoaxios_secure_cache.backends.memory import InMemoryCacheBackend

    cache = InMemoryCacheBackend(default_ttl_seconds=300)
    await cache.set("key", {"data": "value"}, ttl_seconds=300)
    value = await cache.get("key")

Implementation Notes:
    - Uses asyncio.Lock for thread safety
    - Automatically cleans up expired entries on access
    - Stores entries with Unix timestamp expiration
    - Does not persist data across restarts

Deprecation:
    InMemoryCacheBackend is deprecated for production use. Use RedisCacheBackend
    for distributed deployments. In development/test environments, this backend
    is acceptable but will still generate a deprecation warning.
"""

import asyncio
import time
import warnings
from dataclasses import dataclass
from typing import Any, Dict, Optional

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import CACHE_TTL_SHORT

logger = get_telemetry(__name__)


# Environments where InMemoryCacheBackend is acceptable (with deprecation warning)
_ALLOWED_ENVIRONMENTS = frozenset({
    "development",
    "dev",
    "test",
    "testing",
    "local",
    "ci",
})


@dataclass
class CacheEntry:
    """Cache entry with value and expiration timestamp.

    Attributes:
        value: Cached value (any Python object)
        expiry: Unix timestamp when entry expires
    """

    value: Any
    expiry: float  # Unix timestamp


class InMemoryCacheBackend:
    """Thread-safe in-memory cache implementation.

    Uses asyncio.Lock for thread safety and stores entries with
    TTL-based expiration. Automatically cleans up expired entries
    on access.

    This implementation is suitable for development, testing, and
    single-process deployments. For distributed environments, use
    RedisCacheBackend.

    Deprecated:
        InMemoryCacheBackend is deprecated; use RedisCacheBackend instead.

    Attributes:
        default_ttl_seconds: Default time-to-live in seconds
        _store: Internal cache storage dictionary
        _lock: Asyncio lock for thread safety

    Example:
        cache = InMemoryCacheBackend(default_ttl_seconds=300)
        await cache.set("user:123", {"name": "Alice"}, ttl_seconds=60)
        user_data = await cache.get("user:123")
        exists = await cache.exists("user:123")
        await cache.delete("user:123")
    """

    @auto_trace(logger)
    def __init__(self, default_ttl_seconds: int = CACHE_TTL_SHORT, environment: str = ""):
        """Initialize in-memory cache.

        Args:
            default_ttl_seconds: Default time-to-live in seconds (default: 300)
            environment: Deployment environment name (e.g. "dev", "production").
                Passed explicitly. Empty string disables
                production detection.

        Warnings:
            - DeprecationWarning in all environments
            - WARNING log in production environments (use Redis instead)
        """
        # Production detection from explicit parameter
        neo_env = environment.lower()
        is_production = neo_env not in _ALLOWED_ENVIRONMENTS and neo_env != ""

        # Always emit deprecation warning
        warnings.warn(
            "InMemoryCacheBackend is deprecated; use RedisCacheBackend instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        # Log warning in production environments
        if is_production:
            logger.warning(
                f"InMemoryCacheBackend used in production environment (NEO_ENV={neo_env}). "
                "This is not recommended for distributed deployments. "
                "Use RedisCacheBackend with 'from secure_cache.backends.redis import "
                "create_redis_backend' for production cache storage."
            )

        self.default_ttl_seconds = default_ttl_seconds
        self._store: Dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    @auto_trace(logger)
    async def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache.

        Returns None if key is missing or expired. Automatically
        removes expired entries during access.

        Args:
            key: Cache key

        Returns:
            Cached value or None if missing/expired

        Note:
            Expired entries are automatically cleaned up when accessed.
        """
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None

            # Check expiration
            if time.time() > entry.expiry:
                # Remove expired entry
                del self._store[key]
                return None

            return entry.value

    @auto_trace(logger)
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (any Python object)
            ttl_seconds: Time-to-live in seconds

        Note:
            Parameter is ttl_seconds (not ttl) per CacheBackend protocol.
        """
        expiry = time.time() + ttl_seconds
        entry = CacheEntry(value=value, expiry=expiry)

        async with self._lock:
            self._store[key] = entry

    @auto_trace(logger)
    async def delete(self, key: str) -> None:
        """Remove key from cache.

        No error is raised if the key does not exist.

        Args:
            key: Cache key to remove
        """
        async with self._lock:
            self._store.pop(key, None)

    @auto_trace(logger)
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        This method checks for key presence without validating expiration.
        A key may exist but be expired - use get() to retrieve valid values.

        Args:
            key: Cache key to check

        Returns:
            True if key exists (may be expired), False otherwise

        Warning:
            This method does not check expiration. A key may exist but
            return None from get() if expired.
        """
        async with self._lock:
            return key in self._store

    @auto_trace(logger)
    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries matching a key prefix.

        Args:
            prefix: Key prefix to match

        Returns:
            Number of entries removed
        """
        async with self._lock:
            keys_to_delete = [
                key for key in self._store.keys()
                if key.startswith(prefix)
            ]

            for key in keys_to_delete:
                del self._store[key]

            logger.debug(f"Invalidated {len(keys_to_delete)} keys matching prefix '{prefix}'")
            return len(keys_to_delete)

    @auto_trace(logger)
    async def keys_by_prefix(self, prefix: str) -> list[str]:
        """Return all keys matching a key prefix.

        Args:
            prefix: Key prefix to match

        Returns:
            List of matching keys
        """
        async with self._lock:
            return [key for key in self._store.keys() if key.startswith(prefix)]

    @auto_trace(logger)
    async def _cleanup_expired(self) -> int:
        """Remove all expired entries from cache.

        Internal method for cache maintenance. Not part of CacheBackend protocol.

        Returns:
            Number of entries removed

        Note:
            This is a utility method for explicit cache cleanup. Expired
            entries are also cleaned automatically during get() operations.
        """
        current_time = time.time()

        async with self._lock:
            expired_keys = [
                key
                for key, entry in self._store.items()
                if current_time > entry.expiry
            ]

            for key in expired_keys:
                del self._store[key]

            return len(expired_keys)
