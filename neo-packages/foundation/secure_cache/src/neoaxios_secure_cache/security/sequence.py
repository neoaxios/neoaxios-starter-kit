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

"""Sequence tracking for replay attack protection.

This module implements SequenceTracker - a component that maintains monotonically
increasing sequence numbers to prevent replay attacks.

CRITICAL: Sequence numbers are tracked PER-USER (not per-tenant) to prevent
cross-user replay attacks within the same tenant.

Features:
- Distributed counters via Redis INCR
- Local LRU cache of last-seen sequences
- Per-user sequence tracking: perm_seq:{tenant_id}:{user_id}
- Atomic increment operations
- Replay detection via sequence comparison

Usage:
    from neoaxios_secure_cache.security.sequence import SequenceTracker

    tracker = SequenceTracker(
        redis_client=redis_client,
        local_cache_size=10000,
    )

    # On write: get next sequence
    seq = await tracker.get_next_sequence(tenant_id="t1", user_id="u1")

    # On read: verify sequence
    is_valid = await tracker.verify_sequence(
        tenant_id="t1",
        user_id="u1",
        sequence=seq,
    )

Implementation Notes:
- Redis key format: perm_seq:{tenant_id}:{user_id}
- Uses Redis INCR for atomic increment
- Local cache prevents repeated Redis lookups
- After restart: local cache empty, first read accepts any sequence
  (known limitation - Redis counter persists across restarts)
- Sequence must be > last_seen to be valid
- Updates last_seen only on valid sequence
"""

from collections import OrderedDict
from typing import Any

from neoaxios_logging import auto_trace, get_telemetry, TraceDisabledReason

from neoaxios_secure_cache.backends.redis import scan_and_unlink
from neoaxios_secure_cache.defaults import SEQUENCE_TRACKER_LOCAL_CACHE_SIZE
from neoaxios_secure_cache.namespace import CacheNamespace, KeyTier

logger = get_telemetry(__name__)


class SequenceTracker:
    """Tracks monotonically increasing sequence numbers per user.

    Prevents replay attacks by ensuring each sequence number is only
    accepted once. Combines Redis-based distributed counters with
    local LRU cache for performance.

    SECURITY: Sequences are tracked per-user (not per-tenant) to prevent
    cross-user replay attacks within the same tenant.

    Attributes:
        redis_client: Redis async client for distributed counters
        local_cache_size: Maximum entries in LRU cache (default 10000)
        _last_seen: LRU cache mapping "{tenant_id}:{user_id}" -> last sequence

    Example:
        tracker = SequenceTracker(
            redis_client=redis_client,
            local_cache_size=10000,
        )

        # Get next sequence for user
        seq = await tracker.get_next_sequence(
            tenant_id="tenant_abc",
            user_id="user_123",
        )

        # Verify sequence from cached data
        is_valid = await tracker.verify_sequence(
            tenant_id="tenant_abc",
            user_id="user_123",
            sequence=seq,
        )
    """

    @auto_trace(logger)
    def __init__(
        self,
        redis_client: Any,
        namespace: CacheNamespace,
        local_cache_size: int = SEQUENCE_TRACKER_LOCAL_CACHE_SIZE,
    ) -> None:
        """Initialize SequenceTracker.

        Args:
            redis_client: Redis async client instance (redis.asyncio)
            namespace: CacheNamespace with domain="security" for key prefixing
            local_cache_size: Maximum entries in LRU cache (default 10000)

        Raises:
            ValueError: If redis_client is None, namespace is None,
                        or local_cache_size <= 0
        """
        if redis_client is None:
            raise ValueError("redis_client cannot be None")

        if namespace is None:
            raise ValueError("namespace cannot be None")

        if local_cache_size <= 0:
            raise ValueError(f"local_cache_size must be positive (got: {local_cache_size})")

        self.redis_client = redis_client
        self._namespace = namespace
        self.local_cache_size = local_cache_size

        # LRU cache: "{tenant_id}:{user_id}" -> last_seen_sequence
        # OrderedDict maintains insertion order for LRU eviction
        self._last_seen: OrderedDict[str, int] = OrderedDict()

        logger.info(
            f"Initialized SequenceTracker with local_cache_size={local_cache_size}"
        )

    @staticmethod
    def _validate_user_args(tenant_id: str, user_id: str) -> None:
        """Validate tenant_id and user_id are non-empty."""
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")
        if not user_id:
            raise ValueError("user_id cannot be empty")

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _make_cache_key(self, tenant_id: str, user_id: str) -> str:
        """Create cache key for local LRU storage.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Returns:
            Cache key in format "{tenant_id}:{user_id}"
        """
        return f"{tenant_id}:{user_id}"

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _make_redis_key(self, tenant_id: str, user_id: str) -> str:
        """Create Redis key for distributed counter.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Returns:
            Namespaced Redis key: {domain_scope}:perm_seq:{tenant_id}:{user_id}
        """
        return self._namespace.make_key_at(
            KeyTier.DOMAIN, f"perm_seq:{tenant_id}:{user_id}"
        )

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _update_lru_cache(self, cache_key: str, sequence: int) -> None:
        """Update LRU cache with new sequence value.

        Implements LRU eviction: if cache is full, removes oldest entry
        before adding new one. Moves existing keys to end on update.

        Args:
            cache_key: Cache key in format "{tenant_id}:{user_id}"
            sequence: Sequence number to store
        """
        # If key exists, remove it first (will be re-added at end)
        if cache_key in self._last_seen:
            del self._last_seen[cache_key]

        # If cache is full, evict oldest entry (first item)
        if len(self._last_seen) >= self.local_cache_size:
            # OrderedDict.popitem(last=False) removes first (oldest) item
            self._last_seen.popitem(last=False)

        # Add new entry at end (most recently used)
        self._last_seen[cache_key] = sequence

    @auto_trace(logger)
    async def get_next_sequence(self, tenant_id: str, user_id: str) -> int:
        """Get next sequence number for user.

        Uses Redis INCR for atomic increment of distributed counter.
        The sequence is PER-USER to prevent cross-user replay attacks.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Returns:
            Next sequence number (monotonically increasing)

        Raises:
            ValueError: If tenant_id or user_id is empty
            Exception: If Redis operation fails

        Example:
            seq = await tracker.get_next_sequence(
                tenant_id="tenant_abc",
                user_id="user_123",
            )
            # seq = 1, 2, 3, ... (increments on each call)
        """
        self._validate_user_args(tenant_id, user_id)

        redis_key = self._make_redis_key(tenant_id, user_id)

        try:
            # Redis INCR is atomic and returns new value
            # First call returns 1, second returns 2, etc.
            next_seq = await self.redis_client.incr(redis_key)

            logger.debug(
                f"Generated sequence {next_seq} for {tenant_id}:{user_id}"
            )

            return next_seq

        except Exception as e:
            logger.log_error(
                Exception(
                    f"Failed to increment sequence for {tenant_id}:{user_id}: {e}"
                )
            )
            raise

    @auto_trace(logger)
    async def verify_sequence(
        self,
        tenant_id: str,
        user_id: str,
        sequence: int,
    ) -> bool:
        """Verify sequence number is valid (not a replay).

        Checks if sequence > last_seen for this user. If valid, updates
        last_seen in local cache. LRU cache prevents repeated Redis lookups.

        SECURITY: Each sequence can only be used once. After verification,
        the sequence becomes the new last_seen value, preventing replay.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier
            sequence: Sequence number to verify

        Returns:
            True if sequence is valid (> last_seen), False if replay detected

        Raises:
            ValueError: If tenant_id, user_id is empty or sequence <= 0

        Example:
            # First verification with seq=5
            is_valid = await tracker.verify_sequence("t1", "u1", 5)
            # Returns True (no previous sequence)

            # Second verification with seq=5 (replay)
            is_valid = await tracker.verify_sequence("t1", "u1", 5)
            # Returns False (5 is not > 5)

            # Third verification with seq=6
            is_valid = await tracker.verify_sequence("t1", "u1", 6)
            # Returns True (6 > 5)
        """
        self._validate_user_args(tenant_id, user_id)
        if sequence <= 0:
            raise ValueError(f"sequence must be positive (got: {sequence})")

        cache_key = self._make_cache_key(tenant_id, user_id)

        # Check local LRU cache first
        last_seen = self._last_seen.get(cache_key)

        if last_seen is None:
            # No cached value - accept sequence and cache it
            # Note: After restart, local cache is empty but Redis persists
            # This means first verification after restart will accept any
            # sequence. This is a known limitation.
            self._update_lru_cache(cache_key, sequence)
            logger.debug(
                f"Sequence {sequence} accepted for {tenant_id}:{user_id} "
                "(no cached value)"
            )
            return True

        # Sequence must be greater than last_seen (not equal)
        is_valid = sequence > last_seen

        if is_valid:
            # Update cache with new sequence
            self._update_lru_cache(cache_key, sequence)
            logger.debug(
                f"Sequence {sequence} accepted for {tenant_id}:{user_id} "
                f"(last_seen={last_seen})"
            )
        else:
            logger.log_error(
                Exception(
                    f"Replay attack detected for {tenant_id}:{user_id}: "
                    f"sequence={sequence}, last_seen={last_seen}"
                )
            )

        return is_valid

    @auto_trace(logger)
    async def clear_user(self, tenant_id: str, user_id: str) -> None:
        """Clear sequence state for specific user.

        Removes both local cache entry and Redis counter. Use when
        user is deleted or sequence needs to be reset.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Raises:
            ValueError: If tenant_id or user_id is empty
            Exception: If Redis operation fails

        Example:
            await tracker.clear_user(
                tenant_id="tenant_abc",
                user_id="user_123",
            )
        """
        self._validate_user_args(tenant_id, user_id)

        cache_key = self._make_cache_key(tenant_id, user_id)
        redis_key = self._make_redis_key(tenant_id, user_id)

        # Remove from local cache
        if cache_key in self._last_seen:
            del self._last_seen[cache_key]

        # Remove from Redis
        try:
            deleted = await self.redis_client.unlink(redis_key)
            logger.debug(
                f"Cleared sequence for {tenant_id}:{user_id} "
                f"(redis_deleted={deleted})"
            )
        except Exception as e:
            logger.log_error(
                Exception(
                    f"Failed to clear Redis sequence for {tenant_id}:{user_id}: {e}"
                )
            )
            raise

    @auto_trace(logger)
    async def clear_tenant(self, tenant_id: str) -> None:
        """Clear all sequence state for tenant.

        Removes all user sequences for the tenant from both local cache
        and Redis. Use when tenant is deleted or full reset needed.

        Args:
            tenant_id: Tenant identifier

        Raises:
            ValueError: If tenant_id is empty
            Exception: If Redis operation fails

        Example:
            await tracker.clear_tenant(tenant_id="tenant_abc")

        Note:
            This operation scans Redis keys with pattern perm_seq:{tenant_id}:*
            which can be slow for tenants with many users. Use sparingly.
        """
        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")

        # Remove all matching entries from local cache
        cache_prefix = f"{tenant_id}:"
        keys_to_remove = [
            key for key in self._last_seen.keys()
            if key.startswith(cache_prefix)
        ]
        for key in keys_to_remove:
            del self._last_seen[key]

        # Remove all matching keys from Redis using SCAN pattern
        redis_pattern = f"{self._namespace.domain_scope()}:perm_seq:{tenant_id}:*"

        try:
            deleted_count = await scan_and_unlink(self.redis_client, redis_pattern)

            logger.debug(
                f"Cleared {deleted_count} sequences for tenant {tenant_id} "
                f"(local_cache_cleared={len(keys_to_remove)})"
            )

        except Exception as e:
            logger.log_error(
                Exception(
                    f"Failed to clear Redis sequences for tenant {tenant_id}: {e}"
                )
            )
            raise


@auto_trace(logger)
def create_sequence_tracker(
    redis_client: Any,
    namespace: CacheNamespace,
    local_cache_size: int = SEQUENCE_TRACKER_LOCAL_CACHE_SIZE,
) -> SequenceTracker:
    """Factory function for SequenceTracker.

    Creates a SequenceTracker instance with validated parameters.
    Provided for consistency with other security components.

    Args:
        redis_client: Redis async client instance (redis.asyncio)
        namespace: CacheNamespace with domain="security" for key prefixing
        local_cache_size: Maximum entries in LRU cache (default 10000)

    Returns:
        Configured SequenceTracker instance

    Raises:
        ValueError: If redis_client is None, namespace is None,
                    or local_cache_size <= 0

    Example:
        tracker = create_sequence_tracker(
            redis_client=redis_client,
            namespace=security_ns,
            local_cache_size=10000,
        )
    """
    return SequenceTracker(
        redis_client=redis_client,
        namespace=namespace,
        local_cache_size=local_cache_size,
    )
