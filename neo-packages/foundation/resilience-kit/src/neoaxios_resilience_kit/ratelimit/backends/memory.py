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

"""In-memory backend for rate limit state storage.

This backend is for TESTING ONLY. It provides a thread-safe in-memory
implementation of the RateLimitBackend protocol.

WARNING: This backend does NOT provide cross-worker coordination.
Use RedisRateLimitBackend for production deployments.
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple

from neoaxios_logging import auto_trace, get_telemetry

from ..protocols import RateLimitResult
from ..utils import _generate_window_members

logger = get_telemetry(__name__)


class InMemoryRateLimitBackend:
    """Thread-safe in-memory storage for rate limiting state.

    For TESTING ONLY - does not provide cross-worker coordination.
    Uses a dict of sorted lists to simulate Redis ZSET behavior.

    Data Structure:
        _storage: Dict[str, List[Tuple[str, float]]]  # key -> sorted list of (member, timestamp)

    Thread Safety:
        All operations are protected by an asyncio.Lock to ensure consistency
        when multiple coroutines access the backend concurrently.
    """

    @auto_trace(logger)
    def __init__(self) -> None:
        """Initialize in-memory storage."""
        self._storage: Dict[str, List[Tuple[str, float]]] = {}
        self._token_buckets: Dict[str, Dict[str, float]] = {}  # {key: {last_refill: ts, tokens: count}}
        self._fixed_windows: Dict[str, Dict[str, float]] = {}  # {key: {count: remaining, expires_at: ts}}
        self._lock = asyncio.Lock()

        logger.info("Initialized InMemoryRateLimitBackend (TESTING ONLY)")

    @auto_trace(logger)
    async def sliding_window_check(
        self,
        key: str,
        window_start: float,
        now: float,
        window_seconds: int,
    ) -> Tuple[int, bool]:
        """Check current count in sliding window.

        Args:
            key: Rate limit key
            window_start: Timestamp of window start
            now: Current timestamp
            window_seconds: Window duration for TTL

        Returns:
            Tuple of (current_count, success)
        """
        async with self._lock:
            if key not in self._storage:
                return 0, True

            # Remove expired entries
            self._storage[key] = [
                (member, ts) for member, ts in self._storage[key] if ts > window_start
            ]

            return len(self._storage[key]), True

    @auto_trace(logger)
    async def sliding_window_add(
        self,
        key: str,
        now: float,
        cost: int,
        window_seconds: int,
    ) -> None:
        """Add request(s) to sliding window.

        Optimized to minimize cryptographic operations and avoid unnecessary sorting.
        For cost > 1, generates a single random token and appends cost as suffix,
        reducing cryptographic overhead from O(cost) to O(1).

        Args:
            key: Rate limit key
            now: Current timestamp
            cost: Number of entries to add
            window_seconds: Window duration for TTL
        """
        async with self._lock:
            if key not in self._storage:
                self._storage[key] = []

            # Generate unique members using the shared utility
            entries = _generate_window_members(now, cost)
            self._storage[key].extend(entries)

            # No sort needed - all timestamps are identical for this batch


    @auto_trace(logger)
    async def atomic_check_and_add(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Atomically check rate limit and add entries if allowed.

        Single lock acquisition ensures no TOCTOU race between check and add.

        Args:
            key: Rate limit key
            limit: Maximum requests allowed in window
            window_seconds: Window duration in seconds
            cost: Number of requests to add (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        now = time.time()
        window_start = now - window_seconds

        async with self._lock:
            if key not in self._storage:
                self._storage[key] = []

            # Remove expired entries
            self._storage[key] = [
                (member, ts) for member, ts in self._storage[key] if ts > window_start
            ]

            current_count = len(self._storage[key])
            allowed = (current_count + cost) <= limit

            if allowed:
                entries = _generate_window_members(now, cost)
                self._storage[key].extend(entries)

            remaining = max(0, limit - current_count - cost) if allowed else 0
            reset_at = int(now + window_seconds)

            retry_after = 0
            if not allowed and self._storage[key]:
                oldest = min(ts for _, ts in self._storage[key])
                retry_after = max(1, int(oldest + window_seconds - now) + 1)
            elif not allowed:
                retry_after = window_seconds

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )

    @auto_trace(logger)
    async def atomic_fixed_window_check(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Atomically check rate limit using a fixed window counter.

        Mirrors Redis behaviour (count-down counter): initializes at ``limit``
        on first request, decrements by ``cost`` on each subsequent request
        within the window. When the window expires the counter re-initializes.

        The request is allowed when the post-decrement counter is >= 0.
        Denied requests do not persist the negative counter value (prevents
        underflow drift).

        Args:
            key: Rate limit key
            limit: Maximum requests allowed in the window
            window_seconds: Window duration in seconds
            cost: Number of units to consume (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        async with self._lock:
            now = time.time()
            entry = self._fixed_windows.get(key)

            if entry is None or now >= entry["expires_at"]:
                # First request or expired window — initialize
                remaining = limit - cost
                expires_at = now + window_seconds

                if remaining >= 0:
                    self._fixed_windows[key] = {
                        "count": remaining,
                        "expires_at": expires_at,
                    }
                    return RateLimitResult(
                        allowed=True,
                        remaining=remaining,
                        reset_at=int(expires_at),
                        retry_after=0,
                    )
                else:
                    # cost > limit — deny without storing
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_at=int(now + window_seconds),
                        retry_after=window_seconds,
                    )
            else:
                # Existing window — decrement
                new_count = entry["count"] - cost
                expires_at = entry["expires_at"]

                if new_count >= 0:
                    entry["count"] = new_count
                    return RateLimitResult(
                        allowed=True,
                        remaining=new_count,
                        reset_at=int(expires_at),
                        retry_after=0,
                    )
                else:
                    # Over limit — do not write negative value
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_at=int(expires_at),
                        retry_after=max(0, int(expires_at - now)),
                    )

    @auto_trace(logger)
    async def get_oldest_entry(self, key: str) -> Optional[float]:
        """Get timestamp of oldest entry in window.

        Args:
            key: Rate limit key

        Returns:
            Timestamp of oldest entry, or None if empty
        """
        async with self._lock:
            if key not in self._storage or not self._storage[key]:
                return None
            return min(ts for _, ts in self._storage[key])

    @auto_trace(logger)
    async def health_check(self) -> bool:
        """Check backend health (always healthy for in-memory).

        Returns:
            True if backend is healthy, False otherwise
        """
        return True

    @auto_trace(logger)
    async def close(self) -> None:
        """Close backend connections."""
        async with self._lock:
            self._storage.clear()
            self._fixed_windows.clear()
        logger.info("Closed InMemoryRateLimitBackend")

    @auto_trace(logger)
    async def clear(self) -> None:
        """Clear all stored data (for testing).

        This method is provided for test setup/teardown and is not part
        of the RateLimitBackend protocol.
        """
        async with self._lock:
            self._storage.clear()
            self._token_buckets.clear()
            self._fixed_windows.clear()

    @auto_trace(logger)
    async def get_key_count(self) -> int:
        """Get number of active keys (for testing).

        This method is provided for test assertions and is not part
        of the RateLimitBackend protocol.

        Returns:
            Number of active keys in storage
        """
        async with self._lock:
            return len(self._storage)

    @auto_trace(logger)
    async def get_bucket_state(
        self, key: str
    ) -> Optional[Tuple[float, float]]:
        """Get token bucket state (last_refill, tokens).

        Args:
            key: Rate limit key

        Returns:
            Tuple of (last_refill_time, tokens), or None if not initialized
        """
        async with self._lock:
            if key not in self._token_buckets:
                return None
            bucket = self._token_buckets[key]
            return (bucket.get("last_refill", 0.0), bucket.get("tokens", 0.0))

    @auto_trace(logger)
    async def set_bucket_state(
        self, key: str, last_refill: float, tokens: float
    ) -> None:
        """Set token bucket state.

        Args:
            key: Rate limit key
            last_refill: Last refill timestamp
            tokens: Current token count
        """
        async with self._lock:
            self._token_buckets[key] = {
                "last_refill": last_refill,
                "tokens": tokens,
            }

    @auto_trace(logger)
    async def atomic_token_bucket_check(
        self,
        key: str,
        capacity: int,
        window_seconds: int,
        cost: int,
        now: float,
        timeout_seconds: int,
    ) -> Tuple[int, int, float, int]:
        """Atomic token bucket check-and-consume under single lock.

        Prevents TOCTOU race between get_bucket_state and set_bucket_state.

        Args:
            key: Rate limit key
            capacity: Burst capacity
            window_seconds: Refill window
            cost: Tokens to consume
            now: Current timestamp
            timeout_seconds: Expiry time for the bucket key in seconds.
                Accepted for protocol parity but not enforced by the
                in-memory backend (buckets are cleared via clear()/close()).

        Returns:
            Tuple of (allowed, remaining, reset_at, retry_after)
        """
        import math

        refill_rate = capacity / window_seconds

        async with self._lock:
            bucket = self._token_buckets.get(key)
            if bucket is None:
                last_refill = now
                tokens = float(capacity)
            else:
                last_refill = bucket.get("last_refill", 0.0)
                tokens = bucket.get("tokens", 0.0)

            # Calculate tokens gained since last refill
            elapsed = max(0.0, now - last_refill)
            tokens_gained = elapsed * refill_rate
            tokens = min(capacity, tokens + tokens_gained)

            # Check if request can be allowed
            allowed = 0
            if tokens >= cost:
                allowed = 1
                tokens = tokens - cost

            # Update bucket state
            if allowed == 1 or tokens > 0:
                self._token_buckets[key] = {
                    "last_refill": now,
                    "tokens": tokens,
                }

            # Calculate reset_at
            reset_at = now
            if tokens < capacity:
                reset_at = now + ((capacity - tokens) / refill_rate)

            # Calculate retry_after
            retry_after = 0
            if allowed == 0:
                retry_after = int(math.ceil(cost / refill_rate))

        return (allowed, int(tokens), reset_at, retry_after)


@auto_trace(logger)
def create_memory_ratelimit_backend() -> InMemoryRateLimitBackend:
    """Factory function for InMemoryRateLimitBackend.

    Returns:
        InMemoryRateLimitBackend: A new in-memory backend instance
    """
    return InMemoryRateLimitBackend()
