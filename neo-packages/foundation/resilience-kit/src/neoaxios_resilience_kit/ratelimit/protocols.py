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

"""Protocol definitions for rate limiting components.

This module defines the protocols (interfaces) for rate limiting backends
and algorithms, enabling dependency injection and testability while
keeping algorithms and backends decoupled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Tuple, runtime_checkable

from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)


@dataclass
class RateLimitResult:
    """Result of a rate limit check.

    Attributes:
        allowed: Whether the request is allowed
        remaining: Number of requests remaining in the window
        reset_at: Unix timestamp when the window resets
        retry_after: Seconds until request would be allowed (if denied)
    """

    allowed: bool
    remaining: int
    reset_at: int
    retry_after: int = 0


@runtime_checkable
class RateLimitBackend(Protocol):
    """Protocol for rate limit storage backends.

    Implementations must provide atomic operations for sliding window,
    token bucket, and fixed window algorithms.

    Example implementations:
    - RedisRateLimitBackend: Production backend extending secure_cache
    - InMemoryRateLimitBackend: Testing backend with full implementation
    """

    async def health_check(self) -> bool:
        """Check backend health.

        Returns:
            True if backend is healthy, False otherwise
        """
        ...

    async def atomic_check_and_add(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> "RateLimitResult":
        """Atomically check rate limit and add entries if allowed.

        Prevents TOCTOU race conditions by performing the check and add
        in a single atomic operation.

        Args:
            key: Rate limit key
            limit: Maximum requests allowed in window
            window_seconds: Window duration in seconds
            cost: Number of requests to add (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        ...

    async def atomic_token_bucket_check(
        self,
        key: str,
        capacity: int,
        window_seconds: int,
        cost: int,
        now: float,
        timeout_seconds: int,
    ) -> Tuple[int, int, float, int]:
        """Atomically check and consume tokens from a token bucket.

        Prevents TOCTOU race conditions by performing the check and
        consumption in a single atomic operation.

        Args:
            key: Rate limit key
            capacity: Burst capacity (max tokens)
            window_seconds: Refill window in seconds
            cost: Tokens to consume
            now: Current timestamp
            timeout_seconds: Expiry time for the bucket key in seconds.
                The caller (TokenBucketAlgorithm) computes this from its
                configured timeout_seconds attribute.

        Returns:
            Tuple of (allowed, remaining, reset_at, retry_after)
        """
        ...

    async def atomic_fixed_window_check(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> "RateLimitResult":
        """Atomically check rate limit using a fixed window counter.

        Uses a native Redis pipeline (SET NX EX + DECRBY) on a single key,
        avoiding Lua scripts entirely. This makes the operation fully
        cluster-safe with no cross-slot concerns.

        The counter is initialized at ``limit`` on first request (via SET NX)
        with a TTL of ``window_seconds``, then atomically decremented by
        ``cost`` (via DECRBY). The request is allowed when the post-decrement
        value is >= 0.

        Args:
            key: Rate limit key
            limit: Maximum requests allowed in the window
            window_seconds: Window duration in seconds
            cost: Number of units to consume (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        ...

    async def close(self) -> None:
        """Close backend connections."""
        ...


@runtime_checkable
class RateLimitAlgorithm(Protocol):
    """Protocol for rate limiting algorithms.

    Algorithms implement the rate limiting logic using a backend
    for state storage.

    Example implementations:
    - SlidingWindowAlgorithm: Accurate, no burst exploitation
    - TokenBucketAlgorithm: Allows controlled bursting
    """

    async def check(
        self,
        backend: RateLimitBackend,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Check if request is allowed under rate limit.

        Args:
            backend: Rate limit storage backend
            key: Rate limit key
            limit: Maximum requests allowed in window
            window_seconds: Window size in seconds
            cost: Cost of this request (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        ...
