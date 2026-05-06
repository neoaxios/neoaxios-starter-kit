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

"""Sliding window log algorithm for accurate rate limiting.

This algorithm maintains a sorted set of request timestamps. Each request:
1. Removes expired entries (outside the window)
2. Counts remaining entries
3. If under limit, adds new entry
4. Returns allow/deny decision

Advantages:
- Accurate: No burst exploitation at window boundaries
- Memory efficient: Old entries automatically cleaned

Redis Data Structure:
    Key: ratelimit:{scope}:{id}
    Type: ZSET
    Score: Unix timestamp (float)
    Member: Unique request ID (timestamp + random)

Performance:
    Time complexity: O(log N + M) per check, where N = total members in the sorted
        set and M = expired members removed by ZREMRANGEBYSCORE. ZCARD is O(1).
    Memory complexity: O(N) per key, where N = number of requests within the current
        window. Each member is a unique timestamp+random string stored in the ZSET.
    Implementation: Lua-scripted. The ZREMRANGEBYSCORE + ZCARD + ZADD sequence executes
        as a single atomic Lua script on the Redis server, which blocks the Redis event
        loop for the duration of script execution (typically 5-50 microseconds depending
        on N).
    Recommendation: Use FixedWindowAlgorithm for most use cases where boundary burst
        (up to 2x at window edges) is acceptable. FixedWindowAlgorithm provides O(1)
        time and memory using native Redis commands with no Lua scripts, making it
        fully cluster-safe and non-blocking. SlidingWindowAlgorithm should be reserved
        for cases requiring exact rolling-window semantics without boundary burst.
"""

from neoaxios_logging import auto_trace, get_telemetry

from ..protocols import RateLimitBackend, RateLimitResult

logger = get_telemetry(__name__)


class SlidingWindowAlgorithm:
    """Sliding window log algorithm using Redis sorted sets.

    Implements RateLimitAlgorithm protocol.

    Example:
        algorithm = SlidingWindowAlgorithm()
        result = await algorithm.check(
            backend=redis_backend,
            key="ratelimit:user:123",
            limit=100,
            window_seconds=60,
            cost=1,
        )
        if result.allowed:
            # Process request
        else:
            # Return 429
    """

    @auto_trace(logger)
    async def check(
        self,
        backend: RateLimitBackend,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Check if request is allowed under rate limit.

        Uses atomic check-and-add to prevent TOCTOU race conditions.
        The backend's atomic_check_and_add method ensures that the count
        check and entry addition happen in a single atomic operation.

        Args:
            backend: Rate limit storage backend
            key: Rate limit key (e.g., "ratelimit:user:123")
            limit: Maximum requests allowed in window
            window_seconds: Window size in seconds
            cost: Cost of this request (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata
        """
        # Use atomic check-and-add to prevent race conditions.
        # Backend raises RateLimitBackendError on failure (fail-closed).
        # Prefix with algorithm discriminator to prevent WRONGTYPE collision
        # between algorithms using different Redis data structures.
        result = await backend.atomic_check_and_add(
            key=f"sw:{key}",
            limit=limit,
            window_seconds=window_seconds,
            cost=cost,
        )

        if result.allowed:
            logger.debug(
                "Request allowed",
                key=key,
                limit=limit,
                remaining=result.remaining,
            )
        else:
            logger.debug(
                "Request denied",
                key=key,
                limit=limit,
                retry_after=result.retry_after,
            )

        return result


@auto_trace(logger)
def create_sliding_window_algorithm() -> SlidingWindowAlgorithm:
    """Factory function for SlidingWindowAlgorithm."""
    return SlidingWindowAlgorithm()
