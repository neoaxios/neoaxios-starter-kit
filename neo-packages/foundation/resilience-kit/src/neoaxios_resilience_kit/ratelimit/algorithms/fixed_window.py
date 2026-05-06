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

"""Fixed window counter algorithm for high-throughput rate limiting.

This algorithm uses a simple counter with a TTL-based expiration window.
Each request atomically decrements the counter; when the counter reaches
zero the request is denied until the window expires and the counter resets.

Complexity:
    Time:   O(1) per check -- two native Redis commands (SET NX EX + DECRBY)
    Memory: O(1) per key -- single STRING value with TTL

Redis Data Structure:
    Key:   ratelimit:{scope}:fw:{id}
    Type:  STRING (integer counter)
    Value: Initialized to ``limit``, decremented by ``cost`` per request
    TTL:   ``window_seconds``

Boundary-Burst Limitation:
    Fixed window algorithms reset the counter at the window boundary. A client
    that exhausts its budget at the end of window N and immediately issues
    requests at the start of window N+1 can achieve up to 2x the nominal rate
    across two adjacent windows. When this boundary burst is unacceptable,
    use ``SlidingWindowAlgorithm`` instead -- it maintains per-request
    timestamps and does not suffer from boundary effects.

The ``fw:`` algorithm discriminator prefix is applied to all keys to prevent
WRONGTYPE collisions with other algorithms that use different Redis data
structures.
"""

from neoaxios_logging import auto_trace, get_telemetry

from ..protocols import RateLimitBackend, RateLimitResult

logger = get_telemetry(__name__)


class FixedWindowAlgorithm:
    """Fixed window counter algorithm using native Redis commands.

    Implements RateLimitAlgorithm protocol.

    The algorithm is stateless -- all parameters are passed per-call via
    ``check()``. No constructor arguments are required.

    Example:
        algorithm = FixedWindowAlgorithm()
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
    def __init__(self) -> None:
        """Initialize fixed window algorithm (stateless -- no parameters)."""

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

        Uses atomic fixed window check to prevent TOCTOU race conditions.
        The backend's atomic_fixed_window_check method uses native Redis
        commands (SET NX EX + DECRBY) -- no Lua scripts involved.

        Args:
            backend: Rate limit storage backend
            key: Rate limit key (e.g., "ratelimit:user:123")
            limit: Maximum requests allowed in window
            window_seconds: Window size in seconds
            cost: Cost of this request (default: 1)

        Returns:
            RateLimitResult with allowed status and metadata

        Raises:
            ValueError: If cost <= 0
            RateLimitBackendError: If backend operation fails
        """
        if cost <= 0:
            raise ValueError(f"cost must be > 0, got {cost}")

        # Prefix with algorithm discriminator to prevent WRONGTYPE collision
        # between algorithms using different Redis data structures.
        return await backend.atomic_fixed_window_check(
            key=f"fw:{key}",
            limit=limit,
            window_seconds=window_seconds,
            cost=cost,
        )


@auto_trace(logger)
def create_fixed_window_algorithm() -> FixedWindowAlgorithm:
    """Factory function for FixedWindowAlgorithm."""
    return FixedWindowAlgorithm()
