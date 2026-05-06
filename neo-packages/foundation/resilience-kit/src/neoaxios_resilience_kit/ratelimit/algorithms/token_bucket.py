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

"""Token bucket rate limiting algorithm with configurable burst capacity.

This module implements the token bucket algorithm, which allows controlled
bursting of requests while maintaining long-term rate limits.

Features:
- Configurable burst capacity (tokens available at start)
- Configurable refill rate (tokens per second)
- Cost-based consumption (each request consumes N tokens)
- Atomic backend operations (no race conditions)
- Timeout-based token expiry (reduces memory footprint)

Use token bucket for:
- APIs with bursty but bounded traffic patterns
- Cost-based limiting on expensive operations
- Gradual rate increases (warm-up periods)
- Stacked limits (burst limit + sustained limit)

Performance:
    Time complexity: O(1) per check. The Lua script reads and writes a fixed number
        of HASH fields (tokens, last_refill) regardless of request volume.
    Memory complexity: O(1) per key. Uses a single Redis HASH with two fields per
        identity — no per-request storage growth.
    Implementation: Lua-scripted. The refill-check-consume sequence executes as a
        single atomic Lua script on the Redis server, which blocks the Redis event
        loop for the duration of script execution (typically 1-2 microseconds).
    Recommendation: Use FixedWindowAlgorithm when burst control is not needed.
        FixedWindowAlgorithm provides the same O(1) complexity using native Redis
        commands with no Lua scripts, making it fully cluster-safe and non-blocking.
        TokenBucketAlgorithm should be reserved for cases requiring controlled burst
        capacity, cost-based consumption, or smooth refill semantics.
"""

import time
from typing import Optional

from neoaxios_logging import auto_trace, get_telemetry

from ..protocols import RateLimitBackend, RateLimitResult

logger = get_telemetry(__name__)


class TokenBucketAlgorithm:
    """Token bucket rate limiting algorithm.

    Allows requests as long as tokens are available in a bucket. Tokens are
    refilled at a constant rate over time, enabling controlled bursting.

    Algorithm:
    1. Bucket stores available tokens (capped at capacity)
    2. Each request consumes N tokens (cost)
    3. Tokens refill at rate: `tokens_per_second = capacity / window`
    4. If tokens < cost, request is denied
    5. All operations are atomic via backend.atomic_token_bucket_check()

    Example:
        algo = TokenBucketAlgorithm(capacity=10, window_seconds=60)
        # Burst capacity: 10 tokens
        # Refill rate: 10 tokens/60s = 0.167 tokens/s
        # Sustained rate: ~0.167 requests/s
        # Burst window: Can handle 10 requests immediately, then limited to refill rate

    Args:
        capacity: Maximum tokens in bucket (controls burst)
        window_seconds: Window over which capacity is refilled (refill rate)
        timeout_seconds: Expiry time for unused buckets (default: 2*window)

    Attributes:
        capacity: Burst capacity in tokens
        window_seconds: Refill window in seconds
        timeout_seconds: Bucket expiry time in seconds
    """

    @auto_trace(logger)
    def __init__(
        self,
        capacity: int = 100,
        window_seconds: int = 60,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        """Initialize token bucket algorithm.

        ``capacity`` and ``window_seconds`` here are defaults / sentinels
        only — :meth:`check` accepts ``limit`` and ``window_seconds``
        per-call so a single algorithm instance can host many distinct
        (capacity, window) tuples.

        ``timeout_seconds`` is the bucket-key TTL applied to the
        backend.  When the caller supplies an explicit value at
        construction it is treated as an OVERRIDE and used verbatim
        for every per-call invocation — useful for callers that need a
        TTL larger or smaller than ``2 * window`` (e.g. tests pinning
        a 1 s TTL).  When omitted, the TTL is derived **per call**
        from the runtime ``window_seconds`` argument so callers using
        sentinel construction values (``capacity=1, window_seconds=1``)
        do not silently freeze the TTL to ``2 s`` — which would break
        any per-call ``window_seconds=60`` budget by expiring the
        bucket key 58 s before the refill window completes.  See
        :meth:`_effective_timeout_seconds` for the resolution rule.

        Args:
            capacity: Maximum tokens in bucket (burst capacity).
                Sentinel default — :meth:`check` accepts the runtime
                value as ``limit``.
            window_seconds: Time window for refilling capacity (refill
                rate = capacity/window).  Sentinel default — the
                per-call ``window_seconds`` argument is authoritative
                for the rate-limiting math.
            timeout_seconds: Optional explicit override for the bucket
                key TTL.  When ``None`` (default), each per-call
                invocation derives its own TTL from the call's
                ``window_seconds`` argument (``2 * window``).  When
                set, the override is used for every per-call
                invocation regardless of the runtime window.

        Raises:
            ValueError: If capacity <= 0 or window_seconds <= 0
        """
        if capacity <= 0:
            raise ValueError(f"capacity must be > 0, got {capacity}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be > 0, got {window_seconds}")

        self.capacity = capacity
        self.window_seconds = window_seconds
        # ``_timeout_seconds_override`` is the source of truth for the
        # opt-in explicit TTL.  ``self.timeout_seconds`` retains the
        # construction-time snapshot (override or 2 * window) so
        # introspection / logging stays meaningful, but callers MUST
        # NOT rely on it for the actual per-call TTL — see
        # :meth:`_effective_timeout_seconds`.
        self._timeout_seconds_override: Optional[int] = timeout_seconds
        self.timeout_seconds = timeout_seconds or (2 * window_seconds)

        logger.info(
            "Initialized TokenBucketAlgorithm",
            capacity=capacity,
            window_seconds=window_seconds,
            timeout_seconds=self.timeout_seconds,
            refill_rate=capacity / window_seconds,
        )

    def _effective_timeout_seconds(self, runtime_window_seconds: int) -> int:
        """Return the bucket key TTL for a per-call invocation.

        Resolution order:

        1. Explicit override at construction
           (``__init__(timeout_seconds=N)``) wins — used verbatim for
           every call regardless of the runtime window.
        2. Otherwise, derive ``2 * runtime_window_seconds`` so the
           bucket key persists at least one full refill cycle.

        Re-gate fix: prior to this method existing, the algorithm
        passed the construction-time-snapshotted ``self.timeout_seconds``
        on every per-call backend hit, which froze the TTL to
        ``2 * __init__.window_seconds`` even when the per-call
        ``window_seconds`` was much larger.  Callers using sentinel
        ``__init__(window_seconds=1)`` semantics (a single algorithm
        servicing many runtime windows) silently expired their bucket
        keys after 2 s, defeating any longer per-call window.
        """
        if self._timeout_seconds_override is not None:
            return self._timeout_seconds_override
        return 2 * runtime_window_seconds

    @auto_trace(logger)
    async def check(
        self,
        backend: RateLimitBackend,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Check if request is allowed under token bucket limit.

        Delegates to backend.atomic_token_bucket_check() for atomic
        check-and-consume, preventing TOCTOU race conditions.

        This method is designed to work with token bucket parameters where:
        - `limit` is interpreted as burst capacity (replaces self.capacity)
        - `window_seconds` is interpreted as refill window (replaces self.window_seconds)

        Args:
            backend: Rate limit storage backend
            key: Rate limit key
            limit: Burst capacity (tokens in bucket)
            window_seconds: Refill window in seconds
            cost: Tokens to consume (default: 1)

        Returns:
            RateLimitResult with allowed status and timing info

        Raises:
            ValueError: If cost <= 0
            RateLimitBackendError: If backend operation fails
        """
        if cost <= 0:
            raise ValueError(f"cost must be > 0, got {cost}")

        now = time.time()

        # Prefix with algorithm discriminator to prevent WRONGTYPE collision
        # between algorithms using different Redis data structures.
        discriminated_key = f"tb:{key}"

        try:
            allowed, remaining, reset_at, retry_after = (
                await backend.atomic_token_bucket_check(
                    key=discriminated_key,
                    capacity=limit,
                    window_seconds=window_seconds,
                    cost=cost,
                    now=now,
                    timeout_seconds=self._effective_timeout_seconds(
                        window_seconds
                    ),
                )
            )

            logger.debug(
                "Token bucket check completed",
                key=key,
                allowed=bool(allowed),
                remaining=remaining,
                cost=cost,
            )

            return RateLimitResult(
                allowed=bool(allowed),
                remaining=remaining,
                reset_at=int(reset_at),
                retry_after=int(retry_after),
            )

        except Exception as e:
            logger.log_error(
                e,
                context="Token bucket check failed",
                key=key,
                cost=cost,
            )
            raise


@auto_trace(logger)
def create_token_bucket_algorithm(
    capacity: int = 100,
    window_seconds: int = 60,
    timeout_seconds: Optional[int] = None,
) -> TokenBucketAlgorithm:
    """Factory function for TokenBucketAlgorithm.

    Args:
        capacity: Maximum tokens in bucket (burst capacity)
        window_seconds: Refill window in seconds
        timeout_seconds: Bucket expiry time (default: 2*window_seconds)

    Returns:
        Configured TokenBucketAlgorithm instance

    Raises:
        ValueError: If parameters are invalid
    """
    return TokenBucketAlgorithm(
        capacity=capacity,
        window_seconds=window_seconds,
        timeout_seconds=timeout_seconds,
    )
