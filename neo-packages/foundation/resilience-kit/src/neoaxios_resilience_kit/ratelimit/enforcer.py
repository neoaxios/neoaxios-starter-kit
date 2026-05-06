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

"""Rate limit enforcement logic -- framework-agnostic.

This module provides the core rate limit check-record-respond pattern
as a standalone enforcer class with no HTTP or framework dependencies.

The enforcer handles:
- Checking if a request is allowed
- Recording the request in the backend
- Returning RateLimitResult on success
- Raising RateLimitBackendError on backend failure (fail-closed)

Rate limiting is always fail-closed: when the backend is unavailable,
:class:`RateLimitBackendError` is raised rather than admitting traffic.
"""

from typing import Optional

from neoaxios_logging import auto_trace, get_telemetry

from .algorithms.fixed_window import FixedWindowAlgorithm
from .config import RateLimitConfig
from .exceptions import RateLimitBackendError
from .protocols import RateLimitAlgorithm, RateLimitBackend, RateLimitResult

logger = get_telemetry(__name__)

# Module-level singleton — FixedWindowAlgorithm is stateless (O(1), no Lua),
# so a single shared instance is safe and avoids per-enforcer allocation.
_DEFAULT_ALGORITHM: RateLimitAlgorithm = FixedWindowAlgorithm()


class RateLimitEnforcer:
    """Enforces rate limits using algorithm and backend.

    This class encapsulates the core rate limiting logic:
    1. Check current usage against limit
    2. Record new request if allowed
    3. Return RateLimitResult with allowed status and metadata

    On backend failure, RateLimitBackendError is raised (fail-closed).
    No HTTP semantics -- callers in framework-specific layers handle
    translation to HTTP responses.

    Attributes:
        backend: Storage backend for rate limit state
        algorithm: Rate limiting algorithm
        config: Global configuration

    Example:
        from neoaxios_resilience_kit.ratelimit import FixedWindowAlgorithm

        enforcer = RateLimitEnforcer(
            backend=redis_backend,
            algorithm=FixedWindowAlgorithm(),
            config=RateLimitConfig(),
        )

        result = await enforcer.check_and_record(
            key="user:123",
            limit=100,
            window_seconds=60,
            cost=1,
        )

        if not result.allowed:
            # Caller decides how to handle denial
            pass
    """

    @auto_trace(logger)
    def __init__(
        self,
        backend: RateLimitBackend,
        algorithm: RateLimitAlgorithm = _DEFAULT_ALGORITHM,
        config: Optional[RateLimitConfig] = None,
    ) -> None:
        """Initialize enforcer.

        Args:
            backend: Storage backend for rate limit state
            algorithm: Rate limiting algorithm (default: FixedWindowAlgorithm)
            config: Global configuration (default: RateLimitConfig())
        """
        self.backend = backend
        self.algorithm = algorithm
        self.config = config or RateLimitConfig()

        logger.info(
            "Initialized RateLimitEnforcer",
            algorithm=self.algorithm.__class__.__name__,
            prefix=self.config.key_prefix,
        )

    @auto_trace(logger)
    async def check_and_record(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitResult:
        """Check rate limit and record request if allowed.

        Rate limiting is fail-closed: when the backend is unavailable,
        :class:`RateLimitBackendError` is raised.

        Args:
            key: Rate limit key (should include prefix)
            limit: Maximum requests allowed in window
            window_seconds: Window size in seconds
            cost: Cost of this request

        Returns:
            RateLimitResult with allowed status and metadata

        Raises:
            RateLimitBackendError: If backend fails (fail-closed behavior)
        """
        try:
            result = await self.algorithm.check(
                backend=self.backend,
                key=key,
                limit=limit,
                window_seconds=window_seconds,
                cost=cost,
            )

            return result

        except Exception as e:
            logger.log_error(
                Exception("Rate limit check failed: backend unavailable"),
            )
            # Fail-closed: always raise exception when backend fails
            raise RateLimitBackendError(
                message="Rate limit backend unavailable",
                original_error=e,
                backend_type=self.backend.__class__.__name__,
            )


@auto_trace(logger)
def create_enforcer(
    backend: RateLimitBackend,
    algorithm: RateLimitAlgorithm = _DEFAULT_ALGORITHM,
    config: Optional[RateLimitConfig] = None,
) -> RateLimitEnforcer:
    """Factory function for RateLimitEnforcer."""
    return RateLimitEnforcer(
        backend=backend,
        algorithm=algorithm,
        config=config,
    )
