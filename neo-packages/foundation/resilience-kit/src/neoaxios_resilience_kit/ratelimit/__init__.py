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

"""Rate limiting patterns for resilience in distributed systems.

Provides framework-agnostic rate limiting abstractions with interchangeable
in-memory and Redis backends, pluggable algorithm strategies (fixed window,
sliding window, token bucket), HMAC-obfuscated key building, unified
configuration, and an enforcer for rate limit checking.

Public API:
    Protocols:
        - RateLimitBackend: Protocol for rate limit storage backends
        - RateLimitAlgorithm: Protocol for rate limiting algorithms
        - RateLimitResult: Dataclass representing a rate limit check result

    Configuration:
        - RateLimitConfig: Global rate limiter configuration
        - EndpointConfig: Per-endpoint rate limit configuration

    Utilities:
        - parse_rate: Parse rate limit string into (limit, window_seconds)
        - is_valid_rate: Validate rate limit string format

    Exceptions:
        - RateLimitError: Base exception for all rate limiting errors
        - RateLimitBackendError: Backend unavailable (fail-closed)
        - RateLimitConfigError: Configuration validation error

    Key Building:
        - RateLimitIdentity: Protocol for rate limit identity input
        - HmacRateLimitKeyBuilder: HMAC-obfuscated key builder

    Algorithms:
        - FixedWindowAlgorithm: Fixed window counter algorithm
        - create_fixed_window_algorithm: Factory for FixedWindowAlgorithm
        - SlidingWindowAlgorithm: Sliding window log algorithm
        - create_sliding_window_algorithm: Factory for SlidingWindowAlgorithm
        - TokenBucketAlgorithm: Token bucket rate limiting algorithm
        - create_token_bucket_algorithm: Factory for TokenBucketAlgorithm

    Backends:
        - InMemoryRateLimitBackend: In-memory backend for testing
        - create_memory_ratelimit_backend: Factory for InMemoryRateLimitBackend
        - RedisRateLimitBackend: Redis-backed production backend
        - create_redis_ratelimit_backend: Factory for RedisRateLimitBackend

    Enforcer:
        - RateLimitEnforcer: Core enforcement logic (check-record-respond)
        - create_enforcer: Factory for RateLimitEnforcer
"""

from .algorithms.fixed_window import (
    FixedWindowAlgorithm,
    create_fixed_window_algorithm,
)
from .algorithms.sliding_window import (
    SlidingWindowAlgorithm,
    create_sliding_window_algorithm,
)
from .algorithms.token_bucket import (
    TokenBucketAlgorithm,
    create_token_bucket_algorithm,
)
from .backends.memory import (
    InMemoryRateLimitBackend,
    create_memory_ratelimit_backend,
)
from .backends.redis import (
    RedisRateLimitBackend,
    create_redis_ratelimit_backend,
)
from .config import (
    EndpointConfig,
    RateLimitConfig,
)
from .enforcer import (
    RateLimitEnforcer,
    create_enforcer,
)
from .exceptions import (
    RateLimitBackendError,
    RateLimitConfigError,
    RateLimitError,
)
from .key_builder import (
    HmacRateLimitKeyBuilder,
    RateLimitIdentity,
)
from .protocols import (
    RateLimitAlgorithm,
    RateLimitBackend,
    RateLimitResult,
)
from .utils import (
    is_valid_rate,
    parse_rate,
)

__all__ = [
    # Protocols
    "RateLimitAlgorithm",
    "RateLimitBackend",
    "RateLimitResult",
    # Configuration
    "EndpointConfig",
    "RateLimitConfig",
    # Utilities
    "is_valid_rate",
    "parse_rate",
    # Exceptions
    "RateLimitBackendError",
    "RateLimitConfigError",
    "RateLimitError",
    # Key Building
    "HmacRateLimitKeyBuilder",
    "RateLimitIdentity",
    # Algorithms
    "FixedWindowAlgorithm",
    "SlidingWindowAlgorithm",
    "TokenBucketAlgorithm",
    "create_fixed_window_algorithm",
    "create_sliding_window_algorithm",
    "create_token_bucket_algorithm",
    # Backends
    "InMemoryRateLimitBackend",
    "RedisRateLimitBackend",
    "create_memory_ratelimit_backend",
    "create_redis_ratelimit_backend",
    # Enforcer
    "RateLimitEnforcer",
    "create_enforcer",
]
