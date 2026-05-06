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

"""Resilience patterns for distributed systems: circuit breakers, rate limiting, and failure handling.

This package provides production-grade resilience patterns including:

Circuit Breakers:
- AsyncCircuitBreakerProtocol: Async protocol for circuit breakers
- AsyncRedisCircuitBreaker: Distributed circuit breaker via redis.asyncio (async)
- create_async_circuit_breaker: Async factory (async_redis only)

Rate Limiting:
- RateLimitEnforcer / create_enforcer: Core enforcement logic with factory
- RateLimitBackend / RateLimitAlgorithm: Pluggable backend and algorithm protocols
- InMemoryRateLimitBackend / RedisRateLimitBackend: Storage backends with factories
- FixedWindowAlgorithm / SlidingWindowAlgorithm / TokenBucketAlgorithm: Algorithm strategies with factories
- RateLimitConfig / EndpointConfig: Unified rate limiter configuration
- RateLimitIdentity / HmacRateLimitKeyBuilder: HMAC-obfuscated key building
- RateLimitError / RateLimitBackendError / RateLimitConfigError: Exception hierarchy
- parse_rate / is_valid_rate: Rate string utilities

Retry:
- retry_with_timeout: Async retry with exponential backoff and hard deadline
- RetryBudgetExhausted: Raised when the retry budget (attempts or deadline) is exhausted
"""

from neoaxios_resilience_kit.circuit_breaker import (
    AsyncCircuitBreakerProtocol,
    AsyncRedisCircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    create_async_circuit_breaker,
)
from neoaxios_resilience_kit.ratelimit import (
    EndpointConfig,
    FixedWindowAlgorithm,
    HmacRateLimitKeyBuilder,
    InMemoryRateLimitBackend,
    RateLimitAlgorithm,
    RateLimitBackend,
    RateLimitBackendError,
    RateLimitConfig,
    RateLimitConfigError,
    RateLimitEnforcer,
    RateLimitError,
    RateLimitIdentity,
    RateLimitResult,
    RedisRateLimitBackend,
    SlidingWindowAlgorithm,
    TokenBucketAlgorithm,
    create_enforcer,
    create_fixed_window_algorithm,
    create_memory_ratelimit_backend,
    create_redis_ratelimit_backend,
    create_sliding_window_algorithm,
    create_token_bucket_algorithm,
    is_valid_rate,
    parse_rate,
)
from neoaxios_resilience_kit.retry import (
    RetryBudgetExhausted,
    retry_with_timeout,
)

__version__ = "0.2.1"

__all__ = [
    # Circuit breaker
    "AsyncCircuitBreakerProtocol",
    "AsyncRedisCircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpenError",
    "CircuitState",
    "create_async_circuit_breaker",
    # Rate limiting
    "create_enforcer",
    "create_fixed_window_algorithm",
    "create_memory_ratelimit_backend",
    "create_redis_ratelimit_backend",
    "create_sliding_window_algorithm",
    "create_token_bucket_algorithm",
    "EndpointConfig",
    "FixedWindowAlgorithm",
    "HmacRateLimitKeyBuilder",
    "InMemoryRateLimitBackend",
    "is_valid_rate",
    "parse_rate",
    "RateLimitAlgorithm",
    "RateLimitBackend",
    "RateLimitBackendError",
    "RateLimitConfig",
    "RateLimitConfigError",
    "RateLimitEnforcer",
    "RateLimitError",
    "RateLimitIdentity",
    "RateLimitResult",
    "RedisRateLimitBackend",
    "SlidingWindowAlgorithm",
    "TokenBucketAlgorithm",
    # Retry
    "retry_with_timeout",
    "RetryBudgetExhausted",
]
