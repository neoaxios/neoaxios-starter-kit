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

"""Circuit breaker factory for async Redis backend.

Provides ``create_async_circuit_breaker()`` which returns an
AsyncRedisCircuitBreaker backed by Redis via the secure_cache gateway.
"""

from __future__ import annotations

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache import CacheNamespace
from neoaxios_secure_cache.gateway import get_gateway

from neoaxios_resilience_kit.circuit_breaker.async_redis_backend import (
    AsyncRedisCircuitBreaker,
)
from neoaxios_resilience_kit.circuit_breaker.config import (
    CircuitBreakerConfig,
)
from neoaxios_resilience_kit.circuit_breaker.protocol import (
    AsyncCircuitBreakerProtocol,
)

logger = get_telemetry(__name__)


@auto_trace(logger)
def create_async_circuit_breaker(
    config: CircuitBreakerConfig,
    namespace: CacheNamespace | None = None,
    backend: str = "async_redis",
) -> AsyncCircuitBreakerProtocol:
    """Create an async circuit breaker backed by Redis.

    Only ``backend="async_redis"`` is supported.

    Redis connections are obtained from the secure_cache gateway via
    ``get_gateway().get_async_client("circuit")``.

    Args:
        config: Circuit breaker configuration.
        namespace: CacheNamespace for Redis key scoping (required for
            async_redis backend).
        backend: Backend selector.  Only ``"async_redis"`` is accepted.

    Returns:
        AsyncRedisCircuitBreaker satisfying AsyncCircuitBreakerProtocol.

    Raises:
        ValueError: If backend is unknown or namespace is None for async_redis.
    """
    if backend == "async_redis":
        if namespace is None:
            raise ValueError(
                "namespace is required when backend is 'async_redis'. "
                "Provide a CacheNamespace with domain='circuit'."
            )
        # All Redis connections go through the secure_cache gateway.
        client = get_gateway().get_async_client(
            "circuit", decode_responses=False,
        )
        return AsyncRedisCircuitBreaker(
            redis_client=client, config=config, namespace=namespace,
        )

    raise ValueError(f"Unknown async circuit breaker backend: {backend!r}")
