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

"""Circuit breaker patterns for resilience in distributed systems.

Provides Protocol-based circuit breaker abstractions with an async Redis
backend, unified configuration, and a factory for backend selection.

Public API:
    - AsyncCircuitBreakerProtocol -- async protocol for circuit breakers
    - AsyncRedisCircuitBreaker -- async, distributed circuit breaker via redis.asyncio
    - create_async_circuit_breaker -- async factory (async_redis only)
"""

from neoaxios_resilience_kit.circuit_breaker.async_redis_backend import (
    AsyncRedisCircuitBreaker,
)
from neoaxios_resilience_kit.circuit_breaker.config import (
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)
from neoaxios_resilience_kit.circuit_breaker.factory import (
    create_async_circuit_breaker,
)
from neoaxios_resilience_kit.circuit_breaker.protocol import (
    AsyncCircuitBreakerProtocol,
)

__all__ = [
    "AsyncCircuitBreakerProtocol",
    "AsyncRedisCircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpenError",
    "CircuitState",
    "create_async_circuit_breaker",
]
