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

"""Circuit breaker protocol definition.

Defines a runtime-checkable protocol for async circuit breaker backends.
Consumers type-hint against AsyncCircuitBreakerProtocol and construct
via create_async_circuit_breaker().
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar, runtime_checkable

from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)

T = TypeVar("T")


@runtime_checkable
class AsyncCircuitBreakerProtocol(Protocol):
    """Runtime-checkable protocol for async circuit breaker implementations.

    AsyncRedisCircuitBreaker satisfies this protocol. Consumers should
    type-hint against this protocol and use create_async_circuit_breaker()
    for instantiation.
    """

    @property
    def state(self) -> Any:
        """Current circuit state (CircuitState enum value)."""
        ...

    async def execute(self, func: Callable[[], Awaitable[T]]) -> T:
        """Execute async function with circuit breaker protection.

        Args:
            func: Zero-argument async callable to execute.

        Returns:
            Result of awaiting func.

        Raises:
            CircuitBreakerOpenError: If circuit is open.
        """
        ...

    async def record_success(self) -> None:
        """Record a successful operation, potentially closing the circuit."""
        ...

    async def record_failure(self) -> None:
        """Record a failed operation, potentially opening the circuit."""
        ...

    async def get_metrics(self) -> dict[str, Any]:
        """Get current circuit breaker metrics.

        Returns:
            Dict with at minimum: service, operation, state keys.
        """
        ...

    async def reset(self) -> None:
        """Reset the circuit breaker to CLOSED state."""
        ...

    async def allow_request(self) -> bool:
        """Check if a request should be allowed through the circuit.

        Returns:
            True if request can proceed.

        Raises:
            CircuitBreakerOpenError: If circuit is open and recovery timeout
                has not elapsed.
        """
        ...
