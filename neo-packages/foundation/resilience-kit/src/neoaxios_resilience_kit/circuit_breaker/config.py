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

"""Circuit breaker configuration, state enum, and exception types.

Provides the unified configuration model, state enum, and exception class
used by all circuit breaker backends.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from neoaxios_secure_cache.defaults import (
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS,
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS,
    CIRCUIT_BREAKER_STATE_TTL_SECONDS,
)
from neoaxios_secure_config import Field, SecureSchema
from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states.

    Values are uppercase strings matching Redis storage format.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and request is rejected."""

    def __init__(self, service: str, operation: str, retry_after: int) -> None:
        self.service = service
        self.operation = operation
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker open for {service}:{operation}. "
            f"Retry after {retry_after}s"
        )


class CircuitBreakerConfig(SecureSchema):
    """Unified circuit breaker configuration.

    Inherits from SecureSchema for:
    - Frozen (immutable) model
    - to_safe_dict() for safe logging
    - SecretStr support for fields that need masking

    The backend field selects which circuit breaker implementation
    the create_async_circuit_breaker() factory returns.

    Attributes:
        backend: Backend type selector ("redis" for async_redis).
        service: Service name for circuit identification.
        operation: Operation name for circuit identification.
        failure_threshold: Failures before opening circuit.
        recovery_timeout_seconds: Seconds before attempting recovery.
        half_open_max_calls: Test calls allowed in half-open state.
        state_ttl_seconds: TTL for Redis keys (Redis backend only).
        fail_open: Allow requests when Redis unavailable (Redis backend only).
    """

    backend: Literal["in_memory", "redis"] = Field(
        default="in_memory",
        description="Backend type: in_memory (per-process) or redis (distributed)",
    )
    service: str = Field(
        min_length=1,
        description="Service name for circuit identification (e.g., 'llm')",
    )
    operation: str = Field(
        default="default",
        min_length=1,
        description="Operation name for circuit identification (e.g., 'completion')",
    )
    failure_threshold: int = Field(
        default=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        ge=1,
        description="Number of failures before opening circuit",
    )
    recovery_timeout_seconds: int = Field(
        default=CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS,
        ge=1,
        description="Seconds to wait before attempting recovery (half-open)",
    )
    half_open_max_calls: int = Field(
        default=CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS,
        ge=1,
        description="Number of test calls allowed in half-open state",
    )
    state_ttl_seconds: int = Field(
        default=CIRCUIT_BREAKER_STATE_TTL_SECONDS,
        ge=1,
        description="TTL for Redis keys in seconds (Redis backend only, ignored by in-memory)",
    )
    fail_open: bool = Field(
        default=False,
        description=(
            "Allow requests when Redis is unavailable (Redis backend only). "
            "Default False (fail-closed): distributed workers depend on Redis "
            "for shared state."
        ),
    )
