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

"""Async Redis-backed circuit breaker with shared state across distributed workers.

Stores circuit breaker state in Redis using redis.asyncio.Redis, ensuring all
workers share the same view of service health. Satisfies AsyncCircuitBreakerProtocol.

All public methods are async def. Multi-key operations (record_success,
get_metrics, reset) use async pipelines for single-round-trip atomicity.

Redis Key Structure (namespace-scoped via CacheNamespace with hash tags):
    {domain_scope}:{{service}:{operation}}:failures       - failure count (int)
    {domain_scope}:{{service}:{operation}}:state           - CLOSED|OPEN|HALF_OPEN
    {domain_scope}:{{service}:{operation}}:last_failure    - ISO timestamp
    {domain_scope}:{{service}:{operation}}:half_open_lock  - lock for half-open test

Where {domain_scope} is produced by CacheNamespace.domain_scope() and encodes
org, env, service, app, version, and domain='circuit'. The {{service}:{operation}}
hash tag ensures all 4 keys land in the same Redis Cluster hash slot, enabling
pipeline operations without CROSSSLOT errors.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

import redis.asyncio
import redis.exceptions
from neoaxios_secure_cache import CacheNamespace
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_resilience_kit.circuit_breaker.config import (
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)

logger = get_telemetry(__name__)

T = TypeVar("T")


class AsyncRedisCircuitBreaker:
    """Async Redis-backed circuit breaker with shared state.

    Satisfies AsyncCircuitBreakerProtocol. Uses CacheNamespace-scoped Redis keys
    for distributed state sharing across async consumers and other processes.

    All public methods are async def. Pipeline operations are used for
    record_success, get_metrics, and reset to minimize round-trips.

    Example:
        >>> from neoaxios_secure_cache import CacheNamespace
        >>> from neoaxios_resilience_kit import create_async_circuit_breaker, CircuitBreakerConfig
        >>> ns = CacheNamespace(org="neo", env="prod", service="api", app="checkout", domain="circuit")
        >>> config = CircuitBreakerConfig(service="llm", operation="completion", backend="redis")
        >>> breaker = create_async_circuit_breaker(config, namespace=ns)
        >>> result = await breaker.execute(async_call_llm)
    """

    def __init__(
        self,
        redis_client: redis.asyncio.Redis,
        config: CircuitBreakerConfig,
        namespace: CacheNamespace,
    ) -> None:
        """Initialize async Redis circuit breaker.

        Args:
            redis_client: Connected async Redis client.
            config: Circuit breaker configuration.
            namespace: CacheNamespace with domain='circuit' for key scoping.
        """
        self._redis_client = redis_client
        self._config = config
        self._namespace = namespace
        self._local_state: CircuitState = CircuitState.CLOSED

    @property
    def state(self) -> CircuitState:
        """Current circuit state (sync property for protocol compliance).

        Note: This property cannot perform async I/O. Returns the locally
        cached state, updated whenever async methods read or modify state
        in Redis (allow_request, record_success, record_failure, reset,
        get_metrics).
        """
        return self._local_state

    @auto_trace(logger)
    def _key(self, suffix: str) -> str:
        """Build Redis key with suffix via CacheNamespace.make_slot_key()."""
        return self._namespace.make_slot_key(
            slot_group=f"{self._config.service}:{self._config.operation}",
            suffix=suffix,
        )

    @auto_trace(logger)
    async def _get_state(self) -> CircuitState:
        """Get current circuit state from Redis.

        Returns:
            CircuitState.CLOSED if state not found or Redis unavailable
            (when fail_open=True).

        Raises:
            redis.exceptions.RedisError: If Redis unavailable and fail_open=False.
        """
        try:
            state_bytes: bytes | None = await self._redis_client.get(self._key("state"))  # type: ignore[assignment]
            if state_bytes is None:
                self._local_state = CircuitState.CLOSED
                return CircuitState.CLOSED
            resolved = CircuitState(state_bytes.decode())
            self._local_state = resolved
            return resolved
        except redis.exceptions.RedisError as e:
            logger.log_error(
                e,
                context="Redis read failed for circuit state",
                service=self._config.service,
                operation=self._config.operation,
            )
            if self._config.fail_open:
                # fail_open is an explicit operator opt-in via config.
                # Defaulting to CLOSED lets requests through when Redis is unavailable,
                # which is the documented and intended behavior for fail_open=True.
                return CircuitState.CLOSED
            raise

    @auto_trace(logger)
    async def allow_request(self) -> bool:
        """Check if request should be allowed.

        Returns:
            True if request can proceed, False if circuit is open.

        Raises:
            CircuitBreakerOpenError: If circuit is open and fail_open is False.
        """
        try:
            state = await self._get_state()

            if state == CircuitState.CLOSED:
                return True

            if state == CircuitState.OPEN:
                last_failure: bytes | None = await self._redis_client.get(self._key("last_failure"))  # type: ignore[assignment]
                if last_failure:
                    last_dt = datetime.fromisoformat(last_failure.decode())
                    elapsed = (
                        datetime.now(timezone.utc) - last_dt
                    ).total_seconds()

                    if elapsed >= self._config.recovery_timeout_seconds and await self._try_acquire_half_open_lock():
                        logger.info(
                            "circuit_breaker_half_open",
                            service=self._config.service,
                            operation=self._config.operation,
                            elapsed_seconds=elapsed,
                        )
                        return True

                raise CircuitBreakerOpenError(
                    self._config.service,
                    self._config.operation,
                    self._config.recovery_timeout_seconds,
                )

            if state == CircuitState.HALF_OPEN:
                raise CircuitBreakerOpenError(
                    self._config.service,
                    self._config.operation,
                    self._config.recovery_timeout_seconds,
                )

            return True

        except redis.exceptions.RedisError as e:
            logger.log_error(
                e,
                context="Redis read failed for allow_request check",
                service=self._config.service,
                operation=self._config.operation,
            )
            if self._config.fail_open:
                # fail_open is an explicit operator opt-in via config.
                # Returning True allows requests when Redis is unavailable,
                # which is the documented and intended behavior for fail_open=True.
                return True
            raise

    @auto_trace(logger)
    async def _try_acquire_half_open_lock(self) -> bool:
        """Try to acquire lock for half-open test request.

        Uses SET NX for atomic lock acquisition, then pipelines the state
        transition to HALF_OPEN in a single round-trip.
        """
        lock_key = self._key("half_open_lock")
        acquired = await self._redis_client.set(
            lock_key,
            "1",
            nx=True,
            ex=self._config.recovery_timeout_seconds,
        )
        if acquired:
            # Transactional pipeline (MULTI/EXEC) is intentionally retained here.
            # make_slot_key() co-locates all circuit breaker keys in the same
            # hash slot, ensuring single-node execution under cluster topology.
            pipe = self._redis_client.pipeline()
            pipe.set(
                self._key("state"),
                CircuitState.HALF_OPEN.value,
                ex=self._config.state_ttl_seconds,
            )
            await pipe.execute()
            self._local_state = CircuitState.HALF_OPEN
        return bool(acquired)

    @auto_trace(logger)
    async def record_success(self) -> None:
        """Record successful request, reset circuit to closed.

        Uses async pipeline for single-round-trip atomicity.
        """
        try:
            # Transactional pipeline (MULTI/EXEC) is intentionally retained here.
            # make_slot_key() co-locates all circuit breaker keys in the same
            # hash slot, ensuring single-node execution under cluster topology.
            pipe = self._redis_client.pipeline()
            pipe.set(
                self._key("state"),
                CircuitState.CLOSED.value,
                ex=self._config.state_ttl_seconds,
            )
            pipe.set(
                self._key("failures"), 0, ex=self._config.state_ttl_seconds
            )
            pipe.delete(self._key("half_open_lock"))
            pipe.delete(self._key("last_failure"))
            await pipe.execute()
            self._local_state = CircuitState.CLOSED

            logger.info(
                "circuit_breaker_reset",
                service=self._config.service,
                operation=self._config.operation,
            )

        except redis.exceptions.RedisError as e:
            # Swallowing Redis errors in record_success is safe
            # because the in-flight request already succeeded. Failing to update
            # circuit state in Redis means the next request will re-evaluate;
            # the success was not lost, only the state reset was deferred.
            logger.log_error(
                e,
                context="Redis write failed during record_success",
                service=self._config.service,
                operation=self._config.operation,
            )

    @auto_trace(logger)
    async def record_failure(self) -> None:
        """Record failed request, potentially open circuit.

        Pipelines incr+expire+set into a single round-trip, then
        reads state and conditionally transitions to OPEN.
        """
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            # Transactional pipeline (MULTI/EXEC) is intentionally retained here.
            # make_slot_key() co-locates all circuit breaker keys in the same
            # hash slot, ensuring single-node execution under cluster topology.
            pipe = self._redis_client.pipeline()
            pipe.incr(self._key("failures"))
            pipe.expire(self._key("failures"), self._config.state_ttl_seconds)
            pipe.set(
                self._key("last_failure"),
                now_iso,
                ex=self._config.state_ttl_seconds,
            )
            pipe.get(self._key("state"))
            results = await pipe.execute()
            new_count: int = results[0]

            state_bytes: bytes | None = results[3]
            if state_bytes is None:
                current_state = CircuitState.CLOSED
            else:
                current_state = CircuitState(
                    state_bytes.decode() if isinstance(state_bytes, bytes) else state_bytes
                )
            self._local_state = current_state

            should_open = (
                current_state == CircuitState.HALF_OPEN
                or new_count >= self._config.failure_threshold
            )
            if should_open:
                await self._transition_to_open(new_count)

        except redis.exceptions.RedisError as e:
            # Swallowing Redis errors in record_failure is safe
            # because the circuit breaker is a secondary protection mechanism.
            # The primary failure (from the wrapped call) is still propagated to
            # the caller. Missing a failure count increment may delay circuit
            # opening but does not mask the original error.
            logger.log_error(
                e,
                context="Redis write failed during record_failure",
                service=self._config.service,
                operation=self._config.operation,
            )

    @auto_trace(logger)
    async def _transition_to_open(self, failure_count: int) -> None:
        """Transition circuit to open state.

        Pipelines state SET + lock DELETE into a single round-trip.
        """
        try:
            # Transactional pipeline (MULTI/EXEC) is intentionally retained here.
            # make_slot_key() co-locates all circuit breaker keys in the same
            # hash slot, ensuring single-node execution under cluster topology.
            pipe = self._redis_client.pipeline()
            pipe.set(
                self._key("state"),
                CircuitState.OPEN.value,
                ex=self._config.state_ttl_seconds,
            )
            pipe.delete(self._key("half_open_lock"))
            await pipe.execute()
            self._local_state = CircuitState.OPEN

            logger.info(
                "circuit_breaker_opened",
                service=self._config.service,
                operation=self._config.operation,
                failure_count=failure_count,
                recovery_timeout=self._config.recovery_timeout_seconds,
            )
        except redis.exceptions.RedisError as e:
            # Swallowing Redis errors in _transition_to_open is safe
            # because the original failure (from record_failure) is already propagated
            # to the caller. Failing to persist OPEN state means the circuit stays in
            # its previous state temporarily; the next record_failure will retry.
            logger.log_error(
                e,
                context="Redis write failed during circuit state transition to OPEN",
                service=self._config.service,
                operation=self._config.operation,
            )

    @auto_trace(logger)
    async def get_metrics(self) -> dict[str, Any]:
        """Get current circuit breaker metrics.

        Uses async pipeline for single-round-trip atomicity.
        """
        try:
            # Non-transactional pipeline: these are pure reads for a diagnostic
            # snapshot — no write ordering to protect.  Commands are still batched
            # in a single round-trip but skip MULTI/EXEC to avoid
            # serialising the hash slot under contention.
            pipe = self._redis_client.pipeline(transaction=False)
            pipe.get(self._key("state"))
            pipe.get(self._key("failures"))
            pipe.get(self._key("last_failure"))
            results: list[bytes | None] = await pipe.execute()  # type: ignore[assignment]

            state = (
                results[0].decode() if results[0] else CircuitState.CLOSED.value
            )
            self._local_state = CircuitState(state)
            failures = int(results[1]) if results[1] else 0
            last_failure = results[2].decode() if results[2] else None

            return {
                "service": self._config.service,
                "operation": self._config.operation,
                "state": state,
                "failure_count": failures,
                "last_failure": last_failure,
                "config": {
                    "failure_threshold": self._config.failure_threshold,
                    "recovery_timeout_seconds": self._config.recovery_timeout_seconds,
                },
            }
        except redis.exceptions.RedisError as e:
            # get_metrics is a diagnostic/observability endpoint.
            # Returning a degraded result with state=UNKNOWN and the error message
            # is preferable to raising, because callers (health checks, dashboards)
            # must not crash when Redis is transiently unavailable.
            logger.log_error(
                e,
                context="Redis read failed during get_metrics",
                service=self._config.service,
                operation=self._config.operation,
            )
            return {
                "service": self._config.service,
                "operation": self._config.operation,
                "state": "UNKNOWN",
                "error": str(e),
            }

    @auto_trace(logger)
    async def reset(self) -> None:
        """Reset the circuit breaker to CLOSED state.

        Deletes all Redis keys (failures, state, last_failure, half_open_lock)
        via async pipeline for single-round-trip atomic cleanup.
        """
        try:
            # Transactional pipeline (MULTI/EXEC) is intentionally retained here.
            # make_slot_key() co-locates all circuit breaker keys in the same
            # hash slot, ensuring single-node execution under cluster topology.
            # MULTI/EXEC is required because a concurrent record_failure() using
            # its own MULTI/EXEC pipeline can re-create `failures` or `last_failure`
            # between individual non-transactional DELETEs, leaving stale failure
            # state after reset and risking premature circuit re-opening.
            pipe = self._redis_client.pipeline()
            pipe.delete(self._key("state"))
            pipe.delete(self._key("failures"))
            pipe.delete(self._key("last_failure"))
            pipe.delete(self._key("half_open_lock"))
            await pipe.execute()
            self._local_state = CircuitState.CLOSED

            logger.info(
                "circuit_breaker_manual_reset",
                service=self._config.service,
                operation=self._config.operation,
            )
        except redis.exceptions.RedisError as e:
            # reset() is an explicit operator action (manual reset).
            # Swallowing is acceptable because the operator will observe the failure
            # via the logged error and retry. Raising here would crash CLI tooling
            # or health-check endpoints that call reset().
            logger.log_error(
                e,
                context="Redis write failed during manual reset",
                service=self._config.service,
                operation=self._config.operation,
            )

    @auto_trace(logger)
    async def execute(self, func: Callable[[], Awaitable[T]]) -> T:
        """Execute async function with circuit breaker protection.

        Args:
            func: Zero-argument async callable to execute.

        Returns:
            Result of awaiting func.

        Raises:
            CircuitBreakerOpenError: If circuit is open.
        """
        if not await self.allow_request():
            raise CircuitBreakerOpenError(
                self._config.service,
                self._config.operation,
                self._config.recovery_timeout_seconds,
            )

        try:
            result = await func()
            await self.record_success()
            return result
        except Exception:
            await self.record_failure()
            raise
