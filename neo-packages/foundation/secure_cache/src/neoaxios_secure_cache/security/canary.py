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

"""Canary monitoring for cache integrity verification.

This module implements CanaryMonitor - a background verification system that detects
cache tampering by monitoring canary values stored in the cache.

Features:
- Background verification task runs every 5 seconds
- 1% inline probabilistic checks using secrets module for crypto-safety
- Per-tenant canaries with unique values
- Namespaced canary key via CacheNamespace
- Automatic tamper detection state activation on tampering detection

Usage:
    from neoaxios_secure_cache.security.canary import create_canary_monitor
    from neoaxios_secure_cache.backends.redis import create_redis_backend

    backend = create_redis_backend()
    monitor = create_canary_monitor(
        cache=backend,
        tenant_id="tenant-123",
        check_interval_seconds=5.0,
        inline_check_probability=0.01,
        namespace=security_ns,
    )

    await monitor.start()
    # ... use cache operations ...
    await monitor.stop()

Implementation Notes:
- Implements canary-based tampering detection
- Uses secrets.token_bytes() for crypto-safe randomness
- Background task uses asyncio.create_task()
- Graceful shutdown cancels task and waits for completion
- Factory function for 3+ parameter constructors

Security Requirements:
- Canary values must be unpredictable (use secrets module)
- 1% inline check probability for minimal performance impact
- Background checks ensure regular verification
"""

import asyncio
import secrets
from typing import Any, Optional

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import (
    CACHE_TTL_LONG,
    CANARY_CHECK_INTERVAL_SECONDS,
    CANARY_INLINE_CHECK_PROBABILITY,
)
from neoaxios_secure_cache.namespace import CacheNamespace, KeyTier

logger = get_telemetry(__name__)


class CanaryMonitor:
    """Background canary monitor for cache integrity verification.

    Monitors cache integrity by storing and verifying canary values at regular intervals.
    Detects tampering through background verification (every 5 seconds) and inline checks
    (1% probability on cache operations).

    Features:
    - Background verification: asyncio task runs every check_interval_seconds
    - Inline verification: secrets-based randomness for 1% check probability
    - Per-tenant canaries: unique canary value per tenant_id
    - Tamper detection: activates tamper detection state on canary mismatch
    - Graceful shutdown: cancels background task and waits for completion

    Attributes:
        cache: CacheBackend instance to monitor
        tenant_id: Tenant identifier for canary key namespace
        check_interval_seconds: Background check interval (default: 5.0)
        inline_check_probability: Probability of inline checks (default: 0.01 = 1%)
        tamper_detection: TamperDetectionState instance for tracking violations and recovery
        _canary_value: Expected canary value (set on initialization)
        _background_task: Background verification task
        _running: Flag indicating if monitor is active

    Example:
        monitor = create_canary_monitor(
            cache=backend,
            tenant_id="tenant-123"
        )
        await monitor.start()

        # On cache operations
        if not await monitor.check_inline():
            # Inline check triggered - verify_canary() already called
            pass

        await monitor.stop()
    """

    @auto_trace(logger)
    def __init__(
        self,
        cache: Any,
        tenant_id: str,
        check_interval_seconds: float = CANARY_CHECK_INTERVAL_SECONDS,
        inline_check_probability: float = CANARY_INLINE_CHECK_PROBABILITY,
        tamper_detection: Optional[Any] = None,
        namespace: CacheNamespace | None = None,
        metrics: Optional[Any] = None,
    ) -> None:
        """Initialize canary monitor.

        Args:
            cache: CacheBackend instance to monitor
            tenant_id: Tenant identifier for canary key namespace
            check_interval_seconds: Background check interval in seconds
            inline_check_probability: Probability of inline checks (0.0-1.0)
            tamper_detection: TamperDetectionState instance (optional, created if None)
            namespace: CacheNamespace with domain="security" for key prefixing
            metrics: SecureCacheMetrics instance for Prometheus gauge emission
                (optional, gauges not emitted when None)

        Raises:
            ValueError: If cache is None
            ValueError: If tenant_id is empty
            ValueError: If check_interval_seconds <= 0
            ValueError: If inline_check_probability not in [0.0, 1.0]

        Note:
            Use create_canary_monitor() factory function instead of
            direct instantiation.
        """
        if cache is None:
            raise ValueError("cache cannot be None")

        if not tenant_id:
            raise ValueError("tenant_id cannot be empty")

        if check_interval_seconds <= 0:
            raise ValueError(
                f"check_interval_seconds must be positive (got {check_interval_seconds})"
            )

        if not (0.0 <= inline_check_probability <= 1.0):
            raise ValueError(
                f"inline_check_probability must be in [0.0, 1.0] (got {inline_check_probability})"
            )

        self.cache = cache
        self.tenant_id = tenant_id
        self.check_interval_seconds = check_interval_seconds
        self.inline_check_probability = inline_check_probability
        self._inline_threshold = int(inline_check_probability * 256)
        self._namespace = namespace
        self._metrics = metrics

        # Import here to avoid circular dependency
        from neoaxios_secure_cache.security.tamper_detection import create_tamper_detection_state

        self.tamper_detection = tamper_detection or create_tamper_detection_state()

        # Generate unique canary value (32 bytes = 64 hex chars)
        self._canary_value = secrets.token_hex(32)

        # Background task state
        self._background_task: Optional[asyncio.Task] = None
        self._running = False

        logger.info(
            "canary_monitor_initialized",
            tenant_id=tenant_id,
            check_interval_seconds=check_interval_seconds,
            inline_check_probability=inline_check_probability,
        )

    @auto_trace(logger)
    def _get_canary_key(self) -> str:
        """Get namespaced canary key for this tenant.

        Returns:
            Namespaced canary key via CacheNamespace.

        Raises:
            ValueError: If namespace was not provided at construction time.
        """
        if self._namespace is None:
            raise ValueError("namespace is required for canary key generation")
        return self._namespace.make_key_at(
            KeyTier.DOMAIN, f"canary:{self.tenant_id}"
        )

    @auto_trace(logger)
    async def start(self) -> None:
        """Start background verification task.

        Stores initial canary value in cache and launches background task
        for periodic verification.

        Raises:
            RuntimeError: If monitor is already running
            Exception: If canary storage fails
        """
        if self._running:
            raise RuntimeError("CanaryMonitor is already running")

        try:
            # Store initial canary value (24 hour TTL)
            canary_key = self._get_canary_key()
            await self.cache.set(canary_key, self._canary_value, ttl_seconds=CACHE_TTL_LONG)
            logger.info("canary_stored", tenant_id=self.tenant_id)

            # Start background task
            self._running = True
            self._background_task = asyncio.create_task(self._background_verification_loop())
            logger.info("Started background verification task")

        except Exception as e:
            self._running = False
            logger.log_error(e, operation="start_canary_monitor")
            raise

    @auto_trace(logger)
    async def stop(self) -> None:
        """Stop background verification task gracefully.

        Cancels background task and waits for completion.
        Does not raise if monitor is not running.
        """
        if not self._running:
            logger.debug("CanaryMonitor is not running")
            return

        self._running = False

        if self._background_task:
            try:
                self._background_task.cancel()
                await self._background_task
            except asyncio.CancelledError:
                logger.debug("Background task cancelled successfully")
            except Exception as e:
                logger.log_error(e, operation="stop_background_task")

        logger.info("Stopped CanaryMonitor")

    @auto_trace(logger)
    async def _background_verification_loop(self) -> None:
        """Background task that verifies canary at regular intervals.

        Runs until _running flag is False. Sleeps for check_interval_seconds
        between checks.
        """
        logger.info(
            "canary_background_loop_started",
            check_interval_seconds=self.check_interval_seconds,
        )

        try:
            while self._running:
                await asyncio.sleep(self.check_interval_seconds)

                if not self._running:
                    break

                await self.verify_canary()

        except asyncio.CancelledError:
            logger.debug("Background verification loop cancelled")
            raise
        except Exception as e:
            logger.log_error(e, operation="background_verification_loop")
            raise

    @auto_trace(logger)
    async def check_inline(self) -> bool:
        """Probabilistic inline canary check.

        Called on cache operations. Returns False if inline check was triggered
        (meaning verify_canary() was already called).

        Uses secrets.token_bytes() for crypto-safe randomness.
        For 1% probability: secrets.token_bytes(1)[0] < 3 ≈ 1.2% (3/256)

        Returns:
            True if no inline check performed, False if check was triggered

        Implementation:
            - Generate random byte using secrets.token_bytes(1)
            - Calculate threshold: int(inline_check_probability * 256)
            - Trigger check if random_byte < threshold
        """
        # Generate crypto-safe random byte
        random_byte = secrets.token_bytes(1)[0]

        # Check if we should verify (threshold precomputed in __init__)
        if random_byte < self._inline_threshold:
            logger.debug("Inline canary check triggered")
            await self.verify_canary()
            return False  # Inline check was performed

        return True  # No inline check performed

    @auto_trace(logger)
    async def verify_canary(self) -> bool:
        """Verify canary value matches expected value.

        Retrieves canary from cache and compares with expected value.
        Activates tamper detection state on mismatch or retrieval failure.
        Emits Prometheus gauges (cache_canary_mismatch, cache_integrity_violation_active)
        when metrics are configured.

        Returns:
            True if canary matches, False if mismatch or error

        Side Effects:
            - Activates tamper detection state on verification failure
            - Records success in tamper detection state on verification success
            - Emits Prometheus metrics on state changes
        """
        try:
            canary_key = self._get_canary_key()
            stored_value = await self.cache.get(canary_key)

            if stored_value is None:
                self._activate_tamper_detection(
                    f"Canary missing for tenant '{self.tenant_id}' - activating tamper detection"
                )
                return False

            if stored_value != self._canary_value:
                self._activate_tamper_detection(
                    f"Canary mismatch for tenant '{self.tenant_id}' - activating tamper detection"
                )
                return False

            # Canary verified successfully
            logger.debug("canary_verified", tenant_id=self.tenant_id)
            was_active = self.tamper_detection.is_active()
            self.tamper_detection.record_success()
            # Emit recovery metrics if tamper detection just deactivated
            if was_active and not self.tamper_detection.is_active():
                self._emit_tampering_metrics(active=False)
            return True

        except Exception:
            self._activate_tamper_detection(
                f"Error verifying canary for tenant '{self.tenant_id}' - "
                f"activating tamper detection"
            )
            return False

    @auto_trace(logger)
    def _activate_tamper_detection(self, reason: str) -> None:
        """Activate tamper detection state, log the reason, and emit tampering metrics.

        Args:
            reason: Human-readable reason for tamper detection activation.
        """
        logger.log_error(Exception(reason))
        self.tamper_detection.activate()
        self._emit_tampering_metrics(active=True)

    @auto_trace(logger)
    def _emit_tampering_metrics(self, active: bool) -> None:
        """Emit canary mismatch and integrity violation Prometheus gauges.

        No-op when metrics are not configured.

        Args:
            active: True when tampering detected, False on recovery.
        """
        if self._metrics is None:
            return
        self._metrics.set_canary_mismatch(tenant_id=self.tenant_id, active=active)
        self._metrics.set_integrity_violation_active(tenant_id=self.tenant_id, active=active)


@auto_trace(logger)
def create_canary_monitor(
    cache: Any,
    tenant_id: str,
    check_interval_seconds: float = CANARY_CHECK_INTERVAL_SECONDS,
    inline_check_probability: float = CANARY_INLINE_CHECK_PROBABILITY,
    tamper_detection: Optional[Any] = None,
    namespace: CacheNamespace | None = None,
    metrics: Optional[Any] = None,
) -> CanaryMonitor:
    """Factory function for CanaryMonitor.

    Creates a CanaryMonitor instance with validated parameters.
    Required for objects with 3+ constructor parameters.

    Args:
        cache: CacheBackend instance to monitor
        tenant_id: Tenant identifier for canary key namespace
        check_interval_seconds: Background check interval in seconds (default: 5.0)
        inline_check_probability: Probability of inline checks (default: 0.01 = 1%)
        tamper_detection: TamperDetectionState instance (optional, created if None)
        namespace: CacheNamespace with domain="security" for key prefixing
        metrics: SecureCacheMetrics instance for Prometheus gauge emission
            (optional, gauges not emitted when None)

    Returns:
        Configured CanaryMonitor instance

    Raises:
        ValueError: If cache is None
        ValueError: If tenant_id is empty
        ValueError: If check_interval_seconds <= 0
        ValueError: If inline_check_probability not in [0.0, 1.0]

    Example:
        from neoaxios_secure_cache.security.canary import create_canary_monitor
        from neoaxios_secure_cache.backends.redis import create_redis_backend

        backend = create_redis_backend()
        monitor = create_canary_monitor(
            cache=backend,
            tenant_id="tenant-123",
            namespace=security_ns,
        )

        await monitor.start()
        # ... use cache operations ...
        await monitor.stop()
    """
    # Validation happens in __init__
    return CanaryMonitor(
        cache=cache,
        tenant_id=tenant_id,
        check_interval_seconds=check_interval_seconds,
        inline_check_probability=inline_check_probability,
        tamper_detection=tamper_detection,
        namespace=namespace,
        metrics=metrics,
    )
