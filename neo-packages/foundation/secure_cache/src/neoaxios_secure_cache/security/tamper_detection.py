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

"""Tamper detection state for cache integrity violations.

Tracks whether cache tampering has been detected and manages
auto-recovery after consecutive successful canary checks.

CanaryMonitor calls activate() on tampering detection and
record_success() on each passing verification. After
recovery_threshold consecutive successes, tamper detection deactivates.

The is_active() flag is consumed by:
- secure_cache.health.get_cache_health() for /health readiness demotion
- CanaryMonitor._emit_tampering_metrics() for Prometheus gauge emission

This module does NOT enforce cache bypass, rate limiting, or jitter.
Those concerns belong to the consumer/infrastructure layer which has
the context to decide the appropriate response.

Usage:
    from neoaxios_secure_cache.security.tamper_detection import create_tamper_detection_state

    state = create_tamper_detection_state(recovery_threshold=10)

    # On tampering detection
    state.activate()

    # Check status
    if state.is_active():
        # Signal to health/metrics — consumer decides response
        pass

    # On successful canary check
    state.record_success()  # Auto-deactivates after threshold
"""

from neoaxios_secure_cache.defaults import AUTO_RECOVERY_THRESHOLD
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class TamperDetectionState:
    """Tamper detection state for cache integrity violations.

    Tracks activation state and manages auto-recovery via consecutive
    successful canary checks. Consumed by health and metrics layers
    for signaling — does not enforce cache behavior changes.

    Attributes:
        recovery_threshold: Number of consecutive successes for auto-recovery
        _active: Tamper detection activation flag
        _consecutive_successes: Counter for auto-recovery

    Example:
        state = create_tamper_detection_state(recovery_threshold=10)

        # On tampering detection
        state.activate()

        # On successful canary check
        state.record_success()  # Auto-deactivates after threshold
    """

    @auto_trace(logger)
    def __init__(
        self,
        recovery_threshold: int = AUTO_RECOVERY_THRESHOLD,
    ) -> None:
        """Initialize tamper detection state.

        Args:
            recovery_threshold: Consecutive successes required for auto-recovery

        Raises:
            ValueError: If recovery_threshold <= 0

        Note:
            Use create_tamper_detection_state() factory function instead of
            direct instantiation.
        """
        if recovery_threshold <= 0:
            raise ValueError(
                f"recovery_threshold must be positive (got {recovery_threshold})"
            )

        self.recovery_threshold = recovery_threshold

        # Tamper detection state
        self._active = False
        self._consecutive_successes = 0

        logger.info(
            f"Initialized TamperDetectionState (recovery={recovery_threshold})"
        )

    @auto_trace(logger)
    def is_active(self) -> bool:
        """Check if tamper detection is active.

        Returns:
            True if tampering has been detected, False otherwise
        """
        return self._active

    @auto_trace(logger)
    def activate(self) -> None:
        """Activate tamper detection state.

        Sets tamper detection to active and resets consecutive success counter.
        Logs security event.
        """
        if not self._active:
            self._active = True
            logger.log_error(
                Exception(
                    "Tamper detection ACTIVATED - cache integrity violation detected"
                )
            )
        else:
            logger.debug("Tamper detection already active")

        # Always reset consecutive successes counter on activation
        self._consecutive_successes = 0

    @auto_trace(logger)
    def record_success(self) -> None:
        """Record successful canary check.

        Increments consecutive success counter. Deactivates tamper detection
        if counter reaches recovery_threshold.
        """
        if not self._active:
            # Not in tamper detection state - nothing to do
            return

        self._consecutive_successes += 1
        logger.debug(
            f"Canary check success recorded ({self._consecutive_successes}/"
            f"{self.recovery_threshold})"
        )

        if self._consecutive_successes >= self.recovery_threshold:
            self._active = False
            self._consecutive_successes = 0
            logger.info(
                f"Tamper detection DEACTIVATED - {self.recovery_threshold} consecutive "
                f"successful checks"
            )


@auto_trace(logger)
def create_tamper_detection_state(
    recovery_threshold: int = AUTO_RECOVERY_THRESHOLD,
) -> TamperDetectionState:
    """Factory function for TamperDetectionState.

    Args:
        recovery_threshold: Consecutive successes for auto-recovery (default: 10)

    Returns:
        Configured TamperDetectionState instance

    Raises:
        ValueError: If recovery_threshold <= 0
    """
    return TamperDetectionState(
        recovery_threshold=recovery_threshold,
    )
