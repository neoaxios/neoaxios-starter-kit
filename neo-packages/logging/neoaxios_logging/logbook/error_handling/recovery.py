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

"""
Retry and recovery logic for transient logging errors.

This module implements intelligent retry mechanisms for handling
transient errors in logging operations:
- Disk temporarily full (may free up)
- Network file systems temporarily unavailable
- Temporary permission issues
- File descriptor limits reached temporarily

The recovery system distinguishes between:
- Transient errors (retry with backoff)
- Permanent errors (fail fast, use fallback)
"""

import time
import threading
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from enum import Enum

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


class ErrorCategory(Enum):
    """Classification of error types for recovery strategy."""
    TRANSIENT = "transient"  # Retry with backoff
    PERMANENT = "permanent"  # Fail fast, use fallback
    UNKNOWN = "unknown"      # Conservative retry, then fail


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1  # seconds
    max_delay: float = 5.0      # seconds
    backoff_factor: float = 2.0  # Exponential backoff multiplier


class RecoveryManager:
    """
    Manages retry and recovery for logging operations.

    Features:
    - Exponential backoff for retries
    - Error classification (transient vs permanent)
    - Automatic recovery detection
    - Thread-safe operation
    """

    @auto_trace(logger)
    def __init__(self, config: Optional[RetryConfig] = None):
        """
        Initialize recovery manager.

        Args:
            config: Retry configuration (uses defaults if None)
        """

        self.config = config or RetryConfig()
        self.retry_counts: Dict[str, int] = {}
        self.last_success: Dict[str, float] = {}
        self.lock = threading.Lock()


    @auto_trace(logger)
    def execute_with_retry(
        self,
        operation: Callable[[], Any],
        operation_id: str,
        on_error: Optional[Callable[[Exception], None]] = None
    ) -> Optional[Any]:
        """
        Execute operation with automatic retry on transient failures.

        Args:
            operation: Function to execute
            operation_id: Unique identifier for this operation (for tracking)
            on_error: Optional callback when errors occur

        Returns:
            Operation result if successful, None if all retries exhausted

        Example:
            def write_log():
                with open(path, 'a') as f:
                    f.write(log_data)

            result = manager.execute_with_retry(
                write_log,
                operation_id="write_main_log"
            )
        """

        attempt = 0
        delay = self.config.initial_delay

        while attempt < self.config.max_attempts:
            attempt += 1

            try:
                # Execute operation
                result = operation()

                # Success - reset counters
                with self.lock:
                    self.retry_counts[operation_id] = 0
                    self.last_success[operation_id] = time.time()

                logger.trace(
                    "Operation succeeded",
                    operation_id=operation_id,
                    attempt=attempt
                )
                return result

            except Exception as e:
                # Classify error
                category = self._classify_error(e)

                logger.debug(
                    "Operation failed",
                    operation_id=operation_id,
                    attempt=attempt,
                    max_attempts=self.config.max_attempts,
                    error_type=type(e).__name__,
                    error_category=category.value,
                    error=str(e)
                )

                # Track retry count
                with self.lock:
                    self.retry_counts[operation_id] = attempt

                # Call error callback if provided
                if on_error:
                    try:
                        on_error(e)
                    except:
                        pass  # Suppress callback errors

                # Permanent errors don't get retries
                if category == ErrorCategory.PERMANENT:
                    logger.warning(
                        "Permanent error detected, aborting retries",
                        operation_id=operation_id,
                        error_type=type(e).__name__
                    )
                    return None

                # Last attempt failed
                if attempt >= self.config.max_attempts:
                    logger.warning(
                        "All retry attempts exhausted",
                        operation_id=operation_id,
                        attempts=attempt,
                        last_error=str(e)
                    )
                    return None

                # Wait before retry (exponential backoff)
                if attempt < self.config.max_attempts:
                    logger.trace(
                        "Retrying after delay",
                        operation_id=operation_id,
                        delay_seconds=delay,
                        next_attempt=attempt + 1
                    )
                    time.sleep(delay)
                    delay = min(delay * self.config.backoff_factor, self.config.max_delay)

        return None

    def _classify_error(self, error: Exception) -> ErrorCategory:
        """
        Classify error as transient, permanent, or unknown.

        Args:
            error: The exception to classify

        Returns:
            Error category determining retry strategy
        """
        error_type = type(error).__name__
        error_msg = str(error).lower()

        # Transient errors (retry with backoff)
        if any(msg in error_msg for msg in [
            "disk full",
            "no space left",
            "temporarily unavailable",
            "resource temporarily unavailable",
            "too many open files",
            "connection reset",
            "connection refused",
            "timeout",
        ]):
            logger.trace("Classified as transient", error_type=error_type)
            return ErrorCategory.TRANSIENT

        # Permanent errors (fail fast)
        if any(msg in error_msg for msg in [
            "permission denied",
            "access denied",
            "not a directory",
            "is a directory",
            "read-only file system",
            "file name too long",
        ]) or error_type in ["PermissionError", "FileNotFoundError", "NotADirectoryError", "IsADirectoryError"]:
            logger.trace("Classified as permanent", error_type=error_type)
            return ErrorCategory.PERMANENT

        # OSError can be either - check errno if available
        if isinstance(error, OSError):
            errno = getattr(error, 'errno', None)
            if errno:
                # ENOSPC (28) - No space left on device (transient)
                if errno == 28:
                    return ErrorCategory.TRANSIENT
                # EACCES (13), EPERM (1) - Permission denied (permanent)
                if errno in (1, 13):
                    return ErrorCategory.PERMANENT
                # EMFILE (24), ENFILE (23) - Too many open files (transient)
                if errno in (23, 24):
                    return ErrorCategory.TRANSIENT

        # Unknown - conservative retry
        logger.trace("Classified as unknown", error_type=error_type)
        return ErrorCategory.UNKNOWN

    @auto_trace(logger)
    def is_recovered(self, operation_id: str, since_seconds: float = 60.0) -> bool:
        """
        Check if an operation has recovered after previous failures.

        Args:
            operation_id: Operation identifier
            since_seconds: Consider recovered if successful within this time

        Returns:
            True if operation succeeded recently, False otherwise
        """

        with self.lock:
            last_success = self.last_success.get(operation_id)
            if last_success is None:
                return False

            time_since_success = time.time() - last_success
            recovered = time_since_success < since_seconds

            return recovered

    def get_retry_count(self, operation_id: str) -> int:
        """
        Get current retry count for an operation.

        Args:
            operation_id: Operation identifier

        Returns:
            Number of retries for this operation
        """
        with self.lock:
            return self.retry_counts.get(operation_id, 0)

    @auto_trace(logger)
    def reset_retry_count(self, operation_id: str) -> None:
        """
        Reset retry count for an operation.

        Args:
            operation_id: Operation identifier
        """

        with self.lock:
            self.retry_counts[operation_id] = 0


    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Get diagnostic information about retry/recovery state.

        Returns:
            Dictionary with diagnostics
        """
        with self.lock:
            return {
                "active_operations": list(self.retry_counts.keys()),
                "retry_counts": dict(self.retry_counts),
                "config": {
                    "max_attempts": self.config.max_attempts,
                    "initial_delay": self.config.initial_delay,
                    "max_delay": self.config.max_delay,
                    "backoff_factor": self.config.backoff_factor,
                }
            }


# Global recovery manager instance
_recovery_manager: Optional[RecoveryManager] = None
_recovery_manager_lock = threading.Lock()


def get_recovery_manager(config: Optional[RetryConfig] = None) -> RecoveryManager:
    """
    Get or create the global recovery manager singleton.

    Args:
        config: Retry configuration (only used on first call)

    Returns:
        Global RecoveryManager instance
    """
    global _recovery_manager

    if _recovery_manager is None:
        with _recovery_manager_lock:
            if _recovery_manager is None:
                _recovery_manager = RecoveryManager(config)
                logger.info("Recovery manager initialized")

    return _recovery_manager
