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
Shared constants and enums for the telemetry package.

This module provides common types and constants used across all telemetry subsystems,
eliminating duplication and ensuring consistency.
"""

from enum import IntEnum, Enum
from typing import Union


class LogLevel(IntEnum):
    """
    Unified log criticality levels across all telemetry systems.

    These levels are used by FlightRecorder, Logbook, and all other
    telemetry components to ensure consistent filtering and analysis.

    Mapping to standard logging:
    - TRACE → Custom (5, below DEBUG)
    - ENTER/EXIT → TRACE (5-7)
    - DEBUG → DEBUG (10)
    - INFO → INFO (20)
    - WARNING → WARNING (30)
    - ERROR → ERROR (40)
    - CRITICAL → CRITICAL (50)
    """
    TRACE = 5       # Automatic function entry/exit logging
    ENTER = 6       # Function/test entry points (maps to TRACE)
    EXIT = 7        # Function/test exit points (maps to TRACE)
    DEBUG = 10      # Detailed debug information
    INFO = 20       # General informational messages
    WARNING = 30    # Warning conditions
    ERROR = 40      # Error conditions (production default)
    CRITICAL = 50   # Critical issues requiring immediate attention

    def to_structlog_level(self) -> str:
        """
        Convert LogLevel to structlog method name.

        Returns:
            String method name for structlog (e.g., 'info', 'error')
        """
        mapping = {
            LogLevel.TRACE: "debug",  # structlog doesn't have trace, use debug
            LogLevel.ENTER: "debug",
            LogLevel.EXIT: "debug",
            LogLevel.DEBUG: "debug",
            LogLevel.INFO: "info",
            LogLevel.WARNING: "warning",
            LogLevel.ERROR: "error",
            LogLevel.CRITICAL: "critical"
        }
        return mapping.get(self, "info")

    def to_python_logging_level(self) -> int:
        """
        Convert LogLevel to Python logging level.

        Returns:
            Integer level for Python logging module
        """
        import logging
        mapping = {
            LogLevel.TRACE: logging.DEBUG - 5,      # Below DEBUG
            LogLevel.ENTER: logging.DEBUG - 4,      # Slightly above TRACE
            LogLevel.EXIT: logging.DEBUG - 3,       # Slightly above ENTER
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL
        }
        return mapping.get(self, logging.INFO)

    @classmethod
    def from_string(cls, level: Union[str, bytes]) -> 'LogLevel':
        """
        Convert string or bytes to LogLevel.

        Args:
            level: Level name (case-insensitive), as string or bytes

        Returns:
            LogLevel enum value

        Raises:
            ValueError: If level string is invalid
        """
        # Handle bytes input
        if isinstance(level, bytes):
            level = level.decode('utf-8')

        try:
            return cls[level.upper()]
        except KeyError:
            raise ValueError(f"Invalid log level: {level}. Must be one of: {', '.join(cls.__members__.keys())}")

    def __str__(self) -> str:
        return self.name


class TraceDisabledReason(Enum):
    """
    Reasons for disabling @auto_trace on a function.

    When @auto_trace must be disabled for performance or other reasons,
    a reason MUST be provided to maintain auditability and documentation.
    The decorator is still present (so the call site stays consistent)
    but returns the unwrapped function at decoration time (zero overhead).

    Usage:
        @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
        def make_key(self, key_suffix: str) -> str:
            return f"{self.prefix}{key_suffix}"
    """
    HOTPATH = "hotpath"
    """Function is called in performance-critical hot path (e.g., per-request)."""

    TRIVIAL_GETTER = "trivial_getter"
    """Simple property/getter with no side effects or failure modes."""

    CALLER_TRACED = "caller_traced"
    """All callers are already traced, providing sufficient visibility."""

    HIGH_FREQUENCY = "high_frequency"
    """Function called at very high frequency where tracing overhead is prohibitive."""

    def __str__(self) -> str:
        return self.value


class EventType(Enum):
    """
    Common event types for consistent messaging across telemetry systems.

    These standardized event types ensure consistent event names in logs,
    making it easier to query and analyze telemetry data.
    """
    # Test lifecycle events
    TEST_STARTED = "Test started"
    TEST_COMPLETED = "Test completed"
    TEST_FAILED = "Test failed"
    TEST_SKIPPED = "Test skipped"

    # Process lifecycle events
    PROCESS_STARTED = "Process started"
    PROCESS_TRACKED = "Process tracking started"
    PROCESS_COMPLETED = "Process completed"
    PROCESS_FAILED = "Process failed"

    # Worker/execution events
    WORKER_STARTED = "Worker started"
    WORKER_COMPLETED = "Worker completed"
    CLEANUP_STARTED = "Starting cleanup"
    CLEANUP_COMPLETED = "Cleanup completed"

    # Error/diagnostic events
    HANGING_DETECTED = "Hanging process detected"
    TERMINATION_ATTEMPT = "Termination attempt"
    TERMINATION_RESULT = "Termination completed"
    ERROR_OCCURRED = "Error occurred"
    EXCEPTION_OCCURRED = "Exception occurred"

    def __str__(self) -> str:
        return self.value


# Default telemetry configuration constants
DEFAULT_TELEMETRY_DIR = ".telemetry"
DEFAULT_TELEMETRY_LEVEL = "WARNING"
DEFAULT_TELEMETRY_FORMAT = "json"
DEFAULT_FLIGHT_RECORDER_DIR = ".qrs/flight_recorder/sessions"
DEFAULT_RETENTION_DAYS = 30
DEFAULT_PERFORMANCE_HISTORY_SIZE = 100


# Valid log formats
VALID_LOG_FORMATS = ["json", "text"]

# Valid log levels (as strings)
VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
