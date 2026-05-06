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
Thread-local log buffer for failure-only logging.

Stores ENTRY log data in memory until function completes.
Buffer is automatically cleared on success or flushed on failure.
"""

import threading
from typing import Dict, Any, List
from dataclasses import dataclass
from ..config.defaults import MAX_BUFFER_DEPTH


class BufferDepthExceededError(Exception):
    """
    Raised when LogBuffer exceeds maximum depth.

    This typically indicates infinite recursion or unexpectedly deep call chains.
    Most call stacks are <100 levels. If you legitimately need deeper stacks,
    increase MAX_BUFFER_DEPTH in telemetry/logbook/config/defaults.py to 10000.

    Attributes:
        current_depth: Current buffer depth when limit was hit
        max_depth: Configured maximum depth (MAX_BUFFER_DEPTH)
        oldest_entry_message: Message from oldest buffered entry (for debugging)
    """

    def __init__(self, current_depth: int, max_depth: int, oldest_entry_message: str):
        self.current_depth = current_depth
        self.max_depth = max_depth
        self.oldest_entry_message = oldest_entry_message

        message = (
            f"LogBuffer depth exceeded: {current_depth} >= {max_depth}. "
            f"This likely indicates infinite recursion. "
            f"Oldest buffered call: {oldest_entry_message}. "
            f"If you legitimately need deeper stacks (rare), increase MAX_BUFFER_DEPTH "
            f"in telemetry/logbook/config/defaults.py to 10000."
        )
        super().__init__(message)


@dataclass
class LogEntry:
    """Buffered log entry awaiting outcome."""
    message: str
    log_data: Dict[str, Any]
    timestamp: float
    level: int


class LogBuffer:
    """
    Thread-local buffer for ENTRY logs in failure-only mode.

    Each thread maintains its own stack of buffered entries.
    When a function succeeds, its entry is discarded.
    When a function fails, all buffered entries in the stack are flushed.
    """

    def __init__(self):
        """Initialize thread-local storage."""
        self._local = threading.local()

    def _get_stack(self) -> List[LogEntry]:
        """Get current thread's log stack."""
        if not hasattr(self._local, 'stack'):
            self._local.stack = []
        return self._local.stack

    def push(self, message: str, log_data: Dict[str, Any], timestamp: float, level: int):
        """
        Push ENTRY log to buffer.

        Args:
            message: Log message (e.g., "ENTRY: process_order")
            log_data: Structured log data (args, kwargs, etc.)
            timestamp: Log timestamp
            level: Log level (TRACE)

        Raises:
            BufferDepthExceededError: If buffer depth exceeds MAX_BUFFER_DEPTH.
                This typically indicates infinite recursion. Increase MAX_BUFFER_DEPTH
                to 10000 in defaults.py if you legitimately need deeper stacks.

        Note:
            Fail-fast design prevents silent data loss and forces fix of infinite
            recursion bugs. Most call stacks are <100 levels.
        """
        stack = self._get_stack()

        # Enforce maximum buffer depth - fail fast on pathological recursion
        if len(stack) >= MAX_BUFFER_DEPTH:
            oldest_entry = stack[0] if stack else None
            oldest_message = oldest_entry.message if oldest_entry else "<unknown>"

            raise BufferDepthExceededError(
                current_depth=len(stack),
                max_depth=MAX_BUFFER_DEPTH,
                oldest_entry_message=oldest_message
            )

        entry = LogEntry(
            message=message,
            log_data=log_data,
            timestamp=timestamp,
            level=level
        )
        stack.append(entry)

    def pop_and_discard(self):
        """
        Discard most recent ENTRY (function succeeded).

        Called on successful function completion (rc=0).
        """
        stack = self._get_stack()
        if stack:
            stack.pop()

    def pop_and_flush(self, logger):
        """
        Flush most recent ENTRY to log (function failed).

        Called on function failure (rc=1).
        Writes the buffered ENTRY log before writing EXIT.

        Args:
            logger: Logbook instance to write buffered entry

        Returns:
            The flushed LogEntry, or None if buffer was empty
        """
        stack = self._get_stack()
        if not stack:
            return None

        entry = stack.pop()

        # Write buffered ENTRY to log
        # Use logger's trace method directly
        logger.trace(entry.message, **entry.log_data)

        return entry

    def get_depth(self) -> int:
        """
        Get current call stack depth.

        Returns:
            Number of buffered entries (nested function calls)
        """
        return len(self._get_stack())

    def clear(self):
        """Clear all buffered entries for current thread."""
        if hasattr(self._local, 'stack'):
            self._local.stack = []


# Global singleton buffer
_global_buffer = LogBuffer()


def get_log_buffer() -> LogBuffer:
    """Get the global thread-local log buffer."""
    return _global_buffer


# Export
__all__ = ['LogBuffer', 'LogEntry', 'BufferDepthExceededError', 'get_log_buffer']
