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
FlightRecorder Implementation using structlog

A test execution timeline recording system powered by structlog,
providing automatic lifecycle management, thread safety, and comprehensive
logging with criticality levels and filtering.

Features:
- Buffered writes by default (buffer_size=100, flush every 1s) for performance
- Automatic flush on critical events (errors, exceptions, test boundaries)
- Thread-safe operation with proper locking
- Configurable buffer size and flush intervals
- Runtime enable/disable of buffering
- Optional immediate writes mode (buffer_size=0) for maximum crash safety
"""

import time
import threading
import traceback
import os
import sys
import inspect
import uuid
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
from functools import wraps
from pathlib import Path

try:
    import structlog
    from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
except ImportError:
    raise ImportError("structlog is required. Install with: pip install structlog")

# Import shared types from common module
from ..common import LogLevel, EventType
from neoaxios_logging._fork_safety import register_fork_unsafe, register_reset_callback


class FlightRecorderProcessor:
    """
    Structlog processor that stores events for FlightRecorder API compatibility.
    Maintains a global list of all events for querying.

    This is a singleton processor - all class variables are shared across all uses.
    Thread safety is ensured through _lock for all mutations.
    """
    _events: List[Dict[str, Any]] = []
    _lock = threading.Lock()
    _start_times: Dict[str, float] = {}  # Track start times per test
    _active_instances: Dict[str, 'FlightRecorder'] = {}  # Track active instances by test_name
    
    def __call__(self, logger, method_name, event_dict):
        """Process and store event
        
        Note: All operations must be performed with _lock held for thread safety.
        """
        with self._lock:  # Ensures thread-safe access to all class variables
            # Store a copy of the event
            stored_event = event_dict.copy()
            
            # Add FlightRecorder-specific fields if not present
            test_name = stored_event.get('test_name', 'default')
            
            # Track start time for elapsed_ms calculation
            if test_name not in self._start_times:
                self._start_times[test_name] = time.time()
            
            # Add elapsed_ms if not present
            if 'elapsed_ms' not in stored_event:
                elapsed_ms = (time.time() - self._start_times[test_name]) * 1000
                stored_event['elapsed_ms'] = elapsed_ms
            
            # Add thread_id if not present
            if 'thread_id' not in stored_event:
                stored_event['thread_id'] = threading.current_thread().name
            
            # Add flight_recorder_level based on method_name if not present
            if 'flight_recorder_level' not in stored_event:
                stored_event['flight_recorder_level'] = self._get_level_from_method(method_name)
            
            # Handle include_traceback parameter if present
            if stored_event.get('include_traceback', False) and 'traceback' not in stored_event:
                stored_event['traceback'] = traceback.format_exc()
            
            # Preserve all FlightRecorder-specific fields
            # Keep both 'flight_recorder_level' and map it to 'level' for compatibility
            if 'flight_recorder_level' in stored_event:
                # Don't remove the original field, just add the mapped one
                if 'level' not in stored_event:
                    stored_event['level'] = stored_event['flight_recorder_level'].lower() if isinstance(stored_event['flight_recorder_level'], str) else method_name
            
            self._events.append(stored_event)
        
        return event_dict
    
    @classmethod
    def get_events(cls, test_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get stored events, optionally filtered by test name.

        Automatically flushes any active FlightRecorder instance for the requested
        test_name to ensure all buffered events are included.

        Args:
            test_name: Optional test name to filter events. If None, returns all events.

        Returns:
            List of event dictionaries, optionally filtered by test_name.
        """
        # Flush active instance for this test_name if it exists
        if test_name and test_name in cls._active_instances:
            instance = cls._active_instances[test_name]
            if instance._buffering_enabled:
                instance.flush()

        with cls._lock:
            if test_name:
                return [e for e in cls._events if e.get('test_name') == test_name]
            return cls._events.copy()
    
    @classmethod
    def clear_events(cls):
        """Clear all stored events and reset start times.
        
        This prevents memory leaks from accumulating test start times.
        """
        with cls._lock:
            cls._events.clear()
            cls._start_times.clear()

    @classmethod
    def _reset_for_fork_child(cls) -> None:
        cls._events = []
        cls._start_times = {}
        cls._active_instances = {}
        cls._lock = threading.Lock()
    
    _LEVEL_MAP: dict[str, str] = {
        'debug': 'DEBUG',
        'info': 'INFO',
        'warning': 'WARNING',
        'warn': 'WARNING',
        'error': 'ERROR',
        'critical': 'CRITICAL',
        'fatal': 'CRITICAL',
    }

    @staticmethod
    def _get_level_from_method(method_name: str) -> str:
        """Map structlog method names to LogLevel names.

        Args:
            method_name: The structlog method name (e.g., 'debug', 'info')

        Returns:
            The corresponding LogLevel name string
        """
        return FlightRecorderProcessor._LEVEL_MAP.get(method_name, LogLevel.INFO.name)


def _detect_test_name():
    """
    Auto-detect test name from test framework context.
    Supports pytest, unittest, nose, and doctest.
    """
    # Try pytest first
    try:
        import pytest
        if hasattr(pytest, 'current_test_item'):
            item = pytest.current_test_item
            if item:
                return item.nodeid
    except (ImportError, AttributeError):
        pass
    
    # Try unittest
    try:
        for frame_info in inspect.stack():
            frame_locals = frame_info.frame.f_locals
            self_obj = frame_locals.get('self')
            if self_obj and hasattr(self_obj, '__class__'):
                cls = self_obj.__class__
                if 'unittest.TestCase' in str(cls.__mro__):
                    method_name = frame_info.function
                    if method_name.startswith('test'):
                        return f"{cls.__name__}.{method_name}"
    except Exception:
        pass
    
    # Try to get from __name__ in test modules
    for frame_info in inspect.stack():
        func_name = frame_info.function
        if func_name.startswith('test_'):
            frame_globals = frame_info.frame.f_globals
            module = frame_globals.get('__name__', 'unknown')
            return f"{module}.{func_name}"
    
    return None


class _Span:
    """Named span within a FlightRecorder session.

    Provides a context manager that emits span start/end events
    and a record() method for structured key-value observations.
    Used by FlightRecorder.span() — not instantiated directly.
    """

    __slots__ = ("_recorder", "_name")

    def __init__(self, recorder: 'FlightRecorder', name: str) -> None:
        self._recorder = recorder
        self._name = name

    def __enter__(self) -> '_Span':
        self._recorder.emit(f"span:{self._name}:start", LogLevel.ENTER)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self._recorder.emit(
                f"span:{self._name}:error",
                LogLevel.ERROR,
                error=str(exc_val),
                error_type=exc_type.__name__,
            )
        self._recorder.emit(f"span:{self._name}:end", LogLevel.EXIT)

    def record(self, key: str, value: Any) -> None:
        """Record a key-value observation within this span.

        Args:
            key: Observation name (e.g., "entity_id", "status_code").
            value: Observation value.
        """
        self._recorder.emit(
            f"span:{self._name}:{key}",
            LogLevel.INFO,
            **{key: value},
        )


class FlightRecorder:
    """
    Records test execution timeline using structlog.

    Features:
    - Context manager support for automatic lifecycle management
    - Auto-detection of test names from framework context
    - Thread-safe operation with structlog's contextvars
    - Decorator support for zero-instrumentation testing
    - Filtering and analysis capabilities
    - Buffering enabled by default (buffer_size=100, flush every 1s) for performance

    Buffering Behavior:
    - By default, events are buffered (buffer_size=100) and flushed periodically (every 1s)
    - Events are also auto-flushed when:
        * Buffer reaches buffer_size limit
        * ERROR or CRITICAL level event occurs
        * Test start/completion events
        * Manual flush() is called
        * Context manager exits
    - For maximum crash safety, use buffer_size=0 for immediate writes

    Usage:
        # Context manager (automatic lifecycle) - buffered writes
        with FlightRecorder("test_name") as fr:
            fr.emit("operation_started")
            # ... test code ...
            # test_result automatically recorded on exit

        # Immediate writes mode (for crash safety)
        with FlightRecorder("test_name", buffer_size=0) as fr:
            fr.emit("critical_operation")  # Written immediately

        # Runtime buffering control
        fr = FlightRecorder("test_name")
        fr.disable_buffering()  # Switch to immediate mode
        fr.emit("critical_event")  # Written immediately
        fr.enable_buffering(buffer_size=50)  # Back to buffered mode
    """
    
    # Class-level configuration
    _configured = False
    _processor = None
    _log_file_path = None  # Path to the current session log file
    
    @classmethod
    def reset(cls):
        """Reset FlightRecorder configuration and clean up resources."""
        cls._cleanup_handlers()
        cls._configured = False
        cls._processor = None
        # Clear any existing events
        if cls._processor:
            FlightRecorderProcessor.clear_events()

    @classmethod
    def _reset_for_fork_child(cls) -> None:
        cls._cleanup_handlers()
        cls._configured = False
        cls._processor = None
        cls._log_file_path = None
    
    @classmethod
    def _needs_reconfiguration(cls, persist_to_disk: bool) -> bool:
        """
        Check if structlog needs reconfiguration for file output.

        This handles the case where Logbook (or other code) configured
        structlog with PrintLoggerFactory before FlightRecorder initialized.

        Args:
            persist_to_disk: Whether file persistence is requested

        Returns:
            True if reconfiguration is needed for file output
        """
        if not persist_to_disk:
            return False

        # Check if structlog is using console output (PrintLoggerFactory)
        try:
            config = structlog.get_config()
            logger_factory = config.get('logger_factory')

            # If using PrintLoggerFactory, we need to reconfigure for file output
            if logger_factory and 'PrintLoggerFactory' in str(type(logger_factory)):
                return True

            # Check if file handlers exist
            root_logger = logging.getLogger()
            has_file_handler = any(
                isinstance(h, (logging.FileHandler, logging.handlers.RotatingFileHandler))
                for h in root_logger.handlers
            )

            # Need reconfiguration if no file handlers exist
            return not has_file_handler

        except Exception:
            # If we can't determine, err on the side of reconfiguring
            return True

    @classmethod
    def _verify_file_logging_enabled(cls) -> bool:
        """
        Verify that file logging is actually configured and working.

        Returns:
            True if file handlers are present and configured, False otherwise.
        """
        try:
            root_logger = logging.getLogger()

            # Check if any file handlers exist
            file_handlers = [
                h for h in root_logger.handlers
                if isinstance(h, (logging.FileHandler, logging.handlers.RotatingFileHandler))
            ]

            return len(file_handlers) > 0
        except Exception:
            return False

    @classmethod
    def _ensure_configured(cls, persist_to_disk: bool = None, output_dir: Optional[Path] = None,
                          strict_mode: bool = False):
        """
        Ensure structlog is configured for FlightRecorder.

        Args:
            persist_to_disk: If True, enable file logging. If None, check env var.
            output_dir: Optional output directory for logs (passed to _setup_file_logging).
            strict_mode: If True, raise exception if file logging fails (for debugging).

        Raises:
            RuntimeError: If strict_mode=True and persist_to_disk=True but file logging fails.
        """
        # Use provided value or default
        if persist_to_disk is None:
            persist_to_disk = True

        # Check if reconfiguration is needed (handles import order issues)
        needs_reconfig = cls._needs_reconfiguration(persist_to_disk)

        if not cls._configured or needs_reconfig:
            # Clean up any existing handlers before configuring
            cls._cleanup_handlers()

            # Only create new processor if not already exists
            if not cls._processor:
                cls._processor = FlightRecorderProcessor()

            processors = [
                merge_contextvars,  # Thread-safe context
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                cls._processor,  # Our custom processor for in-memory storage
                structlog.processors.JSONRenderer()
            ]

            if persist_to_disk:
                # Setup file logging with optional custom output directory
                cls._setup_file_logging(output_dir=output_dir, strict_mode=strict_mode)

                # Use stdlib logging integration for file output
                structlog.configure(
                    processors=processors,
                    wrapper_class=structlog.stdlib.BoundLogger,
                    logger_factory=structlog.stdlib.LoggerFactory(),
                    cache_logger_on_first_use=True
                )

                # Propagate to root logger for file output
                logging.getLogger().setLevel(logging.DEBUG)

                # Validate file logging is working (strict mode)
                if strict_mode and not cls._verify_file_logging_enabled():
                    raise RuntimeError(
                        f"FlightRecorder strict_mode=True: File logging failed to initialize. "
                        f"Requested output_dir: {output_dir}. "
                        f"Check permissions and disk space."
                    )
            else:
                # Memory-only configuration with stdlib.LoggerFactory to prevent stdout pollution
                # Using stdlib.LoggerFactory instead of PrintLoggerFactory prevents asyncio debug
                # messages and other stdout noise from contaminating FlightRecorder JSONL files
                structlog.configure(
                    processors=processors,
                    wrapper_class=structlog.BoundLogger,
                    context_class=dict,
                    logger_factory=structlog.stdlib.LoggerFactory(),
                    cache_logger_on_first_use=True
                )

            cls._configured = True
    
    @classmethod
    def _cleanup_handlers(cls):
        """Remove FlightRecorder's own handlers before reconfiguration.

        IMPORTANT: Only removes handlers that belong to FlightRecorder (logging to .qrs/).
        Does NOT remove other handlers like Logbook's handler.
        """
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            # Only remove handlers that belong to FlightRecorder
            # Check if it's a RotatingFileHandler logging to a .qrs/ directory
            try:
                is_rotating = isinstance(handler, logging.handlers.RotatingFileHandler)
                if is_rotating and hasattr(handler, 'baseFilename'):
                    # Only remove if it's a FlightRecorder handler (logs to .qrs/)
                    if '.qrs' in handler.baseFilename or 'flight_recorder' in handler.baseFilename:
                        try:
                            handler.close()
                        except Exception:
                            pass  # Ignore errors during cleanup
                        root_logger.removeHandler(handler)
            except (TypeError, AttributeError):
                pass  # Skip handlers we can't inspect
    
    @classmethod
    def _setup_file_logging(cls, output_dir: Optional[Path] = None, strict_mode: bool = False):
        """Configure Python logging with file handlers for FlightRecorder persistence.

        Args:
            output_dir: Optional output directory for logs. If None, uses
                       FLIGHT_RECORDER_OUTPUT_DIR env var or default.
            strict_mode: If True, raise exceptions instead of falling back to memory-only.

        Raises:
            RuntimeError: If strict_mode=True and directory/file creation fails.
        """
        try:
            # Determine log directory
            if output_dir:
                # Use provided output directory directly (no date subdirectory)
                session_dir = Path(output_dir)
            else:
                env_dir = (
                    os.environ.get("FLIGHT_RECORDER_OUTPUT_DIR")
                    or os.environ.get("NEO_FLIGHT_RECORDER_OUTPUT_DIR")
                )
                if env_dir:
                    session_dir = Path(env_dir)
                else:
                    # Default output directory
                    default_dir = Path('.qrs') / 'flight_recorder' / 'sessions'
                    log_dir = default_dir
                    today = datetime.now().strftime("%Y-%m-%d")
                    session_dir = log_dir / today

            try:
                session_dir.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError) as e:
                error_msg = f"Could not create log directory {session_dir}: {e}"
                if strict_mode:
                    raise RuntimeError(f"FlightRecorder strict_mode=True: {error_msg}")
                else:
                    # Fall back to memory-only logging on error
                    return
            
            # Create session-specific log file
            timestamp = datetime.now().strftime("%H%M%S")
            pid = os.getpid()
            log_file = session_dir / f"session_{timestamp}_{pid}.jsonl"

            # Store the log file path for access by instances
            cls._log_file_path = log_file

            # Default configuration
            max_bytes = 100 * 1024 * 1024  # 100MB
            backup_count = 10
            
            # Configure rotating file handler
            try:
                file_handler = logging.handlers.RotatingFileHandler(
                    str(log_file),
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
                
                # Set formatter to output only the message (which is JSON from structlog)
                file_handler.setFormatter(logging.Formatter('%(message)s'))
                # Set handler level to DEBUG - FlightRecorder doesn't need TRACE logs
                file_handler.setLevel(logging.DEBUG)

                # Configure root logger for structlog to use
                root_logger = logging.getLogger()
                # Only set root logger level if it hasn't been set yet (still at WARNING=30)
                # Keep it at NOTSET to pass all logs through to handlers for filtering
                if root_logger.level == logging.WARNING:
                    root_logger.setLevel(logging.NOTSET)
                root_logger.addHandler(file_handler)

                # Log startup notification to console (stderr) - controlled by environment and TTY status
                # Suppress if FLIGHT_RECORDER_QUIET=1 or if stderr is not a TTY (piped/redirected)
                quiet_mode = os.environ.get("FLIGHT_RECORDER_QUIET", "0") == "1"
                is_tty = sys.stderr.isatty()

                if not quiet_mode and is_tty:
                    startup_msg = "✓ FlightRecorder telemetry enabled | Log file: " + str(log_file)
                    print(startup_msg, file=sys.stderr)

            except (OSError, PermissionError, IOError) as e:
                error_msg = f"Could not create log file {log_file}: {e}"
                if strict_mode:
                    # Clean up any partial handlers before raising
                    cls._cleanup_handlers()
                    raise RuntimeError(f"FlightRecorder strict_mode=True: {error_msg}")
                else:
                    # Clean up any partial handlers and fall back to memory-only logging
                    cls._cleanup_handlers()
                    return
                
        except Exception as e:
            error_msg = f"Unexpected error setting up file logging: {e}"
            if strict_mode:
                # Clean up any partial handlers before raising
                cls._cleanup_handlers()
                raise RuntimeError(f"FlightRecorder strict_mode=True: {error_msg}")
            else:
                # Clean up any partial handlers and fall back to memory-only logging
                cls._cleanup_handlers()
                return
    
    def __init__(self, test_name: Optional[str] = None, default_level: LogLevel = LogLevel.INFO,
                 buffer_size: int = 100, flush_interval_seconds: float = 1.0,
                 output_dir: Optional[Path] = None,
                 persist_to_disk: bool = True,
                 strict_mode: bool = False):
        """
        Initialize FlightRecorder with optional test name and buffering.

        Args:
            test_name: Optional name for the test. If None, tries auto-detection.
            default_level: Default log level for emit calls (default: INFO).
            buffer_size: Size of the buffer for batching writes (default: 100).
                        When 0, writes happen immediately (no data loss on crash).
                        When > 0, events are buffered up to this count before auto-flush.
            flush_interval_seconds: Interval for periodic flushing in seconds (default: 1.0).
                                  Only used when buffer_size > 0. Creates a background timer thread.
                                  Set to 0 to disable periodic flushing.
            output_dir: Directory for flight recorder logs. If None, uses
                       FLIGHT_RECORDER_OUTPUT_DIR env var or default (.qrs/flight_recorder/sessions).
            persist_to_disk: Whether to persist events to disk (default: True).
                           When False, events are only stored in memory.
            strict_mode: When True, raise exceptions if file logging fails instead of
                        silently falling back to memory-only mode (default: False).
                        Useful for debugging persistence issues.

        Raises:
            ValueError: If buffer_size is negative or flush_interval_seconds is negative.
            RuntimeError: If strict_mode=True and persist_to_disk=True but file logging fails.

        Examples:
            # Buffered writes (default for performance)
            fr = FlightRecorder("my_test")

            # Immediate writes (for maximum crash safety)
            fr = FlightRecorder("my_test", buffer_size=0)

            # Custom buffer size and flush interval
            fr = FlightRecorder("my_test", buffer_size=200, flush_interval_seconds=2.0)

            # Custom output directory (useful for CI report aggregation)
            fr = FlightRecorder("my_test", output_dir=Path(".test-reports/run-123/host/flight_recorder"))

            # Strict mode for debugging (fail fast on persistence errors)
            fr = FlightRecorder("my_test", persist_to_disk=True, strict_mode=True)
        """
        # Validate parameters
        if buffer_size < 0:
            raise ValueError(f"buffer_size must be non-negative, got {buffer_size}")
        if flush_interval_seconds < 0:
            raise ValueError(f"flush_interval_seconds must be non-negative, got {flush_interval_seconds}")

        self.output_dir = output_dir
        self.persist_to_disk = persist_to_disk
        self.strict_mode = strict_mode
        self._ensure_configured(persist_to_disk=persist_to_disk, output_dir=output_dir, strict_mode=strict_mode)

        # Store the actual log file path (set during _setup_file_logging)
        self.log_file = self.__class__._log_file_path
        
        # Determine test name
        if test_name is None:
            test_name = _detect_test_name() or 'unknown_test'
        
        self.test_name = test_name
        self.test_id = str(uuid.uuid4())
        self.default_level = default_level
        self.start_time = time.time()
        self._context_depth = 0

        # Buffering configuration (enabled by default for performance)
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval_seconds
        self._buffer: List[tuple] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        self._flush_timer = None
        self._buffering_enabled = buffer_size > 0
        self._fork_needs_reinit = False
        
        # Start flush timer if buffering is enabled
        if self._buffering_enabled and flush_interval_seconds > 0:
            self._start_flush_timer()
        
        # Create bound logger with test context
        self.logger = structlog.get_logger().bind(
            test_name=self.test_name,
            test_id=self.test_id,
            start_time=self.start_time
        )

        # Register this instance for auto-flush in get_events()
        FlightRecorderProcessor._active_instances[self.test_name] = self

        register_fork_unsafe(self)

    def _reset_after_fork(self) -> None:
        self._fork_needs_reinit = True

        if self._flush_timer:
            try:
                self._flush_timer.cancel()
            except Exception:
                pass
            self._flush_timer = None

        self._buffer.clear()
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()

    def _ensure_fork_reinit(self) -> None:
        if not self._fork_needs_reinit:
            return

        self._fork_needs_reinit = False
        self._ensure_configured(
            persist_to_disk=self.persist_to_disk,
            output_dir=self.output_dir,
            strict_mode=self.strict_mode
        )

        self.log_file = self.__class__._log_file_path
        self.start_time = time.time()
        self.test_id = str(uuid.uuid4())
        self._context_depth = 0

        self._buffer = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()
        if self._buffering_enabled and self._flush_interval > 0:
            self._start_flush_timer()

        self.logger = structlog.get_logger().bind(
            test_name=self.test_name,
            test_id=self.test_id,
            start_time=self.start_time
        )

        FlightRecorderProcessor._active_instances[self.test_name] = self
    
    def __enter__(self):
        """Enter context manager."""
        self._ensure_fork_reinit()
        self._context_depth += 1
        if self._context_depth == 1:
            self.emit(EventType.TEST_STARTED.value, LogLevel.ENTER)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self._ensure_fork_reinit()
        self._context_depth -= 1
        if self._context_depth == 0:
            success = exc_type is None
            error_msg = str(exc_val) if exc_val else None
            
            if exc_type:
                self.emit("Exception occurred", LogLevel.ERROR, 
                         error=error_msg, 
                         exception_type=exc_type.__name__ if exc_type else None,
                         include_traceback=True)
            
            self.emit(EventType.TEST_COMPLETED.value, LogLevel.EXIT,
                     success=success, error=error_msg)
            
            # Always flush buffer on context exit to prevent data loss
            if self._buffering_enabled:
                self.flush()

            # Cancel flush timer
            if self._flush_timer:
                self._flush_timer.cancel()
                self._flush_timer = None

            # Unregister this instance
            if self.test_name in FlightRecorderProcessor._active_instances:
                del FlightRecorderProcessor._active_instances[self.test_name]
    
    def emit(self, *args: Any, level: Optional[LogLevel] = None, include_traceback: bool = False, **kwargs: Any) -> None:
        """
        Emit a log event with precise timing and criticality level.

        Supports variable arguments for flexible logging:
        - Single argument: emit("message") or emit("message", LogLevel.DEBUG)
        - Multiple arguments: emit("User:", user_id, "Score:", score, LogLevel.INFO)
        - With kwargs: emit("Test result", status="passed", score=100, LogLevel.DEBUG)

        By default, events are buffered and auto-flushed when:
        - Buffer reaches capacity (buffer_size, default 100)
        - ERROR or CRITICAL level event occurs
        - Test boundary events (TEST_STARTED, TEST_COMPLETED)
        - Message contains 'error' or 'exception' (case-insensitive)
        - Periodic flush interval (default 1s)

        With buffer_size=0, events are written immediately.
        
        Args:
            *args: Variable arguments. Can be:
                   - (message,): Just a message string
                   - (message, level): Message and LogLevel
                   - (val1, val2, ...): Multiple values to log (concatenated)
                   - (val1, val2, ..., level): Multiple values and LogLevel
            level: Log criticality level (defaults to self.default_level)
            include_traceback: Whether to include stack trace in the event
            **kwargs: Additional metadata to include in the event
        
        Examples:
            fr.emit("Test started")
            fr.emit("Test started", LogLevel.DEBUG)
            fr.emit("User ID:", user_id, "Status:", status)
            fr.emit("Verified: score equals", score, LogLevel.INFO)
            fr.emit("Error occurred", LogLevel.ERROR, error_code=500)
        
        Note:
            Events at ERROR level or higher always trigger an immediate flush
            when buffering is enabled, ensuring critical information is not lost.
        """
        self._ensure_fork_reinit()
        # Parse arguments to extract message and optional level
        message = ""
        parsed_level = level  # Keyword argument takes precedence
        
        if args:
            # Check if last arg is a LogLevel (only if no level kwarg was provided)
            if level is None and len(args) > 1 and isinstance(args[-1], LogLevel):
                # Last argument is the level
                parsed_level = args[-1]
                message_args = args[:-1]
            else:
                message_args = args
            
            # Build message from remaining args
            if len(message_args) == 1:
                message = str(message_args[0])
            else:
                # Join multiple arguments with space, converting each to string
                message = " ".join(str(arg) for arg in message_args)
        
        # Use parsed level or fallback to default
        if parsed_level is None:
            parsed_level = self.default_level
        
        # Calculate elapsed time
        elapsed_ms = (time.time() - self.start_time) * 1000
        
        # Add metadata
        log_kwargs = {
            'elapsed_ms': elapsed_ms,
            'flight_recorder_level': parsed_level.name,
            'thread_id': threading.current_thread().name,
            **kwargs
        }
        
        # Add traceback if requested
        if include_traceback:
            log_kwargs['traceback'] = traceback.format_exc()
        
        # Handle buffering vs immediate write
        if self._buffering_enabled:
            with self._buffer_lock:
                self._buffer.append((message, log_kwargs, parsed_level))
                
                # Auto-flush on critical events to minimize data loss
                should_flush = (
                    len(self._buffer) >= self._buffer_size or  # Buffer full
                    parsed_level >= LogLevel.ERROR or  # Error or critical event
                    message in [EventType.TEST_COMPLETED.value, EventType.TEST_STARTED.value] or  # Test boundaries
                    'exception' in message.lower() or  # Exception occurred
                    'error' in message.lower()  # Error condition
                )
                
                if should_flush:
                    self._flush_buffer_locked()
        else:
            # Immediate write (default behavior - no data loss)
            log_method = getattr(self.logger, parsed_level.to_structlog_level())
            log_method(message, **log_kwargs)
    
    def _flush_buffer_locked(self) -> None:
        """
        Flush buffered events to structlog. Must be called with _buffer_lock held.
        Internal method - use flush() for external calls.
        """
        if not self._buffer:
            return
        
        # Write all buffered events
        for message, log_kwargs, level in self._buffer:
            log_method = getattr(self.logger, level.to_structlog_level())
            log_method(message, **log_kwargs)
        
        self._buffer.clear()
        self._last_flush = time.time()
    
    def _start_flush_timer(self) -> None:
        """Start periodic flush timer for buffered writes."""
        def flush_periodically():
            try:
                self.flush()
            except Exception:
                # Silently ignore flush errors to prevent timer thread crash
                # The timer will continue to run and retry on next interval
                pass
            finally:
                # Reschedule if still buffering
                if self._buffering_enabled and self._flush_interval > 0:
                    try:
                        self._flush_timer = threading.Timer(self._flush_interval, flush_periodically)
                        self._flush_timer.daemon = True
                        self._flush_timer.start()
                    except Exception:
                        # If we can't reschedule, stop trying
                        self._flush_timer = None
        
        self._flush_timer = threading.Timer(self._flush_interval, flush_periodically)
        self._flush_timer.daemon = True
        self._flush_timer.start()
    
    def flush(self) -> None:
        """
        Manually flush the buffer. Safe to call even when buffering is disabled.
        Use this before critical operations or when you need to ensure all logs are written.
        """
        self._ensure_fork_reinit()
        if self._buffering_enabled:
            with self._buffer_lock:
                self._flush_buffer_locked()

    # Process tracking methods (integrated from telemetry_process.py)

    def emit_process_start(self, pid: int, cmd: List[str], test_file: Optional[str] = None,
                          track_resources: bool = False, **kwargs):
        """
        Track process start with optional resource monitoring.

        Args:
            pid: Process ID
            cmd: Command line arguments
            test_file: Optional test file being executed
            track_resources: Enable psutil resource tracking (requires psutil)
            **kwargs: Additional metadata

        Example:
            fr.emit_process_start(1234, ["pytest", "test.py"], test_file="test.py")
        """
        event_data = {
            "pid": pid,
            "cmd": " ".join(cmd[:3]) + "..." if len(cmd) > 3 else " ".join(cmd),
            "cmd_full": cmd,
            "test_file": test_file,
            "parent_pid": os.getpid(),
            "thread": threading.current_thread().name,
            **kwargs
        }

        if track_resources:
            try:
                import psutil
                proc = psutil.Process(pid)
                event_data.update({
                    "cpu_count": psutil.cpu_count(),
                    "memory_available": psutil.virtual_memory().available,
                    "open_files": len(proc.open_files()),
                    "num_threads": proc.num_threads(),
                    "process_status": proc.status(),
                })
            except ImportError:
                event_data["resource_tracking_error"] = "psutil not available"
            except (Exception,) as e:
                event_data["resource_tracking_error"] = str(e)

        self.emit(EventType.PROCESS_STARTED.value, level=LogLevel.INFO, **event_data)

    def emit_process_end(self, pid: int, exit_code: Optional[int] = None,
                        signal_num: Optional[int] = None, error: Optional[str] = None,
                        track_resources: bool = False, **kwargs):
        """
        Track process end with exit code and optional resource usage.

        Args:
            pid: Process ID
            exit_code: Exit code (0 = success)
            signal_num: Signal number if process was killed
            error: Error message if any
            track_resources: Enable psutil resource tracking (requires psutil)
            **kwargs: Additional metadata

        Example:
            fr.emit_process_end(1234, exit_code=0)
        """
        event_data = {
            "pid": pid,
            "exit_code": exit_code,
            "signal": signal_num,
            "error": error,
            **kwargs
        }

        # Determine log level based on exit code
        if error or (exit_code is not None and exit_code != 0):
            level = LogLevel.WARNING
        else:
            level = LogLevel.INFO

        if track_resources:
            try:
                import psutil
                proc = psutil.Process(pid)
                cpu_info = proc.cpu_times()
                memory_info = proc.memory_info()
                event_data.update({
                    "cpu_user_time": cpu_info.user,
                    "cpu_system_time": cpu_info.system,
                    "memory_rss": memory_info.rss,
                    "memory_vms": memory_info.vms,
                })
            except ImportError:
                event_data["resource_tracking_error"] = "psutil not available"
            except (Exception,):
                # Process may have already terminated
                pass

        self.emit(EventType.PROCESS_COMPLETED.value if not error else EventType.PROCESS_FAILED.value,
                 level=level, **event_data)

    def emit_signal_sent(self, pid: int, sig: int, **kwargs):
        """
        Track signal sent to process.

        Args:
            pid: Process ID
            sig: Signal number
            **kwargs: Additional metadata

        Example:
            fr.emit_signal_sent(1234, signal.SIGTERM)
        """
        import signal as signal_module
        try:
            signal_name = signal_module.Signals(sig).name
        except (ValueError, AttributeError):
            signal_name = f"SIG{sig}"

        self.emit("Signal sent to process",
                 level=LogLevel.INFO,
                 pid=pid,
                 signal=signal_name,
                 signal_num=sig,
                 sender_pid=os.getpid(),
                 sender_thread=threading.current_thread().name,
                 **kwargs)

    def emit_timeout(self, pid: int, timeout: float, test_file: Optional[str] = None, **kwargs):
        """
        Track process timeout.

        Args:
            pid: Process ID that timed out
            timeout: Timeout value in seconds
            test_file: Optional test file
            **kwargs: Additional metadata

        Example:
            fr.emit_timeout(1234, timeout=30.0, test_file="test.py")
        """
        self.emit("Process timeout",
                 level=LogLevel.WARNING,
                 pid=pid,
                 timeout_s=timeout,
                 test_file=test_file,
                 **kwargs)

    def emit_cleanup_attempt(self, method: str, pids: List[int], success: bool, **kwargs):
        """
        Track cleanup attempt for processes.

        Args:
            method: Cleanup method used (e.g., "SIGTERM", "SIGKILL")
            pids: List of process IDs
            success: Whether cleanup succeeded
            **kwargs: Additional metadata

        Example:
            fr.emit_cleanup_attempt("SIGTERM", [1234, 1235], success=True)
        """
        self.emit(EventType.CLEANUP_STARTED.value if not success else EventType.CLEANUP_COMPLETED.value,
                 level=LogLevel.INFO if success else LogLevel.WARNING,
                 method=method,
                 pids=pids,
                 num_pids=len(pids),
                 success=success,
                 **kwargs)

    def get_timeline(self) -> List[Dict[str, Any]]:
        """
        Get flight data timeline for this test.
        
        Returns:
            List of checkpoint dictionaries
        """
        # Flush any pending events before getting timeline
        if self._buffering_enabled:
            self.flush()
        
        events = FlightRecorderProcessor.get_events(self.test_name)
        return [
            {
                "checkpoint": event.get("event", ""),
                "elapsed_ms": event.get("elapsed_ms", 0),
                "thread": event.get("thread_id", ""),
                "level": event.get("flight_recorder_level", "INFO"),
                "timestamp": event.get("timestamp", "")
            }
            for event in events
        ]

    def get_events(self) -> List[Dict[str, Any]]:
        """
        Get all events for this test.

        This method provides access to the raw event data stored by the FlightRecorderProcessor.
        Unlike get_timeline(), this returns the complete event dictionaries without transformation.

        Returns:
            List of event dictionaries for this test
        """
        # Flush any pending events before getting events
        if self._buffering_enabled:
            self.flush()

        return FlightRecorderProcessor.get_events(self.test_name)

    def span(self, name: str) -> '_Span':
        """Create a named span context manager for structured test telemetry.

        Provides a lightweight way to wrap test sections with entry/exit
        events and record key-value observations within the span.

        Args:
            name: Span name (typically the test function name).

        Returns:
            A context manager that emits span start/end events and
            supports record(key, value) for structured observations.

        Usage:
            with flight_recorder.span("test_my_feature") as span:
                span.record("entity_id", entity.entity_id)
                # ... test code ...
                span.record("status_code", response.status_code)
        """
        return _Span(self, name)

    # Class methods for global operations
    @classmethod
    def get_checkpoints(cls, min_level: LogLevel = LogLevel.DEBUG,
                        test_names: Optional[Set[str]] = None,
                        since_timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Get filtered checkpoints based on criteria.
        
        Args:
            min_level: Minimum log level to include
            test_names: Set of test names to filter by
            since_timestamp: Only return checkpoints after this timestamp
        
        Returns:
            Filtered list of checkpoint entries
        """
        cls._ensure_configured()
        events = FlightRecorderProcessor.get_events()
        
        filtered = []
        for event in events:
            # Check level
            event_level = event.get('flight_recorder_level', 'INFO')
            if LogLevel[event_level] < min_level:
                continue
            
            # Check test name
            if test_names and event.get('test_name') not in test_names:
                continue
            
            # Check timestamp
            if since_timestamp:
                event_time = event.get('timestamp', 0)
                if isinstance(event_time, str):
                    # Parse ISO timestamp if needed
                    import datetime
                    event_time = datetime.datetime.fromisoformat(event_time).timestamp()
                if event_time < since_timestamp:
                    continue
            
            filtered.append(event)
        
        return filtered
    
    @classmethod
    def get_errors_and_warnings(cls) -> List[Dict[str, Any]]:
        """Get all error and warning checkpoints"""
        return cls.get_checkpoints(min_level=LogLevel.WARNING)
    
    @classmethod
    def clear_checkpoints(cls):
        """Clear all stored checkpoints"""
        cls._ensure_configured()
        FlightRecorderProcessor.clear_events()
    
    def enable_buffering(self, buffer_size: int = 100, flush_interval_seconds: float = 1.0):
        """
        Enable buffering at runtime. Useful for performance-critical sections.
        
        This method allows switching from immediate writes to buffered writes
        dynamically during test execution. Any previously buffered events
        remain intact.
        
        Args:
            buffer_size: Size of the buffer for batching writes (must be > 0)
            flush_interval_seconds: Interval for periodic flushing in seconds.
                                  If > 0, starts a background timer thread.
        
        Raises:
            ValueError: If buffer_size <= 0 or flush_interval_seconds < 0
        
        Example:
            fr = FlightRecorder("test")
            fr.emit("immediate")  # Written immediately
            fr.enable_buffering(buffer_size=50)
            fr.emit("buffered")  # Buffered
            fr.flush()  # Manual flush
        """
        self._ensure_fork_reinit()
        if buffer_size <= 0:
            raise ValueError(f"buffer_size must be positive when enabling buffering, got {buffer_size}")
        if flush_interval_seconds < 0:
            raise ValueError(f"flush_interval_seconds must be non-negative, got {flush_interval_seconds}")
        with self._buffer_lock:
            self._buffer_size = buffer_size
            self._flush_interval = flush_interval_seconds
            self._buffering_enabled = buffer_size > 0
            
            # Start timer if needed
            if self._buffering_enabled and flush_interval_seconds > 0 and not self._flush_timer:
                self._start_flush_timer()
    
    def disable_buffering(self):
        """
        Disable buffering and flush any pending events.
        
        Returns to immediate write mode for critical sections. This ensures
        all buffered events are written before switching back to immediate mode.
        Safe to call even if buffering is already disabled.
        
        Note:
            - Flushes any pending events before disabling
            - Cancels any active flush timer
            - Thread-safe operation
        
        Example:
            fr.enable_buffering(buffer_size=100)
            fr.emit("buffered1")
            fr.emit("buffered2")
            fr.disable_buffering()  # Both events flushed here
            fr.emit("immediate")  # Written immediately
        """
        self._ensure_fork_reinit()
        with self._buffer_lock:
            # Flush any pending events
            if self._buffer:
                self._flush_buffer_locked()
            
            self._buffering_enabled = False
            
            # Cancel timer
            if self._flush_timer:
                self._flush_timer.cancel()
                self._flush_timer = None
    
    @classmethod
    def export_checkpoints(cls, filepath: Path, min_level: LogLevel = LogLevel.DEBUG,
                          format: str = "json") -> None:
        """
        Export filtered checkpoints to file.
        
        Args:
            filepath: Path to export file
            min_level: Minimum log level to export
            format: Export format ('json' or 'csv')
        """
        checkpoints = cls.get_checkpoints(min_level=min_level)
        
        if format == "json":
            import json
            with open(filepath, 'w') as f:
                json.dump(checkpoints, f, indent=2, default=str)
        elif format == "csv":
            import csv
            if checkpoints:
                # Collect all unique field names from all checkpoints for robustness
                all_fields = set()
                for checkpoint in checkpoints:
                    all_fields.update(checkpoint.keys())
                fieldnames = sorted(all_fields)  # Sort for consistent column order

                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(checkpoints)


def flight_recorded(test_name: Optional[str] = None, buffer_size: int = 100, flush_interval: float = 1.0):
    """
    Decorator that automatically adds FlightRecorder to a test function.

    This decorator wraps tests with FlightRecorder lifecycle management,
    automatically recording test start/completion events.

    Usage:
        @flight_recorded
        def test_something():
            # FlightRecorder lifecycle handled automatically (buffered)
            pass

        @flight_recorded("custom_name")
        def test_something():
            pass

        @flight_recorded(buffer_size=0)
        def test_critical():
            # Immediate writes for critical tests
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine test name - use function name if not specified, otherwise auto-detect
            name = test_name if isinstance(test_name, str) else func.__name__
            
            # Create FlightRecorder with optional buffering
            with FlightRecorder(name, buffer_size=buffer_size, flush_interval_seconds=flush_interval) as fr:
                # Check if this is a pytest test with request fixture
                # Request can be in kwargs or args
                request_obj = None
                if 'request' in kwargs:
                    request_obj = kwargs['request']
                else:
                    # Check args for pytest request fixture
                    for arg in args:
                        # More robust check for pytest FixtureRequest
                        if hasattr(arg, '__class__'):
                            arg_type = str(type(arg))
                            # Check for pytest FixtureRequest class
                            if ('_pytest.fixtures.FixtureRequest' in arg_type or 
                                'FixtureRequest' in arg_type or
                                (hasattr(arg, 'fixturenames') and hasattr(arg, 'function'))):
                                request_obj = arg
                                break
                
                if request_obj is not None:
                    # Attach FlightRecorder to request for access
                    request_obj.flight_recorder = fr
                
                # For unittest, attach to self
                if args and hasattr(args[0], '__class__'):
                    if 'unittest.TestCase' in str(args[0].__class__.__mro__):
                        args[0]._flight_recorder = fr
                
                # Execute test
                return func(*args, **kwargs)
        
        # Attach FlightRecorder for direct access
        wrapper._flight_recorder = None
        return wrapper
    
    # Handle both @flight_recorded and @flight_recorded()
    if callable(test_name):
        func = test_name
        test_name = None
        return decorator(func)
    
    return decorator


# Global configuration function
def configure_flight_recorder(auto_detect_name: bool = True,
                             default_level: LogLevel = LogLevel.INFO,
                             output_file: Optional[str] = None):
    """
    Configure global FlightRecorder settings.
    
    Args:
        auto_detect_name: Whether to auto-detect test names
        default_level: Default logging level
        output_file: Optional file to write logs to
    """
    # Store configuration for later use
    os.environ['FLIGHT_RECORDER_AUTO_DETECT'] = str(auto_detect_name)
    os.environ['FLIGHT_RECORDER_DEFAULT_LEVEL'] = default_level.name
    
    if output_file:
        # Reconfigure structlog with file output
        FlightRecorder._configured = False
        FlightRecorder._ensure_configured()


def _reset_flight_recorder_for_fork_child() -> None:
    log_path = FlightRecorder._log_file_path
    if log_path:
        if not os.environ.get("FLIGHT_RECORDER_OUTPUT_DIR") and not os.environ.get("NEO_FLIGHT_RECORDER_OUTPUT_DIR"):
            os.environ["FLIGHT_RECORDER_OUTPUT_DIR"] = str(Path(log_path).parent)

    FlightRecorder._reset_for_fork_child()
    FlightRecorderProcessor._reset_for_fork_child()


register_reset_callback(_reset_flight_recorder_for_fork_child)
