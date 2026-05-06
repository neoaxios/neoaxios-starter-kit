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
Logbook - Production application logging.

This implementation provides:
- TRACE log level support
- ERROR as default log level (was WARNING)
- Automatic source location via CallsiteParameterAdder
- Exception objects required (not strings)
- Per-component log level filtering
- Structured exception rendering
- Unicode safety

Breaking Changes from Previous Version:
1. Default level is ERROR (was WARNING)
2. function_name parameters removed (auto-captured)
3. log_error() requires Exception objects (not strings)
4. All logs include 'level' field
"""

import logging
import logging.handlers
import os
import sys
import time
import uuid
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import structlog
    from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
except ImportError as e:
    raise ImportError(
        "structlog is required for the telemetry package. "
        "Install with: pip install structlog"
    ) from e

from neoaxios_logging.common.types import LogLevel
from neoaxios_logging.logbook.processors import (
    LogLevelFilterProcessor,
    create_callsite_processor,
    create_exception_processors,
    create_unicode_processors
)
from neoaxios_logging._fork_safety import register_reset_callback


class Logbook:
    """
    Production application logger.

    Features:
    - TRACE level for automatic function tracing
    - Per-component log level filtering
    - Automatic source location (filename, func_name, lineno)
    - Structured exception dictionaries
    - Unicode safety for international characters
    - ERROR as production default level
    - Entry/exit logging with return codes

    Breaking Changes:
    - Default level: ERROR (was WARNING)
    - function_name params removed (auto-added by CallsiteParameterAdder)
    - log_error() requires Exception objects
    - All logs have 'level' field
    """

    # Class-level configuration
    _configured = False
    _needs_fork_reinit = False
    _level_filter_processor: Optional[LogLevelFilterProcessor] = None
    _telemetry_log_path: Optional[Path] = None

    def __init__(
        self,
        name: str,
        level: Optional[LogLevel] = None,
        component_levels: Optional[Dict[str, LogLevel]] = None
    ):
        """
        Initialize enhanced structured logger.

        Args:
            name: Logger/component name
            level: Optional log level override (default: ERROR)
            component_levels: Optional per-component level config

        Example:
            # Simple logger with ERROR default
            logger = Logbook("myapp")

            # Logger with custom level
            logger = Logbook("myapp", level=LogLevel.DEBUG)

            # Logger with per-component levels
            logger = Logbook(
                "myapp",
                component_levels={
                    "myapp.executor": LogLevel.TRACE,
                    "myapp.*": LogLevel.INFO,
                    "*": LogLevel.ERROR
                }
            )
        """
        self.name = name

        # Ensure structlog is configured
        if not self._configured:
            self._ensure_configured(component_levels)

        # Get structlog logger bound to component name and logger field
        self.logger = structlog.get_logger().bind(
            component=name,
            logger=name  # For CallsiteParameterAdder and filtering
        )

        # Configure log level (default: ERROR, not WARNING)
        if level is not None:
            self.log_level = level
        else:
            log_level_str = (
                os.environ.get("NEO_TELEMETRY_LEVEL")
                or os.environ.get("LOG_LEVEL")
                or "ERROR"  # Changed from WARNING
            )
            self.log_level = LogLevel.from_string(log_level_str)

        # Metrics storage (for compatibility)
        self.metrics: Dict[str, List[float]] = {}
        self.events: List[Dict[str, Any]] = []

        # Run context support
        self._run_context = threading.local()
        self._run_context.run_id = None
        self._run_context.metadata = {}

    @classmethod
    def _ensure_configured(cls, component_levels: Optional[Dict[str, LogLevel]] = None):
        """Ensure structlog is properly configured with enhanced processors."""
        if cls._configured:
            return

        # Determine output configuration (defaults changed to enabled)
        telemetry_enabled = os.environ.get("NEO_TELEMETRY_ENABLED", "true").lower() in ("true", "1", "yes")
        console_enabled = os.environ.get("NEO_TELEMETRY_CONSOLE", "true").lower() in ("true", "1", "yes")
        log_format = os.environ.get("NEO_TELEMETRY_FORMAT", "json")

        # Create per-component level filter
        if component_levels is None:
            # Read default level from environment or use ERROR
            default_level_str = os.environ.get("NEO_TELEMETRY_LEVEL", "ERROR")
            try:
                default_level = LogLevel.from_string(default_level_str)
            except ValueError:
                default_level = LogLevel.ERROR

            component_levels = {"*": default_level}

        cls._level_filter_processor = LogLevelFilterProcessor(
            component_levels,
            default_level=LogLevel.ERROR  # Fallback when no pattern matches
        )

        # Create unicode processors
        unicode_decoder, unicode_encoder = create_unicode_processors()

        # Create exception processors
        dict_tb, exc_renderer = create_exception_processors()

        # Create callsite processor
        callsite_proc = create_callsite_processor()

        # Create custom level processor to restore TRACE/ENTER/EXIT levels after add_log_level
        def restore_custom_level(logger, method_name, event_dict):
            """Restore custom log level after add_log_level processor."""
            if "_custom_level" in event_dict:
                event_dict["level"] = event_dict.pop("_custom_level")
            return event_dict

        # Configure processor pipeline
        # Order matters: https://www.structlog.org/en/stable/processors.html
        processors = [
            # 1. Merge contextvars (run_id, etc.)
            merge_contextvars,

            # 2. Decode unicode early
            unicode_decoder,

            # 3. Add source location (filename, func_name, lineno, module)
            callsite_proc,

            # 4. Add timestamp
            structlog.processors.TimeStamper(fmt="iso"),

            # 5. Add log level name (adds Python logging level: debug, info, etc.)
            structlog.processors.add_log_level,

            # 6. Restore custom level (TRACE, ENTER, EXIT) over Python level
            restore_custom_level,

            # 7. Filter by per-component levels
            cls._level_filter_processor,

            # 8. Convert exceptions to dicts
            dict_tb,

            # 9. Encode unicode for output
            unicode_encoder,
        ]

        # Add appropriate renderer (last processor)
        if log_format == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())

        # Configure structlog
        if telemetry_enabled or console_enabled:
            # Setup file handler if telemetry enabled
            log_file_path = None
            if telemetry_enabled:
                telemetry_dir = Path(os.environ.get("TELEMETRY_DIR", ".telemetry"))
                telemetry_dir.mkdir(parents=True, exist_ok=True)

                # Include process ID in filename to avoid collisions between projects/processes
                pid = os.getpid()
                log_file = telemetry_dir / f"telemetry.{pid}.log"
                log_file_path = log_file.absolute()

                # Store log file path at class level for get_telemetry_log_path()
                cls._telemetry_log_path = log_file_path

                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=100 * 1024 * 1024,  # 100MB
                    backupCount=10,
                    encoding='utf-8'
                )
                file_handler._logbook_handler = True
                file_handler.setFormatter(logging.Formatter('%(message)s'))
                # Set handler level to NOTSET to accept TRACE logs (level 5)
                # This allows LogLevelFilterProcessor to handle all filtering
                file_handler.setLevel(logging.NOTSET)

                root_logger = logging.getLogger()
                # Only set root logger level if it hasn't been set yet (still at WARNING=30)
                # Keep it at NOTSET to pass all logs through to handlers for filtering
                if root_logger.level == logging.WARNING:
                    root_logger.setLevel(logging.NOTSET)
                root_logger.addHandler(file_handler)

            # Setup console handler if console enabled
            if console_enabled:
                console_handler = logging.StreamHandler(sys.stderr)
                console_handler._logbook_handler = True
                console_handler.setFormatter(logging.Formatter('%(message)s'))
                logging.getLogger().addHandler(console_handler)

            # Configure structlog with stdlib integration
            structlog.configure(
                processors=processors,
                wrapper_class=structlog.stdlib.BoundLogger,
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True
            )

            # Log startup notification to console (stderr) - controlled by environment and TTY status
            # Suppress if LOGBOOK_QUIET=1 or if stderr is not a TTY (piped/redirected)
            quiet_mode = os.environ.get("LOGBOOK_QUIET", "0") == "1"
            is_tty = sys.stderr.isatty()

            if console_enabled and not quiet_mode and is_tty:
                startup_msg = "✓ Logbook telemetry enabled"
                if log_file_path:
                    startup_msg += f" | Log file: {log_file_path}"
                print(startup_msg, file=sys.stderr)
        else:
            # Telemetry disabled - suppress all output
            null_handler = logging.NullHandler()
            logging.getLogger().addHandler(null_handler)
            logging.getLogger().setLevel(logging.DEBUG)

            structlog.configure(
                processors=processors,
                wrapper_class=structlog.stdlib.BoundLogger,
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True
            )

        cls._configured = True

    def trace(self, msg: str, **kwargs):
        """
        Log TRACE level message.

        TRACE is below DEBUG and should only be enabled for targeted debugging.
        Typically used with @auto_trace decorator for function entry/exit.

        Args:
            msg: Message to log
            **kwargs: Additional structured context
        """
        self._log(LogLevel.TRACE, msg, **kwargs)

    def debug(self, msg: str, **kwargs):
        """Log debug message with context."""
        self._log(LogLevel.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs):
        """Log info message with context."""
        self._log(LogLevel.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        """Log warning message with context."""
        self._log(LogLevel.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs):
        """Log error message with context."""
        self._log(LogLevel.ERROR, msg, **kwargs)

    def exception(self, msg: str, exc: Optional[Exception] = None, **kwargs):
        """
        Log exception with structured traceback.

        Args:
            msg: Error message
            exc: Exception object (optional, uses sys.exc_info() if not provided)
            **kwargs: Additional context

        Example:
            try:
                risky_operation()
            except ValueError as e:
                logger.exception("Operation failed", exc=e, operation="risky")
        """
        import sys

        if exc is not None:
            # Use provided exception
            kwargs["exc_info"] = (type(exc), exc, exc.__traceback__)
        else:
            # Use current exception from sys.exc_info()
            kwargs["exc_info"] = sys.exc_info()

        self._log(LogLevel.ERROR, msg, **kwargs)

    def trace(self, msg: str, **kwargs):
        """
        Log message at TRACE level.

        TRACE is the most verbose level, below DEBUG. Use for automatic
        function entry/exit tracing via @auto_trace decorator.

        Args:
            msg: Log message
            **kwargs: Additional structured data

        Example:
            logger.trace("Function entered", param1="value")
        """
        self._log(LogLevel.TRACE, msg, **kwargs)

    def _check_level(self, level: LogLevel) -> bool:
        """
        Check if the given log level would be logged for this component.

        This is used by decorators to avoid overhead when tracing is disabled.

        Args:
            level: LogLevel to check

        Returns:
            True if this level would be logged

        Example:
            if logger._check_level(LogLevel.TRACE):
                # Expensive trace data collection
                logger.trace("Detailed info", data=expensive_computation())
        """
        if self._level_filter_processor is None:
            # No filtering, assume all levels enabled
            return True

        # Get component level from filter
        try:
            component_level = self._level_filter_processor.get_level(self.name)
            return level >= component_level
        except Exception:
            # If check fails, be conservative and return True
            return True


    def log_error(self, error: Exception, **context):
        """
        Log function error with context.

        BREAKING CHANGE:
        1. function_name parameter removed (auto-captured)
        2. error parameter must be Exception object (not string)

        Args:
            error: Exception object (not string!)
            **context: Additional error context

        Example:
            try:
                process_payment()
            except CardDeclinedError as e:
                logger.log_error(error=e, order_id=123)  # Exception object required
        """
        if not isinstance(error, BaseException):
            raise TypeError(
                f"log_error() requires Exception object, got {type(error).__name__}."
            )

        # Add exception info for structured rendering
        context["exc_info"] = (type(error), error, error.__traceback__)

        self.error(
            f"ERROR: {error}",
            error_type=type(error).__name__,
            error_message=str(error),
            **context
        )

    # Context binding methods
    def bind_context(self, **kwargs):
        """
        Bind context variables that will be included in all subsequent log events.

        Context variables are stored in contextvars and automatically included
        in every log message until unbound or cleared.

        Args:
            **kwargs: Key-value pairs to bind to context

        Example:
            >>> logger = get_telemetry("myapp")
            >>> logger.bind_context(request_id="req-123", user_id=456)
            >>> logger.info("Processing request")  # Includes request_id and user_id
            >>> logger.info("Request complete")    # Still includes context
            >>> logger.clear_context()
        """
        from structlog.contextvars import bind_contextvars
        bind_contextvars(**kwargs)

    def unbind_context(self, *keys):
        """
        Unbind specific context variables.

        Args:
            *keys: Context keys to remove

        Example:
            >>> logger.bind_context(request_id="req-123", session_id="sess-789")
            >>> logger.unbind_context("session_id")  # Remove only session_id
            >>> logger.info("Event")  # Still includes request_id
        """
        from structlog.contextvars import unbind_contextvars
        unbind_contextvars(*keys)

    def clear_context(self):
        """
        Clear all bound context variables.

        Example:
            >>> logger.bind_context(request_id="req-123", user_id=456)
            >>> logger.info("Has context")
            >>> logger.clear_context()
            >>> logger.info("No context")
        """
        from structlog.contextvars import clear_contextvars
        clear_contextvars()

    @contextmanager
    def with_context(self, **kwargs):
        """
        Context manager for scoped context binding.

        Context is automatically cleared when exiting the context manager,
        restoring previous context state.

        Args:
            **kwargs: Context variables to bind

        Yields:
            None

        Example:
            >>> logger = get_telemetry("myapp")
            >>> with logger.with_context(request_id="req-123"):
            ...     logger.info("Processing")  # Has request_id
            ...     with logger.with_context(user_id=456):
            ...         logger.info("User action")  # Has request_id and user_id
            ...     logger.info("After nested")  # Only request_id
            >>> logger.info("Outside")  # No context

            # Nested contexts work correctly
            >>> with logger.with_context(operation="checkout"):
            ...     logger.info("Starting checkout")
            ...     try:
            ...         with logger.with_context(payment_method="card"):
            ...             process_payment()
            ...     except Exception as e:
            ...         logger.log_error(error=e)  # Has operation context
        """
        from structlog.contextvars import bound_contextvars
        with bound_contextvars(**kwargs):
            yield

    def _log(self, level: LogLevel, msg: str, **kwargs):
        """Internal logging with structured context."""
        if Logbook._needs_fork_reinit:
            try:
                Logbook._ensure_configured()
                Logbook._needs_fork_reinit = False
            except Exception:
                Logbook._needs_fork_reinit = False
        try:
            # Store custom level in a different field to avoid being overwritten by add_log_level processor
            # Will be renamed back to 'level' by a custom processor after add_log_level runs
            kwargs["_custom_level"] = str(level)

            # Add run_id if available
            if hasattr(self._run_context, "run_id") and self._run_context.run_id:
                kwargs["run_id"] = self._run_context.run_id

            # Add any run metadata
            if hasattr(self._run_context, "metadata") and self._run_context.metadata:
                kwargs.update(self._run_context.metadata)

            # Add timestamp
            kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()

            # Log using structlog
            log_method = getattr(self.logger, level.to_structlog_level())
            log_method(msg, **kwargs)

        except (ValueError, OSError):
            # Handle closed file descriptors gracefully during shutdown
            pass

    # Metrics, timers, run context - unchanged from previous version
    def record_metric(
        self, name: str, value: float, unit: str = "", tags: Optional[Dict[str, str]] = None
    ):
        """Record a metric value."""
        if name not in self.metrics:
            self.metrics[name] = []

        metric_data = {
            "value": value,
            "unit": unit,
            "timestamp": time.time(),
            "tags": tags or {}
        }
        self.metrics[name].append(metric_data)

        self._log(
            LogLevel.INFO,
            "metric",
            metric_name=name,
            metric_value=value,
            metric_unit=unit,
            **(tags or {})
        )

    def record_event(self, event_type: str, **kwargs):
        """Record a significant event."""
        event = {"type": event_type, "timestamp": time.time(), "data": kwargs}
        self.events.append(event)
        self._log(LogLevel.INFO, f"event:{event_type}", **kwargs)

    @contextmanager
    def timer(self, operation: str, **tags):
        """Context manager to time operations."""
        start_time = time.time()
        self.debug(f"Starting {operation}", **tags)

        try:
            yield
        finally:
            duration = time.time() - start_time
            self.record_metric(f"{operation}_duration", duration, unit="seconds", tags=tags)
            self.debug(f"Completed {operation}", duration_s=duration, **tags)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of recorded metrics."""
        summary = {}

        for name, values in self.metrics.items():
            if values:
                numeric_values = [v["value"] for v in values]
                summary[name] = {
                    "count": len(numeric_values),
                    "sum": sum(numeric_values),
                    "mean": sum(numeric_values) / len(numeric_values),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                    "last": numeric_values[-1],
                }

        return summary

    def export_telemetry(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Export all telemetry data."""
        import copy

        telemetry_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "logger": self.name,
            "metrics": copy.deepcopy(self.metrics),
            "events": copy.deepcopy(self.events),
            "summary": self.get_metrics_summary(),
        }

        if output_path:
            import json
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(telemetry_data, f, indent=2, default=str)

        return telemetry_data

    def start_run(self, run_id: Optional[str] = None, **metadata) -> str:
        """Mark the start of a test run."""
        if run_id is None:
            run_id = f"run-{uuid.uuid4().hex[:8]}-{int(time.time())}"

        self._run_context.run_id = run_id
        self._run_context.metadata = metadata

        # Bind to structlog context
        bind_contextvars(run_id=run_id, **metadata)

        self.record_event("run_started", run_id=run_id, **metadata)
        self.info("Test run started", run_id=run_id, **metadata)

        return run_id

    def end_run(self, status: str = "completed", **kwargs):
        """Mark the end of a test run."""
        if hasattr(self._run_context, "run_id") and self._run_context.run_id:
            run_id = self._run_context.run_id
            self.record_event("run_ended", run_id=run_id, status=status, **kwargs)
            self.info("Test run ended", run_id=run_id, status=status, **kwargs)

            # Clear run context
            self._run_context.run_id = None
            self._run_context.metadata = {}

            # Clear structlog context
            clear_contextvars()

    def get_current_run_id(self) -> Optional[str]:
        """Get the current run ID if any."""
        return getattr(self._run_context, "run_id", None)

    @contextmanager
    def run_context(self, run_id: Optional[str] = None, **metadata):
        """Context manager for test runs."""
        run_id = self.start_run(run_id, **metadata)
        try:
            yield run_id
        finally:
            self.end_run()

    @classmethod
    def set_component_level(cls, component: str, level: LogLevel):
        """
        Set log level for a component at runtime.

        Provides dynamic per-component level control.

        Args:
            component: Component pattern (exact or wildcard)
            level: Minimum log level for this component

        Example:
            # Enable TRACE for specific component
            Logbook.set_component_level("myapp.executor", LogLevel.TRACE)

            # Set wildcard level
            Logbook.set_component_level("myapp.*", LogLevel.INFO)
        """
        if cls._level_filter_processor is None:
            raise RuntimeError("Logger not configured. Create a logger instance first.")

        cls._level_filter_processor.set_level(component, level)

    @classmethod
    def get_component_level(cls, component: str) -> LogLevel:
        """
        Get current log level for a component.

        Args:
            component: Component name

        Returns:
            Current log level for component

        Example:
            >>> level = Logbook.get_component_level("myapp.processor")
            >>> print(level)
            LogLevel.INFO
        """
        if cls._level_filter_processor is None:
            return LogLevel.ERROR

        return cls._level_filter_processor.get_level(component)

    @classmethod
    def get_level_config(cls) -> Dict[str, str]:
        """
        Get current level configuration for all components.

        Returns:
            Dictionary mapping component patterns to level names

        Example:
            >>> config = Logbook.get_level_config()
            >>> print(config)
            {'*': 'ERROR', 'myapp.*': 'INFO'}
        """
        if cls._level_filter_processor is None:
            return {"*": "ERROR"}

        return cls._level_filter_processor.get_level_config()

    @classmethod
    def set_default_level(cls, level: LogLevel):
        """
        Set base log level for all components (convenience method).

        This is equivalent to set_component_level("*", level).

        Args:
            level: New base log level

        Example:
            >>> Logbook.set_default_level(LogLevel.DEBUG)
            >>> # Equivalent to:
            >>> Logbook.set_component_level("*", LogLevel.DEBUG)
        """
        cls.set_component_level("*", level)

    @classmethod
    def get_telemetry_log_path(cls) -> Optional[Path]:
        """
        Get the absolute path to the current telemetry log file.

        Returns the path to the active telemetry log file if telemetry is
        enabled and initialized. Returns None if telemetry is disabled or
        not yet initialized.

        This is useful for debugging and error reporting when users need to
        provide the log file for troubleshooting.

        Returns:
            Optional[Path]: Absolute path to telemetry log file, or None if
                           telemetry is not active

        Example:
            >>> from telemetry import get_telemetry_log_path
            >>> log_path = get_telemetry_log_path()
            >>> if log_path:
            ...     print(f"Telemetry log: {log_path}")
            ... else:
            ...     print("Telemetry logging is not enabled")

            >>> # In error handling
            >>> try:
            ...     merge_coverage_files()
            ... except Exception as e:
            ...     log_path = get_telemetry_log_path()
            ...     if log_path:
            ...         print(f"Check telemetry log for details: {log_path}")
        """
        return cls._telemetry_log_path

    @classmethod
    def _reset_for_fork_child(cls) -> None:
        cls._configured = False
        cls._needs_fork_reinit = True
        cls._level_filter_processor = None
        cls._telemetry_log_path = None

        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            if getattr(handler, "_logbook_handler", False):
                try:
                    handler.close()
                except Exception:
                    pass
                root_logger.removeHandler(handler)


register_reset_callback(Logbook._reset_for_fork_child)


def get_logger(name: str, level: Optional[LogLevel] = None) -> Logbook:
    """
    Get or create a structured logger for the given name.

    Args:
        name: Component name
        level: Optional log level override (default: ERROR)

    Returns:
        Logbook instance
    """
    return Logbook(name, level=level)


def get_telemetry(name: str, level: Optional[LogLevel] = None) -> Logbook:
    """
    Get or create a telemetry logger for the given component.

    This is an alias for get_logger() for backward compatibility.

    Args:
        name: Component name
        level: Optional log level override (default: ERROR)

    Returns:
        Logbook instance

    Example:
        >>> logbook = get_telemetry("myapp.processor")
        >>> logbook.log_entry(task_id=123)
        >>> logbook.info("Processing task")
        >>> logbook.log_exit(return_code=0)
    """
    return get_logger(name, level=level)


def get_telemetry_log_path() -> Optional[Path]:
    """
    Get the absolute path to the current telemetry log file.

    This is a convenience function that delegates to Logbook.get_telemetry_log_path().
    Importable directly from the telemetry package for easy access.

    Returns:
        Optional[Path]: Absolute path to telemetry log file, or None if telemetry
                       is not active

    Example:
        >>> from telemetry import get_telemetry_log_path
        >>> log_path = get_telemetry_log_path()
        >>> if log_path:
        ...     print(f"Telemetry log: {log_path}")
    """
    return Logbook.get_telemetry_log_path()


def with_telemetry(logger: Logbook):
    """
    Decorator for automatic function entry/exit logging.

    Note: This is a legacy decorator. Prefer @auto_trace, which provides more
    features at TRACE level.

    This decorator now uses trace() internally to provide similar behavior
    to the deprecated log_entry/log_exit methods.

    Args:
        logger: Logbook instance

    Returns:
        Decorator function

    Example:
        >>> logger = get_telemetry("myapp")
        >>> @with_telemetry(logger)
        ... def process_data(data_id):
        ...     # Function implementation
        ...     return result
    """
    import functools

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Log entry using trace
            logger.trace(f"ENTRY: {func.__name__}", **kwargs)

            try:
                result = func(*args, **kwargs)
                logger.trace(f"EXIT: {func.__name__}", return_code=0)
                return result
            except Exception as e:
                logger.log_error(error=e)
                logger.trace(f"EXIT: {func.__name__}", return_code=1)
                raise

        return wrapper

    return decorator
