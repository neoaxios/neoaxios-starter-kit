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
Error suppression to prevent logging failures from crashing the application.

This module provides error suppression wrappers that ensure logging
operations never propagate exceptions to the application code.

Philosophy:
- Logging is observability, not core functionality
- Application should never crash due to logging failure
- Failed logs should be handled gracefully with diagnostics
- Suppression should be transparent to application code
"""

import sys
import traceback
import threading
from typing import Callable, Any, Optional, TypeVar, Dict
from functools import wraps
from contextlib import contextmanager

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)

T = TypeVar('T')


class ErrorSuppressor:
    """
    Suppresses logging errors to prevent application crashes.

    This class wraps logging operations and ensures that any exceptions
    are caught, logged (to fallback), and suppressed rather than propagated.
    """

    @auto_trace(logger)
    def __init__(self, component_name: str):
        """
        Initialize error suppressor.

        Args:
            component_name: Name of component for diagnostic reporting
        """

        self.component_name = component_name
        self.suppressed_count = 0
        self.last_error: Optional[Exception] = None
        self.last_error_traceback: Optional[str] = None
        self.lock = threading.Lock()


    def suppress(self, operation: Callable[[], T], default: Optional[T] = None) -> Optional[T]:
        """
        Execute operation with error suppression.

        Args:
            operation: Function to execute
            default: Default value to return on error

        Returns:
            Operation result on success, default on error

        Example:
            result = suppressor.suppress(
                lambda: file.write(data),
                default=0
            )
        """
        try:
            return operation()

        except Exception as e:
            self._handle_suppressed_error(e)
            return default

    @contextmanager
    def suppress_context(self):
        """
        Context manager for error suppression.

        Example:
            with suppressor.suppress_context():
                file.write(data)
                file.flush()
        """
        try:
            yield
        except Exception as e:
            self._handle_suppressed_error(e)

    def _handle_suppressed_error(self, error: Exception) -> None:
        """
        Handle a suppressed error.

        Args:
            error: The exception that was suppressed
        """
        with self.lock:
            self.suppressed_count += 1
            self.last_error = error
            self.last_error_traceback = traceback.format_exc()

        # Try to log the error (to console/stderr)
        try:
            error_info = {
                "component": self.component_name,
                "error_type": type(error).__name__,
                "error": str(error),
                "suppressed_count": self.suppressed_count,
            }

            # Log to stderr as fallback
            sys.stderr.write(
                f"[LOGGING ERROR SUPPRESSED] {self.component_name}: "
                f"{type(error).__name__}: {str(error)}\n"
            )
            sys.stderr.flush()

            # Try to log via logger (may also fail)
            try:
                logger.warning("Logging error suppressed", **error_info)
            except:
                pass  # Even logger failed, already wrote to stderr

        except:
            # Absolute last resort - can't even write to stderr
            # Just increment counter and move on
            pass

    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Get diagnostic information about suppressed errors.

        Returns:
            Dictionary with suppression diagnostics
        """
        with self.lock:
            return {
                "component": self.component_name,
                "suppressed_count": self.suppressed_count,
                "last_error": str(self.last_error) if self.last_error else None,
                "last_error_type": type(self.last_error).__name__ if self.last_error else None,
                "last_error_traceback": self.last_error_traceback,
            }

    def reset_counters(self) -> None:
        """Reset suppression counters."""
        with self.lock:
            self.suppressed_count = 0
            self.last_error = None
            self.last_error_traceback = None


def suppress_logging_errors(func: Callable[..., T]) -> Callable[..., Optional[T]]:
    """
    Decorator to suppress errors in logging operations.

    Args:
        func: Function to wrap with error suppression

    Returns:
        Wrapped function that suppresses exceptions

    Example:
        @suppress_logging_errors
        def write_log(data):
            file.write(data)
            file.flush()
    """
    suppressor = ErrorSuppressor(func.__name__)

    @wraps(func)
    def wrapper(*args, **kwargs) -> Optional[T]:
        return suppressor.suppress(lambda: func(*args, **kwargs))

    # Attach suppressor for diagnostics
    wrapper._suppressor = suppressor  # type: ignore
    return wrapper


def suppress_and_log(component: str, operation: Callable[[], T], default: Optional[T] = None) -> Optional[T]:
    """
    Execute operation with error suppression and logging.

    This is a convenience function for one-off suppressions without
    creating an ErrorSuppressor instance.

    Args:
        component: Component name for diagnostics
        operation: Function to execute
        default: Default value to return on error

    Returns:
        Operation result on success, default on error

    Example:
        result = suppress_and_log(
            "file_writer",
            lambda: write_to_file(data),
            default=False
        )
    """
    suppressor = ErrorSuppressor(component)
    return suppressor.suppress(operation, default)


@contextmanager
def suppress_logging_context(component: str):
    """
    Context manager for suppressing logging errors.

    Args:
        component: Component name for diagnostics

    Example:
        with suppress_logging_context("file_output"):
            file.write(data)
            file.flush()
            file.close()
    """
    suppressor = ErrorSuppressor(component)
    with suppressor.suppress_context():
        yield


class SafeLogger:
    """
    Wrapper around logger that suppresses all errors.

    This ensures that logging calls never crash the application,
    even if the underlying logger has issues.
    """

    def __init__(self, logger_instance):
        """
        Initialize safe logger wrapper.

        Args:
            logger_instance: Underlying logger to wrap
        """
        self._logger = logger_instance
        self._suppressor = ErrorSuppressor(f"SafeLogger[{logger_instance.component}]")

    def debug(self, *args, **kwargs) -> None:
        """Safe debug logging."""
        self._suppressor.suppress(lambda: self._logger.debug(*args, **kwargs))

    def info(self, *args, **kwargs) -> None:
        """Safe info logging."""
        self._suppressor.suppress(lambda: self._logger.info(*args, **kwargs))

    def warning(self, *args, **kwargs) -> None:
        """Safe warning logging."""
        self._suppressor.suppress(lambda: self._logger.warning(*args, **kwargs))

    def error(self, *args, **kwargs) -> None:
        """Safe error logging."""
        self._suppressor.suppress(lambda: self._logger.error(*args, **kwargs))

    def exception(self, *args, **kwargs) -> None:
        """Safe exception logging."""
        self._suppressor.suppress(lambda: self._logger.exception(*args, **kwargs))

    def trace(self, *args, **kwargs) -> None:
        """Safe trace logging."""
        self._suppressor.suppress(lambda: self._logger.trace(*args, **kwargs))


    def log_error(self, *args, **kwargs) -> None:
        """Safe error logging."""
        self._suppressor.suppress(lambda: self._logger.log_error(*args, **kwargs))

    def get_diagnostics(self) -> Dict[str, Any]:
        """Get diagnostics for this safe logger."""
        return self._suppressor.get_diagnostics()


def make_logger_safe(logger_instance):
    """
    Wrap a logger instance to make it safe (suppress all errors).

    Args:
        logger_instance: Logger to wrap

    Returns:
        SafeLogger wrapper

    Example:
        logger = get_telemetry(__name__)
        safe_logger = make_logger_safe(logger)
        safe_logger.info("This will never crash")  # Even if logging fails
    """
    return SafeLogger(logger_instance)
