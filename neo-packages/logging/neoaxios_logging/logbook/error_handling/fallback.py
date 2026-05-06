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
Fallback output handlers for graceful degradation when primary logging fails.

This module implements a fallback chain for handling logging failures:
1. Primary file output (configured path)
2. Fallback to console (stderr)
3. Fallback to /tmp directory
4. Fallback to /dev/null (silent discard)

The goal is to ensure the application never crashes due to logging failures,
while still attempting to preserve log data through alternative outputs.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Optional, IO, Dict, Any
from contextlib import contextmanager

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


class FallbackOutputHandler:
    """
    Manages fallback chain for file output failures.

    When primary file output fails, this handler:
    1. Attempts to write to console (stderr)
    2. Falls back to temporary directory (/tmp)
    3. Falls back to /dev/null as last resort

    The handler tracks which fallback is active and provides
    diagnostics for troubleshooting.
    """

    @auto_trace(logger)
    def __init__(self, primary_path: Path):
        """
        Initialize fallback handler.

        Args:
            primary_path: The primary (desired) output file path
        """
        self.primary_path = primary_path
        self.current_output: Optional[IO] = None
        self.current_mode: str = "none"
        self.fallback_path: Optional[Path] = None
        self.failure_count: int = 0
        self.last_error: Optional[Exception] = None

    @auto_trace(logger)
    @contextmanager
    def get_output(self):
        """
        Context manager that yields an output file handle.

        Implements fallback chain:
        1. Try primary path
        2. Try console (stderr)
        3. Try /tmp
        4. Use /dev/null

        Yields:
            File-like object for writing

        Example:
            with handler.get_output() as out:
                out.write(log_data)
        """

        output = None
        try:
            # Try primary path first
            output = self._try_primary()
            if output:
                self.current_mode = "primary"
                self.current_output = output
                logger.trace("Using primary output", path=str(self.primary_path))
                yield output
                return

            # Try console fallback
            output = self._try_console()
            if output:
                self.current_mode = "console"
                self.current_output = output
                logger.warning(
                    "Fell back to console output",
                    primary_path=str(self.primary_path),
                    error=str(self.last_error) if self.last_error else None
                )
                yield output
                return

            # Try temp directory fallback
            output = self._try_temp()
            if output:
                self.current_mode = "temp"
                self.current_output = output
                logger.warning(
                    "Fell back to temporary directory",
                    temp_path=str(self.fallback_path),
                    primary_path=str(self.primary_path),
                    error=str(self.last_error) if self.last_error else None
                )
                yield output
                return

            # Last resort: /dev/null
            output = self._try_devnull()
            self.current_mode = "devnull"
            self.current_output = output
            logger.error(
                "All outputs failed, using /dev/null",
                primary_path=str(self.primary_path),
                error=str(self.last_error) if self.last_error else None
            )
            yield output

        finally:
            pass

    def _try_primary(self) -> Optional[IO]:
        """
        Try to open primary output file.

        Returns:
            File handle if successful, None if failed
        """
        try:
            # Ensure parent directory exists
            self.primary_path.parent.mkdir(parents=True, exist_ok=True)

            # Open file in append mode
            return open(self.primary_path, 'a', buffering=1)  # Line buffered

        except (OSError, IOError, PermissionError) as e:
            self.last_error = e
            self.failure_count += 1
            logger.debug(
                "Primary output failed",
                path=str(self.primary_path),
                error_type=type(e).__name__,
                error=str(e)
            )
            return None

    def _try_console(self) -> Optional[IO]:
        """
        Try to use console (stderr) as fallback.

        Returns:
            stderr if available, None if failed
        """
        try:
            # Verify stderr is writable
            sys.stderr.write("")
            sys.stderr.flush()
            return sys.stderr

        except (OSError, IOError) as e:
            self.last_error = e
            self.failure_count += 1
            logger.debug(
                "Console fallback failed",
                error_type=type(e).__name__,
                error=str(e)
            )
            return None

    def _try_temp(self) -> Optional[IO]:
        """
        Try to create a temporary log file in /tmp.

        Returns:
            Temp file handle if successful, None if failed
        """
        try:
            # Generate temp file path
            temp_dir = Path(tempfile.gettempdir())
            app_name = self.primary_path.stem
            temp_filename = f"{app_name}_fallback_{os.getpid()}.log"
            self.fallback_path = temp_dir / temp_filename

            # Create temp file
            return open(self.fallback_path, 'a', buffering=1)

        except (OSError, IOError, PermissionError) as e:
            self.last_error = e
            self.failure_count += 1
            logger.debug(
                "Temp directory fallback failed",
                temp_dir=str(temp_dir),
                error_type=type(e).__name__,
                error=str(e)
            )
            return None

    def _try_devnull(self) -> IO:
        """
        Open /dev/null as last resort.

        This always succeeds (or crashes the system, which is acceptable
        at this point since even /dev/null is unavailable).

        Returns:
            /dev/null file handle
        """
        try:
            return open(os.devnull, 'a')
        except Exception as e:
            # If even /dev/null fails, we have bigger problems
            self.last_error = e
            self.failure_count += 1
            # Return a no-op file-like object
            return _NullOutput()

    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Get diagnostic information about fallback state.

        Returns:
            Dictionary with fallback diagnostics
        """
        return {
            "primary_path": str(self.primary_path),
            "current_mode": self.current_mode,
            "fallback_path": str(self.fallback_path) if self.fallback_path else None,
            "failure_count": self.failure_count,
            "last_error": str(self.last_error) if self.last_error else None,
            "last_error_type": type(self.last_error).__name__ if self.last_error else None,
        }

    @auto_trace(logger)
    def reset_to_primary(self) -> bool:
        """
        Attempt to reset to primary output after recovery.

        This is called after transient errors may have been resolved
        (e.g., disk space freed, permissions fixed).

        Returns:
            True if primary output is now available, False otherwise
        """
        output = self._try_primary()
        if output:
            # Close current fallback if different
            if self.current_output and self.current_output not in (sys.stderr, sys.stdout):
                try:
                    self.current_output.close()
                except:
                    pass

            self.current_output = output
            self.current_mode = "primary"
            self.fallback_path = None

            logger.info("Recovered to primary output", path=str(self.primary_path))
            return True

        return False


class _NullOutput:
    """
    Null output that discards all writes.

    Used as absolute last resort when even /dev/null is unavailable.
    """

    def write(self, data: Any) -> int:
        """Discard data silently."""
        return len(str(data)) if data else 0

    def flush(self) -> None:
        """No-op flush."""
        pass

    def close(self) -> None:
        """No-op close."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@auto_trace(logger)
def create_fallback_handler(primary_path: Path) -> FallbackOutputHandler:
    """
    Factory function to create a fallback handler.

    Args:
        primary_path: Primary output file path

    Returns:
        Configured FallbackOutputHandler
    """
    handler = FallbackOutputHandler(primary_path)
    return handler
