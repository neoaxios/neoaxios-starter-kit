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
File output handler with buffering, rotation, and flush policies.

This module provides a sophisticated file output handler for Logbook
with support for:
- Configurable buffering strategies
- Size and time-based rotation
- Flexible flush policies
- Compression of rotated files
"""

import os
import gzip
import bz2
import lzma
import threading
import signal
from pathlib import Path
from typing import Optional, Dict, Any, IO
from datetime import datetime, timedelta

from neoaxios_logging.logbook.config import (
    OutputConfig,
    BufferMode,
    RotationType,
)
from neoaxios_logging._fork_safety import register_fork_unsafe


class FileOutput:
    """
    File output handler with advanced buffering, rotation, and flush policies.

    Features:
    - Multiple buffering strategies (write-through to unbounded)
    - Size-based and time-based rotation
    - Automatic compression of rotated files
    - Flexible flush policies (error, warning, interval, signal)
    - Thread-safe operations
    """

    def __init__(self, config: OutputConfig):
        """
        Initialize file output handler.

        Args:
            config: OutputConfig with file path, buffering, rotation settings
        """
        self.config = config
        self.path = Path(config.path) if config.path else None

        if self.path is None:
            raise ValueError("File output requires a path")

        # Ensure directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # File handle and buffer
        self._file: Optional[IO] = None
        self._buffer: list = []
        self._buffer_size_bytes = 0
        self._lock = threading.RLock()

        # Rotation tracking
        self._current_size = 0
        self._rotation_time = None
        self._init_rotation_time()

        # Flush timer
        self._flush_timer: Optional[threading.Timer] = None
        self._shutdown = False
        self._fork_needs_reinit = False

        # Signal handler for flush
        if config.flush_policy.on_signal:
            self._setup_signal_handler()

        # Open file
        self._open_file()

        # Start flush timer if needed
        if config.flush_policy.on_interval > 0:
            self._start_flush_timer()

        register_fork_unsafe(self)

    def _reset_after_fork(self) -> None:
        self._fork_needs_reinit = True
        self._lock = threading.RLock()

        if self._flush_timer:
            try:
                self._flush_timer.cancel()
            except Exception:
                pass
            self._flush_timer = None

        self._buffer.clear()
        self._buffer_size_bytes = 0
        self._current_size = 0
        self._rotation_time = None

        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def _reinitialize_after_fork(self) -> None:
        if not self._fork_needs_reinit:
            return
        self._fork_needs_reinit = False
        self._init_rotation_time()
        self._open_file()
        if self.config.flush_policy.on_interval > 0:
            self._start_flush_timer()

    def _open_file(self):
        """Open the log file with configured buffering."""
        buffer_size = self._get_buffer_size()

        # Set file permissions on creation
        if not self.path.exists():
            self.path.touch(mode=self.config.permissions)

        # Open file with buffering
        self._file = open(
            self.path,
            mode='a',
            encoding='utf-8',
            buffering=buffer_size
        )

        # Track current file size
        try:
            self._current_size = self.path.stat().st_size
        except OSError:
            self._current_size = 0

    def _get_buffer_size(self) -> int:
        """
        Get buffer size in bytes based on BufferMode.

        Returns:
            Buffer size in bytes (1 for line buffered, -1 for system default)
        """
        if self.config.buffer_size is not None:
            return self.config.buffer_size

        mode_sizes = {
            BufferMode.WRITE_THROUGH: 1,           # Line buffered (cannot use 0 for text mode)
            BufferMode.LINE_BUFFERED: 1,           # Line buffered
            BufferMode.SMALL: 4096,                # 4KB
            BufferMode.DEFAULT: -1,                # System default (~8KB)
            BufferMode.LARGE: 65536,               # 64KB
            BufferMode.UNBOUNDED: -1,              # System default, manual flush
        }

        return mode_sizes.get(self.config.buffer_mode, -1)

    def write(self, event_dict: Dict[str, Any]):
        """
        Write a log event to file.

        Args:
            event_dict: Log event dictionary (JSON-serializable)
        """
        if self._fork_needs_reinit:
            self._reinitialize_after_fork()
        if self._shutdown:
            return

        with self._lock:
            # Check if rotation needed
            self._check_rotation()

            # Serialize event to JSON
            import json
            line = json.dumps(event_dict, default=str) + '\n'
            line_bytes = line.encode('utf-8')

            # Handle buffering
            if self.config.buffer_mode == BufferMode.UNBOUNDED:
                # Manual buffering
                self._buffer.append(line)
                self._buffer_size_bytes += len(line_bytes)

                # Check flush policies
                should_flush = self._should_flush(event_dict)
                if should_flush:
                    self._flush()
            else:
                # Direct write (OS buffering)
                if self._file:
                    self._file.write(line)
                    self._current_size += len(line_bytes)

                    # Check flush policies for direct writes
                    if self._should_flush(event_dict):
                        self._file.flush()
                        os.fsync(self._file.fileno())

    def _should_flush(self, event_dict: Dict[str, Any]) -> bool:
        """
        Check if buffer should be flushed based on policies.

        Args:
            event_dict: Log event dictionary

        Returns:
            True if buffer should be flushed
        """
        policy = self.config.flush_policy

        # Check level-based flush
        level = event_dict.get('level', '').upper()
        if policy.on_error and level == 'ERROR':
            return True
        if policy.on_warning and level in ('WARNING', 'WARN'):
            return True

        # Check buffer size
        if policy.on_buffer_full and self.config.buffer_mode == BufferMode.UNBOUNDED:
            max_size = self._get_buffer_size()
            if max_size > 0 and self._buffer_size_bytes >= max_size:
                return True

        return False

    def _flush(self):
        """Flush buffered events to disk."""
        if not self._buffer or not self._file:
            return

        with self._lock:
            try:
                # Write all buffered lines
                self._file.writelines(self._buffer)
                self._file.flush()
                os.fsync(self._file.fileno())

                # Update size tracking
                self._current_size += self._buffer_size_bytes

                # Clear buffer
                self._buffer.clear()
                self._buffer_size_bytes = 0

            except (OSError, ValueError):
                # Handle closed file or I/O errors
                pass

    def _check_rotation(self):
        """Check if log file should be rotated."""
        should_rotate = False

        if self.config.rotation.type == RotationType.SIZE:
            # Size-based rotation
            if self._current_size >= self.config.rotation.max_bytes:
                should_rotate = True

        elif self.config.rotation.type == RotationType.TIME:
            # Time-based rotation
            if self._rotation_time and datetime.now() >= self._rotation_time:
                should_rotate = True

        elif self.config.rotation.type == RotationType.HYBRID:
            # Both size and time
            size_check = self._current_size >= self.config.rotation.max_bytes
            time_check = self._rotation_time and datetime.now() >= self._rotation_time
            if size_check or time_check:
                should_rotate = True

        if should_rotate:
            self._rotate()

    def _rotate(self):
        """Rotate the log file."""
        if not self._file:
            return

        # Flush and close current file
        self._flush()
        self._file.close()

        # Find next backup number
        backup_num = 1
        while backup_num <= self.config.rotation.backup_count:
            backup_path = Path(f"{self.path}.{backup_num}")
            if not backup_path.exists():
                break
            backup_num += 1

        # Remove oldest backup if at limit
        if backup_num > self.config.rotation.backup_count:
            oldest = Path(f"{self.path}.{self.config.rotation.backup_count}")
            if oldest.exists():
                oldest.unlink()
            backup_num = self.config.rotation.backup_count

        # Rotate existing backups
        for i in range(backup_num - 1, 0, -1):
            src = Path(f"{self.path}.{i}")
            dst = Path(f"{self.path}.{i + 1}")
            if src.exists():
                src.rename(dst)

        # Move current log to .1
        backup_path = Path(f"{self.path}.1")
        self.path.rename(backup_path)

        # Compress if configured
        if self.config.rotation.compress:
            self._compress_file(backup_path)

        # Open new file
        self._open_file()

        # Reset rotation time
        self._init_rotation_time()

    def _compress_file(self, path: Path):
        """
        Compress rotated log file.

        Args:
            path: Path to file to compress
        """
        compress_type = self.config.rotation.compress

        if compress_type == "gzip":
            compressed_path = path.with_suffix(path.suffix + '.gz')
            with open(path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    f_out.writelines(f_in)
            path.unlink()

        elif compress_type == "bz2":
            compressed_path = path.with_suffix(path.suffix + '.bz2')
            with open(path, 'rb') as f_in:
                with bz2.open(compressed_path, 'wb') as f_out:
                    f_out.writelines(f_in)
            path.unlink()

        elif compress_type == "xz":
            compressed_path = path.with_suffix(path.suffix + '.xz')
            with open(path, 'rb') as f_in:
                with lzma.open(compressed_path, 'wb') as f_out:
                    f_out.writelines(f_in)
            path.unlink()

    def _init_rotation_time(self):
        """Initialize next rotation time for time-based rotation."""
        if self.config.rotation.type in (RotationType.TIME, RotationType.HYBRID):
            # Calculate next rotation time based on 'when' and 'interval'
            now = datetime.now()

            if self.config.rotation.when == "midnight":
                # Rotate at midnight
                next_day = now + timedelta(days=self.config.rotation.interval)
                self._rotation_time = next_day.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            elif self.config.rotation.when == "H":
                # Rotate every N hours
                self._rotation_time = now + timedelta(
                    hours=self.config.rotation.interval
                )
            elif self.config.rotation.when == "M":
                # Rotate every N minutes
                self._rotation_time = now + timedelta(
                    minutes=self.config.rotation.interval
                )
            else:
                # Default: rotate at midnight
                next_day = now + timedelta(days=1)
                self._rotation_time = next_day.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )

    def _start_flush_timer(self):
        """Start periodic flush timer."""
        if self._shutdown:
            return

        def flush_task():
            if not self._shutdown:
                with self._lock:
                    # Flush manual buffer if using UNBOUNDED mode
                    if self.config.buffer_mode == BufferMode.UNBOUNDED:
                        self._flush()
                    # Flush OS buffer for other modes
                    elif self._file:
                        try:
                            self._file.flush()
                            os.fsync(self._file.fileno())
                        except (OSError, ValueError):
                            pass
                self._start_flush_timer()

        interval = self.config.flush_policy.on_interval
        self._flush_timer = threading.Timer(interval, flush_task)
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _setup_signal_handler(self):
        """Setup signal handler for flush."""
        sig_name = self.config.flush_policy.on_signal

        if sig_name and hasattr(signal, sig_name):
            sig_num = getattr(signal, sig_name)

            def signal_handler(signum, frame):
                with self._lock:
                    self._flush()

            signal.signal(sig_num, signal_handler)

    def flush(self):
        """Public API: Flush buffered events to disk."""
        self._flush()

    def shutdown(self):
        """Public API: Shutdown the file output handler."""
        self.close()

    def close(self):
        """Close the file output and flush remaining data."""
        self._shutdown = True

        # Stop flush timer
        if self._flush_timer:
            self._flush_timer.cancel()

        with self._lock:
            # Flush any remaining data
            if self.config.flush_policy.on_exit:
                self._flush()

            # Close file
            if self._file:
                self._file.close()
                self._file = None

    def __del__(self):
        """Cleanup on deletion."""
        self.close()


__all__ = ['FileOutput']
