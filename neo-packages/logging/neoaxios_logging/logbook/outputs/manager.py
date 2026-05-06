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
Output manager for coordinating multiple output destinations.

This module provides the OutputManager that routes log events to multiple
configured outputs (files, streams, etc.) with per-output filtering.
"""

import sys
import threading
from typing import Dict, List, Any
from neoaxios_logging.logbook.config import OutputConfig, LogLevel
from .file_output import FileOutput
from neoaxios_logging._fork_safety import register_fork_unsafe


class OutputManager:
    """
    Manages multiple output destinations for structured logs.

    Features:
    - Route events to multiple outputs
    - Per-output level filtering
    - Per-output component filtering
    - Thread-safe operations
    """

    def __init__(self, outputs: List[OutputConfig]):
        """
        Initialize output manager.

        Args:
            outputs: List of OutputConfig defining output destinations
        """
        self.outputs: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._fork_needs_reinit = False

        for output_config in outputs:
            self._add_output(output_config)

        register_fork_unsafe(self)

    def _reset_after_fork(self) -> None:
        self._fork_needs_reinit = True
        self._lock = threading.RLock()
        for output in self.outputs:
            try:
                output["handler"].close()
            except Exception:
                pass

    def _reinitialize_after_fork(self) -> None:
        if not self._fork_needs_reinit:
            return
        self._fork_needs_reinit = False
        configs = [output["config"] for output in self.outputs]
        self.outputs = []
        for config in configs:
            self._add_output(config)

    def _add_output(self, config: OutputConfig):
        """
        Add an output destination.

        Args:
            config: OutputConfig for this destination
        """
        if config.type == "file":
            handler = FileOutput(config)
        elif config.type == "stream":
            handler = self._create_stream_handler(config)
        else:
            raise ValueError(f"Unknown output type: {config.type}")

        self.outputs.append({
            "config": config,
            "handler": handler,
        })

    def _create_stream_handler(self, config: OutputConfig):
        """
        Create a stream handler (stdout/stderr).

        Args:
            config: OutputConfig for stream

        Returns:
            Stream handler object
        """
        stream = sys.stderr if config.stream == "stderr" else sys.stdout

        class StreamHandler:
            """Simple stream handler wrapper."""

            def __init__(self, stream):
                self.stream = stream
                self._lock = threading.RLock()

            def write(self, event_dict: Dict[str, Any]):
                """Write event to stream."""
                import json
                with self._lock:
                    line = json.dumps(event_dict, default=str)
                    self.stream.write(line + '\n')
                    self.stream.flush()

            def close(self):
                """Close stream (no-op for stdout/stderr)."""
                pass

        return StreamHandler(stream)

    def emit(self, event_dict: Dict[str, Any]):
        """
        Emit a log event to all matching outputs.

        Applies per-output filtering based on level and component patterns.

        Args:
            event_dict: Log event dictionary
        """
        if self._fork_needs_reinit:
            self._reinitialize_after_fork()
        with self._lock:
            for output in self.outputs:
                if self._should_emit(output["config"], event_dict):
                    try:
                        output["handler"].write(event_dict)
                    except Exception:
                        # Ignore errors in output handlers to avoid breaking logging
                        pass

    def _should_emit(self, config: OutputConfig, event_dict: Dict[str, Any]) -> bool:
        """
        Check if event should be emitted to this output.

        Args:
            config: OutputConfig with filters
            event_dict: Log event dictionary

        Returns:
            True if event matches output filters
        """
        # Check level
        event_level_str = event_dict.get("level", "").upper()
        try:
            event_level = LogLevel.from_string(event_level_str)
        except (ValueError, AttributeError):
            # If we can't parse level, let it through
            return True

        if event_level < config.level:
            return False

        # Check component pattern
        component = event_dict.get("component") or event_dict.get("logger", "")
        if not self._matches_pattern(config.components, component):
            return False

        return True

    def _matches_pattern(self, pattern: str, component: str) -> bool:
        """
        Check if component matches pattern.

        Supports:
        - "*" (all components)
        - Exact match
        - Prefix wildcard: "myapp.*"

        Args:
            pattern: Component pattern
            component: Component name

        Returns:
            True if component matches pattern
        """
        if pattern == "*":
            return True

        if pattern == component:
            return True

        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            if component.startswith(prefix + ".") or component == prefix:
                return True

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if component.startswith(prefix):
                return True

        return False

    def close(self):
        """Close all output handlers."""
        with self._lock:
            for output in self.outputs:
                try:
                    output["handler"].close()
                except Exception:
                    pass

    def __del__(self):
        """Cleanup on deletion."""
        self.close()


class OutputProcessor:
    """
    Structlog processor that routes events to OutputManager.

    This processor is added to the structlog pipeline to route events
    to multiple configured outputs instead of the default output.
    """

    def __init__(self, output_manager: OutputManager):
        """
        Initialize output processor.

        Args:
            output_manager: OutputManager instance
        """
        self.output_manager = output_manager

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process log event and route to outputs.

        Args:
            logger: Logger instance
            method_name: Log method name
            event_dict: Event dictionary

        Returns:
            Event dictionary (unchanged)
        """
        # Emit to all configured outputs
        self.output_manager.emit(event_dict)

        # Return event_dict for other processors
        return event_dict


__all__ = ['OutputManager', 'OutputProcessor']
