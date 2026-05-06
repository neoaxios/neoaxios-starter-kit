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
Per-component log level filtering processor.

This processor enables granular control over log levels on a per-component basis,
allowing different modules to have different verbosity levels.
"""

from typing import Dict, List, Tuple, Any
import structlog
from neoaxios_logging.common.types import LogLevel


class LogLevelFilterProcessor:
    """
    Processor that filters log events based on per-component log level configuration.

    This processor implements hierarchical log level filtering:
    1. Exact component match (highest priority)
    2. Wildcard prefix match (longest prefix wins)
    3. Default level (fallback)

    Examples:
        Configuration:
        {
            "neoaxios_fastapi_kit.executor": TRACE,
            "neoaxios_fastapi_kit.*": INFO,
            "*": ERROR
        }

        Component "neoaxios_fastapi_kit.executor" -> TRACE (exact match)
        Component "neoaxios_fastapi_kit.stage_orchestrator" -> INFO (wildcard match)
        Component "neoaxios_fastapi_kit.middleware.auth" -> ERROR (default)
    """

    def __init__(self, level_config: Dict[str, LogLevel], default_level: LogLevel = LogLevel.ERROR):
        """
        Initialize the LogLevelFilterProcessor.

        Args:
            level_config: Dictionary mapping component patterns to minimum log levels
            default_level: Default log level for components not in config
        """
        self.default_level = default_level
        self._exact_matches: Dict[str, LogLevel] = {}
        self._prefix_patterns: List[Tuple[str, LogLevel]] = []
        self._lookup_cache: Dict[str, LogLevel] = {}

        # Parse configuration into exact matches and prefix patterns
        for pattern, level in level_config.items():
            if pattern == "*":
                self.default_level = level
            elif pattern.endswith(".*"):
                # Prefix wildcard pattern
                prefix = pattern[:-2]  # Remove ".*"
                self._prefix_patterns.append((prefix, level))
            else:
                # Exact match
                self._exact_matches[pattern] = level

        # Sort prefix patterns by length (longest first) for priority matching
        self._prefix_patterns.sort(key=lambda x: len(x[0]), reverse=True)

    def _get_min_level(self, component: str) -> LogLevel:
        """
        Get the minimum log level for a component.

        Uses a hierarchical matching strategy:
        1. Check cache for previous lookups (O(1))
        2. Check exact matches (O(1))
        3. Check prefix patterns (O(k) where k = number of patterns)
        4. Return default level

        Args:
            component: Component name (e.g., "neoaxios_fastapi_kit.executor")

        Returns:
            Minimum log level for this component
        """
        # Check cache first
        if component in self._lookup_cache:
            return self._lookup_cache[component]

        # Check exact match
        if component in self._exact_matches:
            level = self._exact_matches[component]
            self._lookup_cache[component] = level
            return level

        # Check prefix patterns (longest first)
        for prefix, level in self._prefix_patterns:
            if component.startswith(prefix + "."):
                self._lookup_cache[component] = level
                return level

        # Use default level
        self._lookup_cache[component] = self.default_level
        return self.default_level

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Filter log events based on component-specific log level.

        Args:
            logger: The logger instance
            method_name: The name of the log method (e.g., "debug", "info")
            event_dict: The log event dictionary

        Returns:
            The event_dict unchanged if the event should be logged

        Raises:
            structlog.DropEvent: If the log level is below the minimum for this component
        """
        # Extract component name from event_dict
        component = event_dict.get("logger", event_dict.get("component", ""))

        # Extract log level from event_dict
        level_str = event_dict.get("level", "").upper()

        try:
            event_level = LogLevel.from_string(level_str)
        except (ValueError, AttributeError):
            # If we can't parse the level, let it through
            return event_dict

        # Get minimum level for this component
        min_level = self._get_min_level(component)

        # Drop event if below minimum level
        if event_level < min_level:
            raise structlog.DropEvent

        return event_dict

    def get_level(self, component: str) -> LogLevel:
        """
        Get the minimum log level for a specific component.

        This is a public accessor to _get_min_level() for use by decorators
        and other code that needs to check if a level would be logged.

        Args:
            component: Component name (e.g., "neoaxios_fastapi_kit.executor")

        Returns:
            Minimum log level for this component

        Example:
            >>> processor = LogLevelFilterProcessor({"myapp.*": LogLevel.INFO})
            >>> processor.get_level("myapp.processor")
            LogLevel.INFO
        """
        return self._get_min_level(component)

    def get_level_config(self) -> Dict[str, str]:
        """
        Get the current level configuration.

        Returns:
            Dictionary mapping component patterns to level names
        """
        config = {}

        # Add default
        config["*"] = str(self.default_level)

        # Add exact matches
        for component, level in self._exact_matches.items():
            config[component] = str(level)

        # Add prefix patterns
        for prefix, level in self._prefix_patterns:
            config[f"{prefix}.*"] = str(level)

        return config

    def set_level(self, component: str, level: LogLevel) -> None:
        """
        Set the log level for a component at runtime.

        Args:
            component: Component pattern (exact or wildcard)
            level: Minimum log level for this component
        """
        if component == "*":
            self.default_level = level
        elif component.endswith(".*"):
            # Update prefix pattern
            prefix = component[:-2]
            # Remove existing pattern if present
            self._prefix_patterns = [
                (p, l) for p, l in self._prefix_patterns if p != prefix
            ]
            self._prefix_patterns.append((prefix, level))
            self._prefix_patterns.sort(key=lambda x: len(x[0]), reverse=True)
        else:
            # Exact match
            self._exact_matches[component] = level

        # Clear cache to force re-evaluation
        self._lookup_cache.clear()

    def clear_cache(self) -> None:
        """Clear the lookup cache. Useful for testing or configuration reloads."""
        self._lookup_cache.clear()
