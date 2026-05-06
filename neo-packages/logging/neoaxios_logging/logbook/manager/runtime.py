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
Runtime configuration manager for Logbook.

This module provides runtime API for dynamic configuration changes without
restarting the application.
"""

import threading
from typing import Optional, Dict, Any
from pathlib import Path

from neoaxios_logging.logbook.config import (
    LogbookConfig,
    LogLevel,
    load_config,
)
from neoaxios_logging.logbook.processors import LogLevelFilterProcessor
from neoaxios_logging.logbook.outputs import OutputManager
from neoaxios_logging._fork_safety import register_reset_callback


class RuntimeManager:
    """
    Runtime configuration manager for Logbook.

    Provides dynamic configuration updates at runtime:
    - Change log levels (per-component or default)
    - Add/remove output destinations
    - Reload configuration from file
    - Apply presets

    Thread-safe singleton implementation.
    """

    _instance: Optional['RuntimeManager'] = None
    _lock = threading.RLock()

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize runtime manager."""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._config: Optional[LogbookConfig] = None
        self._level_filter: Optional[LogLevelFilterProcessor] = None
        self._output_manager: Optional[OutputManager] = None
        self._config_lock = threading.RLock()

    def initialize(
        self,
        config: Optional[LogbookConfig] = None,
        level_filter: Optional[LogLevelFilterProcessor] = None,
        output_manager: Optional[OutputManager] = None
    ):
        """
        Initialize runtime manager with components.

        Args:
            config: Initial LogbookConfig
            level_filter: LogLevelFilterProcessor instance
            output_manager: OutputManager instance
        """
        with self._config_lock:
            self._config = config or LogbookConfig.create_default()
            self._level_filter = level_filter
            self._output_manager = output_manager

    def set_level(self, component: str, level: LogLevel):
        """
        Set log level for a specific component at runtime.

        Use "*" to set the base level for all components.

        Args:
            component: Component name or pattern (e.g., "myapp.processor", "myapp.*", or "*" for base level)
            level: New log level

        Example:
            >>> manager = get_runtime_manager()
            >>> manager.set_level("myapp.processor", LogLevel.DEBUG)
            >>> manager.set_level("myapp.*", LogLevel.INFO)
            >>> manager.set_level("*", LogLevel.ERROR)  # Set base level
        """
        with self._config_lock:
            if self._config:
                if component == "*":
                    self._config.level = level
                else:
                    self._config.component_levels[component] = level

            if self._level_filter:
                self._level_filter.set_level(component, level)

    def get_level(self, component: str) -> LogLevel:
        """
        Get current log level for a component.

        Args:
            component: Component name

        Returns:
            Current log level for component

        Example:
            >>> manager = get_runtime_manager()
            >>> level = manager.get_level("myapp.processor")
            >>> print(level)
            LogLevel.INFO
        """
        with self._config_lock:
            if self._config:
                return self._config.get_component_level(component)
            return LogLevel.ERROR

    def get_config(self) -> LogbookConfig:
        """
        Get current configuration.

        Returns:
            Current LogbookConfig

        Example:
            >>> manager = get_runtime_manager()
            >>> config = manager.get_config()
            >>> print(config.level)
        """
        with self._config_lock:
            if self._config:
                return self._config
            return LogbookConfig.create_default()

    def reload_config(self, config_path: Optional[Path] = None):
        """
        Reload configuration from file.

        Args:
            config_path: Path to telemetry.yaml (default: auto-detect)

        Example:
            >>> manager = get_runtime_manager()
            >>> manager.reload_config()  # Reload from telemetry.yaml
        """
        with self._config_lock:
            # Load new config
            new_config = load_config(config_path)

            # Update runtime state
            self._config = new_config

            # Update level filter
            if self._level_filter:
                for component, lvl in new_config.component_levels.items():
                    self._level_filter.set_level(component, lvl)
                self._level_filter.default_level = new_config.level

            # TODO: Update output manager with new outputs
            # This would require recreating outputs, which is complex
            # For now, outputs are only configured at startup

    def apply_preset(self, preset_name: str):
        """
        Apply a configuration preset at runtime.

        Available presets:
        - "development": DEBUG level for all components
        - "production": ERROR level for all components
        - "troubleshooting": ERROR default with selective DEBUG/TRACE

        Args:
            preset_name: Preset name

        Example:
            >>> manager = get_runtime_manager()
            >>> manager.apply_preset("development")
        """
        with self._config_lock:
            if self._config:
                try:
                    self._config.load_preset(preset_name)

                    # Update level filter
                    if self._level_filter:
                        for component, lvl in self._config.component_levels.items():
                            self._level_filter.set_level(component, lvl)
                        self._level_filter.default_level = self._config.level

                except ValueError as e:
                    raise ValueError(f"Unknown preset: {preset_name}") from e

    def get_level_config(self) -> Dict[str, str]:
        """
        Get current level configuration for all components.

        Returns:
            Dictionary mapping component patterns to level names

        Example:
            >>> manager = get_runtime_manager()
            >>> levels = manager.get_level_config()
            >>> print(levels)
            {'*': 'ERROR', 'myapp.*': 'INFO', 'myapp.processor': 'DEBUG'}
        """
        with self._config_lock:
            if self._level_filter:
                return self._level_filter.get_level_config()
            return {}

    def enable_console_output(self):
        """
        Enable console output at runtime.

        Example:
            >>> manager = get_runtime_manager()
            >>> manager.enable_console_output()
        """
        with self._config_lock:
            if self._config:
                self._config.console_enabled = True
            # TODO: Add console output to output_manager

    def disable_console_output(self):
        """
        Disable console output at runtime.

        Example:
            >>> manager = get_runtime_manager()
            >>> manager.disable_console_output()
        """
        with self._config_lock:
            if self._config:
                self._config.console_enabled = False
            # TODO: Remove console output from output_manager

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get runtime statistics.

        Returns:
            Dictionary with statistics (config state, output count, etc.)

        Example:
            >>> manager = get_runtime_manager()
            >>> stats = manager.get_statistics()
            >>> print(f"Base level: {stats['level']}")
            >>> print(f"Component count: {stats['component_count']}")
        """
        with self._config_lock:
            stats = {
                "level": str(self._config.level) if self._config else "ERROR",
                "component_count": len(self._config.component_levels) if self._config else 0,
                "console_enabled": self._config.console_enabled if self._config else False,
                "enabled": self._config.enabled if self._config else False,
            }

            if self._config:
                stats["components"] = {
                    comp: str(lvl) for comp, lvl in self._config.component_levels.items()
                }

            return stats


# Global singleton accessor
_runtime_manager_instance: Optional[RuntimeManager] = None


def get_runtime_manager() -> RuntimeManager:
    """
    Get the global RuntimeManager singleton.

    Returns:
        RuntimeManager instance

    Example:
        >>> from telemetry.logbook.manager import get_runtime_manager
        >>> manager = get_runtime_manager()
        >>> manager.set_level("myapp.processor", LogLevel.DEBUG)
    """
    global _runtime_manager_instance
    if _runtime_manager_instance is None:
        _runtime_manager_instance = RuntimeManager()
    return _runtime_manager_instance


__all__ = ['RuntimeManager', 'get_runtime_manager']


def _reset_runtime_manager_for_fork_child() -> None:
    global _runtime_manager_instance
    _runtime_manager_instance = None
    RuntimeManager._instance = None
    RuntimeManager._lock = threading.RLock()


register_reset_callback(_reset_runtime_manager_for_fork_child)
