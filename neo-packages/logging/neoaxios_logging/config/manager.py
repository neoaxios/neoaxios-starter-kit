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
Telemetry Configuration Management - Infrastructure Layer

This module provides the configuration manager infrastructure for loading, validating,
and merging telemetry configuration from various sources (telemetry.yaml, defaults,
CLI arguments, environment variables).

Config dataclasses are now located in their respective implementation folders:
- LogbookConfig: logbook/config.py
- FlightRecorderConfig + PerformanceConfig: flight_recorder/config.py
- DiagnosticsConfig: diagnostics/config.py
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict
import yaml

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Dumper

# Import config classes from implementations
from ..logbook.config import LogbookConfig
from ..flight_recorder.config import FlightRecorderConfig, PerformanceConfig
from ..diagnostics.config import DiagnosticsConfig


# Default configuration file name
DEFAULT_CONFIG_NAME = "telemetry.yaml"


@dataclass
class ProjectConfig:
    """
    Main project configuration container.

    This is the top-level configuration object that contains all telemetry subsystem configs.
    """

    version: str = "1.0"
    logbook: LogbookConfig = field(default_factory=LogbookConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    flight_recorder: FlightRecorderConfig = field(default_factory=FlightRecorderConfig)
    diagnostics: DiagnosticsConfig = field(default_factory=DiagnosticsConfig)

    # Project-specific settings
    project_name: Optional[str] = None
    project_root: Optional[str] = None

    def __post_init__(self):
        """Convert nested dicts to dataclasses if needed."""
        # Support both 'telemetry' (new YAML) and 'logbook' (legacy)
        if isinstance(self.logbook, dict):
            self.logbook = LogbookConfig.from_dict(self.logbook)
        if isinstance(self.performance, dict):
            self.performance = PerformanceConfig(**self.performance)
        if isinstance(self.flight_recorder, dict):
            self.flight_recorder = FlightRecorderConfig(**self.flight_recorder)
        if isinstance(self.diagnostics, dict):
            self.diagnostics = DiagnosticsConfig(**self.diagnostics)

    def validate(self):
        """Validate the configuration."""
        # Validate version
        if not self.version:
            raise ValueError("version is required")

        # Validate logbook level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "TRACE"]
        level_str = self.logbook.level.name if hasattr(self.logbook.level, 'name') else str(self.logbook.level)
        if level_str.upper() not in valid_levels:
            raise ValueError(
                f"Invalid logbook.level: {level_str}. "
                f"Must be one of: {', '.join(valid_levels)}"
            )

        # Validate logbook format
        valid_formats = ["text", "json"]
        if self.logbook.format not in valid_formats:
            raise ValueError(
                f"Invalid logbook.format: {self.logbook.format}. "
                f"Must be one of: {', '.join(valid_formats)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        from enum import Enum

        def convert_value(obj):
            """Recursively convert enums to strings."""
            if isinstance(obj, Enum):
                return obj.name
            elif isinstance(obj, dict):
                return {k: convert_value(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_value(item) for item in obj]
            else:
                return obj

        result = asdict(self)
        result = convert_value(result)
        # Remove None values for cleaner YAML
        return {k: v for k, v in result.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectConfig":
        """Create from dictionary."""
        # Handle migration from 'telemetry' (YAML key) to 'logbook' (dataclass field)
        if 'telemetry' in data:
            telemetry_data = data.pop('telemetry')

            # If logbook already exists (e.g., from CLI overrides), merge them
            if 'logbook' in data:
                # Merge telemetry into logbook, with logbook taking precedence
                if isinstance(telemetry_data, dict) and isinstance(data['logbook'], dict):
                    merged = {**telemetry_data, **data['logbook']}
                    data['logbook'] = merged
                # else: logbook from CLI overrides completely replaces telemetry
            else:
                # No logbook exists, just rename
                data['logbook'] = telemetry_data

        return cls(**data)


class ConfigManager:
    """Manages telemetry configuration loading and merging."""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        config_name: str = DEFAULT_CONFIG_NAME
    ):
        """
        Initialize config manager.

        Args:
            project_root: Project root directory. Defaults to current directory.
            config_name: Name of the config file to load. Defaults to telemetry.yaml.
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.config_path = self.project_root / config_name
        self._config: Optional[ProjectConfig] = None
        self._cli_overrides: Dict[str, Any] = {}

    def load(self) -> ProjectConfig:
        """
        Load configuration with the following precedence (highest to lowest):

        1. CLI arguments (set via set_cli_override)
        2. System-wide config (/etc/neoaxios/logging.yaml)
        3. User config (~/.config/neoaxios/logging.yaml)
        4. Project workspace (./config/packages/logging.yaml)
        5. Environment-specific (./config/environments/{NEO_ENV}/logging.yaml)
        6. Local overrides (./.neoaxios.local.yaml)
        7. Environment variables (NEO_TELEMETRY_*, etc.)
        8. Bundled defaults (telemetry/config/defaults/logging.yaml)

        Returns:
            ProjectConfig object
        """
        if self._config is not None:
            return self._config

        # Load .env files for legacy support
        from .env_loader import load_env_files
        load_env_files(self.project_root)

        # Load bundled defaults
        bundled_defaults = Path(__file__).parent / "defaults" / "logging.yaml"

        try:
            with open(bundled_defaults) as f:
                config_data = yaml.safe_load(f) or {}
        except (yaml.YAMLError, IOError) as e:
            import warnings
            warnings.warn(f"Failed to load bundled defaults {bundled_defaults}: {e}. Using empty config.")
            config_data = {}

        # Merge with custom config if it exists
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    custom_data = yaml.safe_load(f) or {}
                config_data = self._merge_configs(config_data, custom_data)
            except (yaml.YAMLError, IOError) as e:
                import warnings
                warnings.warn(f"Failed to load {self.config_path}: {e}. Using defaults only.")

        # Apply environment variable overrides
        env_overrides = {}

        # Map: NEO_TELEMETRY_ENABLED → logbook.enabled
        if 'NEO_TELEMETRY_ENABLED' in os.environ:
            value = os.environ['NEO_TELEMETRY_ENABLED'].lower() == 'true'
            env_overrides.setdefault('logbook', {})['enabled'] = value

        # Map: NEO_TELEMETRY_LEVEL → logbook.level
        if 'NEO_TELEMETRY_LEVEL' in os.environ:
            env_overrides.setdefault('logbook', {})['level'] = os.environ['NEO_TELEMETRY_LEVEL']

        # Map: NEO_TELEMETRY_CONSOLE_ENABLED → logbook.console_enabled (if supported)
        if 'NEO_TELEMETRY_CONSOLE_ENABLED' in os.environ:
            value = os.environ['NEO_TELEMETRY_CONSOLE_ENABLED'].lower() == 'true'
            env_overrides.setdefault('logbook', {})['console_enabled'] = value

        # Map: NEO_PERFORMANCE_ENABLED → performance.enabled
        if 'NEO_PERFORMANCE_ENABLED' in os.environ:
            value = os.environ['NEO_PERFORMANCE_ENABLED'].lower() == 'true'
            env_overrides.setdefault('performance', {})['enabled'] = value

        # Map: NEO_PERFORMANCE_TRACKING → performance.enabled (alternative name)
        if 'NEO_PERFORMANCE_TRACKING' in os.environ:
            value = os.environ['NEO_PERFORMANCE_TRACKING'].lower() == 'true'
            env_overrides.setdefault('performance', {})['enabled'] = value

        # Map: NEO_FLIGHT_RECORDER_ENABLED → flight_recorder.enabled
        if 'NEO_FLIGHT_RECORDER_ENABLED' in os.environ:
            value = os.environ['NEO_FLIGHT_RECORDER_ENABLED'].lower() == 'true'
            env_overrides.setdefault('flight_recorder', {})['enabled'] = value

        if env_overrides:
            config_data = self._merge_configs(config_data, env_overrides)

        # Apply CLI overrides (highest priority)
        config_data = self._merge_configs(config_data, self._cli_overrides)

        # Create and validate config
        self._config = ProjectConfig.from_dict(config_data)
        self._config.validate()

        return self._config

    def save(self, config: Optional[ProjectConfig] = None):
        """
        Save configuration to file.

        Args:
            config: Configuration to save. Uses current config if not provided.
        """
        if config is None:
            config = self._config or ProjectConfig()

        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        # Save to file
        with open(self.config_path, "w") as f:
            yaml.dump(config.to_dict(), f, Dumper=Dumper, default_flow_style=False, sort_keys=False)

    def set_cli_override(self, key: str, value: Any):
        """
        Set a CLI override for configuration.

        Args:
            key: Configuration key (supports dot notation, e.g., "performance.enabled")
            value: Value to set
        """
        # Handle dot notation
        keys = key.split(".")
        current = self._cli_overrides

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

        # Clear cached config
        self._config = None

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found

        Returns:
            Configuration value
        """
        config = self.load()

        # Handle dot notation
        keys = key.split(".")
        current = config

        for k in keys:
            if hasattr(current, k):
                current = getattr(current, k)
            elif isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default

        return current


    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result


# Global config manager instance
_global_config_manager: Optional[ConfigManager] = None


def get_config_manager(
    project_root: Optional[Path] = None,
    config_name: str = DEFAULT_CONFIG_NAME
) -> ConfigManager:
    """
    Get global config manager instance.

    Args:
        project_root: Project root directory
        config_name: Name of the config file

    Returns:
        ConfigManager instance
    """
    global _global_config_manager

    if _global_config_manager is None or (
        project_root and _global_config_manager.project_root != Path(project_root)
    ):
        _global_config_manager = ConfigManager(project_root, config_name)

    return _global_config_manager


def load_config(
    project_root: Optional[Path] = None,
    config_name: str = DEFAULT_CONFIG_NAME
) -> ProjectConfig:
    """
    Load telemetry configuration.

    Args:
        project_root: Project root directory
        config_name: Name of the config file

    Returns:
        ProjectConfig object
    """
    return get_config_manager(project_root, config_name).load()
