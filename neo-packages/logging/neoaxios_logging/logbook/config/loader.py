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
Configuration loader for Logbook.

This module provides functions to load LogbookConfig from:
- telemetry.yaml file
- Environment variables
- Defaults
- Presets

Configuration precedence (highest to lowest):
1. Runtime API calls
2. Environment variables
3. telemetry.yaml
4. Defaults
"""

import os
from pathlib import Path
from typing import Optional
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from .schema import LogbookConfig, LogLevel


def load_from_file(config_path: Optional[Path] = None) -> LogbookConfig:
    """
    Load LogbookConfig from telemetry.yaml file.

    Args:
        config_path: Path to telemetry.yaml (default: search upwards from cwd)

    Returns:
        LogbookConfig instance

    Example:
        >>> config = load_from_file()
        >>> print(config.level)
        LogLevel.ERROR
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is None or not config_path.exists():
        # No config file, return defaults
        return LogbookConfig.create_default()

    # Load YAML
    try:
        with open(config_path, 'r') as f:
            data = yaml.load(f, Loader=Loader)
    except (OSError, yaml.YAMLError):
        # Error loading config, return defaults
        return LogbookConfig.create_default()

    # Extract logbook section
    if not isinstance(data, dict):
        return LogbookConfig.create_default()

    logger_config = data.get("logbook", {})

    # Convert to LogbookConfig (handle invalid levels gracefully for YAML files)
    try:
        return LogbookConfig.from_dict(logger_config)
    except ValueError as e:
        # Invalid config in YAML - return defaults with warning
        import warnings
        warnings.warn(f"Invalid configuration in {config_path}: {e}. Using defaults.")
        return LogbookConfig.create_default()


def load_from_env(base_config: Optional[LogbookConfig] = None) -> LogbookConfig:
    """
    Load LogbookConfig with environment variable overrides.

    Environment variables:
    - TELEMETRY_ENABLED: Enable/disable logger (true/false)
    - TELEMETRY_LEVEL: Default log level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - TELEMETRY_LEVEL__component__: Per-component level (e.g., TELEMETRY_LEVEL__myapp_executor__=DEBUG)
    - TELEMETRY_CONSOLE: Enable console output (true/false)
    - TELEMETRY_DIR: Log directory
    - TELEMETRY_FORMAT: Log format (json/text)

    Args:
        base_config: Base configuration to override (default: load from file)

    Returns:
        LogbookConfig with environment overrides

    Example:
        >>> os.environ["TELEMETRY_LEVEL__myapp__"] = "DEBUG"
        >>> config = load_from_env()
        >>> config.get_component_level("myapp.processor")
        LogLevel.DEBUG
    """
    if base_config is None:
        base_config = load_from_file()

    # Apply environment overrides
    config = base_config

    # TELEMETRY_ENABLED
    enabled = os.environ.get("TELEMETRY_ENABLED", "").lower()
    if enabled in ("true", "1", "yes"):
        config.enabled = True
    elif enabled in ("false", "0", "no"):
        config.enabled = False

    # TELEMETRY_LEVEL (base level)
    base_level_str = os.environ.get("TELEMETRY_LEVEL", "")
    if base_level_str:
        try:
            config.level = LogLevel.from_string(base_level_str)
        except ValueError:
            pass

    # TELEMETRY_LEVEL__component__ (per-component levels)
    for key, value in os.environ.items():
        if key.startswith("TELEMETRY_LEVEL__") and key != "TELEMETRY_LEVEL__ALL__":
            # Extract component name from env var
            # TELEMETRY_LEVEL__myapp_executor__ -> myapp.executor
            component = key[len("TELEMETRY_LEVEL__"):]
            if component.endswith("__"):
                component = component[:-2]
            component = component.replace("_", ".")

            # Parse level
            try:
                lvl = LogLevel.from_string(value)
                config.component_levels[component] = lvl
            except ValueError:
                pass

    # TELEMETRY_LEVEL__ALL__ (all components)
    all_level_str = os.environ.get("TELEMETRY_LEVEL__ALL__", "")
    if all_level_str:
        try:
            lvl = LogLevel.from_string(all_level_str)
            config.component_levels["*"] = lvl
        except ValueError:
            pass

    # TELEMETRY_CONSOLE
    console_enabled = os.environ.get("TELEMETRY_CONSOLE", "").lower()
    if console_enabled in ("true", "1", "yes"):
        config.console_enabled = True
    elif console_enabled in ("false", "0", "no"):
        config.console_enabled = False

    # TELEMETRY_DIR
    log_dir = os.environ.get("TELEMETRY_DIR", "")
    if log_dir:
        config.log_dir = log_dir

    # TELEMETRY_FORMAT
    log_format = os.environ.get("TELEMETRY_FORMAT", "")
    if log_format:
        config.format = log_format

    return config


def load_config(
    config_path: Optional[Path] = None,
    apply_env: bool = True,
    preset: Optional[str] = None
) -> LogbookConfig:
    """
    Load complete LogbookConfig with all sources.

    Precedence order:
    1. Preset (if specified)
    2. Environment variables (if apply_env=True)
    3. File (telemetry.yaml)
    4. Defaults

    Args:
        config_path: Path to telemetry.yaml (default: auto-detect)
        apply_env: Apply environment variable overrides
        preset: Preset name to load ("development", "production", "troubleshooting")

    Returns:
        LogbookConfig instance

    Example:
        >>> # Load with all defaults
        >>> config = load_config()

        >>> # Load with development preset
        >>> config = load_config(preset="development")

        >>> # Load specific file without env overrides
        >>> config = load_config(
        ...     config_path=Path("custom/telemetry.yaml"),
        ...     apply_env=False
        ... )
    """
    # Load from file
    config = load_from_file(config_path)

    # Apply preset if specified
    if preset:
        try:
            config.load_preset(preset)
        except ValueError:
            pass

    # Apply environment overrides
    if apply_env:
        config = load_from_env(config)

    return config


def find_config_file(start_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Find telemetry.yaml by searching upwards from start directory.

    Args:
        start_dir: Directory to start search (default: cwd)

    Returns:
        Path to telemetry.yaml or None if not found

    Example:
        >>> path = find_config_file()
        >>> if path:
        ...     print(f"Found config at: {path}")
    """
    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    # Search upwards
    while True:
        config_path = current / "telemetry.yaml"
        if config_path.exists():
            return config_path

        # Check parent
        parent = current.parent
        if parent == current:
            # Reached root
            break
        current = parent

    return None


def create_default_config() -> LogbookConfig:
    """
    Create default LogbookConfig.

    Returns:
        LogbookConfig with sensible defaults

    Example:
        >>> config = create_default_config()
        >>> config.level
        LogLevel.ERROR
    """
    return LogbookConfig.create_default()


def create_development_config() -> LogbookConfig:
    """
    Create development preset configuration.

    Features:
    - All components at DEBUG level
    - Console output enabled
    - File output to .telemetry/dev.log

    Returns:
        LogbookConfig for development

    Example:
        >>> config = create_development_config()
        >>> config.get_component_level("myapp.processor")
        LogLevel.DEBUG
    """
    config = LogbookConfig(
        level=LogLevel.DEBUG,
        component_levels={"*": LogLevel.DEBUG},
        console_enabled=True,
        enabled=True,
        log_dir=".telemetry",
        log_file="dev.log",
        format="json"
    )
    return config


def create_production_config() -> LogbookConfig:
    """
    Create production preset configuration.

    Features:
    - ERROR level by default
    - No console output
    - File output with rotation

    Returns:
        LogbookConfig for production

    Example:
        >>> config = create_production_config()
        >>> config.level
        LogLevel.ERROR
    """
    config = LogbookConfig(
        level=LogLevel.ERROR,
        component_levels={"*": LogLevel.ERROR},
        console_enabled=False,
        enabled=True,
        log_dir=".telemetry",
        log_file="telemetry.log",
        format="json"
    )
    return config


def create_troubleshooting_config() -> LogbookConfig:
    """
    Create troubleshooting preset configuration.

    Features:
    - ERROR default, but allows selective DEBUG/TRACE
    - Console and file output
    - Useful for debugging specific components

    Returns:
        LogbookConfig for troubleshooting

    Example:
        >>> config = create_troubleshooting_config()
        >>> # Then override specific components:
        >>> config.component_levels["myapp.problematic_module"] = LogLevel.TRACE
    """
    config = LogbookConfig(
        level=LogLevel.ERROR,
        component_levels={"*": LogLevel.ERROR},
        console_enabled=True,
        enabled=True,
        log_dir=".telemetry",
        log_file="troubleshoot.log",
        format="json"
    )
    return config


__all__ = [
    'load_from_file',
    'load_from_env',
    'load_config',
    'find_config_file',
    'create_default_config',
    'create_development_config',
    'create_production_config',
    'create_troubleshooting_config',
]
