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
Failure-only logging configuration resolution.

Hierarchy (most specific wins):
1. Decorator level: @auto_trace(logger, log_on_failure_only=True)
2. File level: # logbook: log_on_failure_only=true
3. Project level: LOGBOOK_FAILURE_ONLY=true or .logbook.conf
4. Default: Configured in telemetry.logbook.config.defaults.FAILURE_ONLY_DEFAULT
"""

import os
import builtins
from pathlib import Path
from typing import Optional, Dict
from functools import lru_cache
from neoaxios_logging.logbook.config.defaults import FAILURE_ONLY_DEFAULT

# Global cache for file-level configurations
_file_configs: Dict[str, Dict[str, bool]] = {}

# Store reference to real open() to avoid test mock interference
# This ensures config file introspection always uses the actual filesystem
# even when tests mock builtins.open for their own purposes
_real_open = builtins.open


class FailureOnlyConfig:
    """
    Configuration manager for failure-only logging mode.

    Resolves configuration from multiple sources with proper precedence.
    """

    @staticmethod
    @lru_cache(maxsize=128)
    def get_project_config() -> bool:
        """
        Get project-level failure-only configuration.

        Checks:
        1. Environment variable: LOGBOOK_FAILURE_ONLY
        2. Config file: .logbook.conf in package root

        Returns:
            True if failure-only mode enabled at project level
        """
        # Check environment variable first (highest precedence for project-level)
        env_value = os.getenv('LOGBOOK_FAILURE_ONLY', '').lower()
        if env_value in ('true', '1', 'yes', 'on'):
            return True
        if env_value in ('false', '0', 'no', 'off'):
            return False

        # Check .logbook.conf file
        # Find package root by looking for pyproject.toml or setup.py
        config_file = _find_package_config()
        if config_file and config_file.exists():
            return _parse_config_file(config_file)

        # Return configured default value
        return FAILURE_ONLY_DEFAULT

    @staticmethod
    def get_file_config(file_path: str) -> Optional[bool]:
        """
        Get file-level failure-only configuration.

        Parses special comment at top of file:
        # logbook: log_on_failure_only=true

        Args:
            file_path: Absolute path to source file

        Returns:
            True/False if configured, None if not specified
        """
        # Check cache first
        if file_path in _file_configs:
            return _file_configs[file_path].get('log_on_failure_only')

        try:
            # Use _real_open to bypass test mocks that patch builtins.open
            # This prevents test infrastructure from interfering with config introspection
            with _real_open(file_path, 'r', encoding='utf-8') as f:
                # Only check first 10 lines for performance
                for line_num, line in enumerate(f):
                    if line_num >= 10:
                        break

                    line = line.strip()

                    # Look for special comment
                    if line.startswith('# logbook:'):
                        config = _parse_file_directive(line)
                        _file_configs[file_path] = config
                        return config.get('log_on_failure_only')

        except (IOError, OSError):
            # File not readable, skip file-level config
            pass

        # Cache negative result
        _file_configs[file_path] = {}
        return None

    @staticmethod
    def resolve(
        decorator_value: Optional[bool],
        file_path: Optional[str]
    ) -> bool:
        """
        Resolve final failure-only configuration using hierarchy.

        Args:
            decorator_value: Value from @auto_trace(log_on_failure_only=X)
            file_path: Source file path for file-level config

        Returns:
            True if failure-only mode should be enabled
        """
        # 1. Decorator level (highest precedence)
        if decorator_value is not None:
            return decorator_value

        # 2. File level
        if file_path:
            file_config = FailureOnlyConfig.get_file_config(file_path)
            if file_config is not None:
                return file_config

        # 3. Project level
        return FailureOnlyConfig.get_project_config()


def _find_package_config() -> Optional[Path]:
    """
    Find .logbook.conf in package root.

    Walks up from current working directory looking for package indicators
    (pyproject.toml, setup.py) and checks for .logbook.conf alongside them.

    Returns:
        Path to .logbook.conf if found, None otherwise
    """
    current = Path.cwd()

    # Walk up directory tree
    while current != current.parent:
        # Check for package indicators
        if (current / 'pyproject.toml').exists() or (current / 'setup.py').exists():
            config_file = current / '.logbook.conf'
            if config_file.exists():
                return config_file
            # Found package root but no config file
            return None

        current = current.parent

    return None


def _parse_config_file(config_path: Path) -> bool:
    """
    Parse .logbook.conf file for failure_only setting.

    Format:
        failure_only = true

    Args:
        config_path: Path to .logbook.conf file

    Returns:
        True if failure_only enabled, False otherwise
    """
    try:
        # Use _real_open to bypass test mocks
        with _real_open(config_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Look for failure_only setting
                if line.startswith('failure_only'):
                    # Format: failure_only = true
                    parts = line.split('=')
                    if len(parts) == 2:
                        value = parts[1].strip().lower()
                        return value in ('true', '1', 'yes', 'on')

    except (IOError, OSError):
        pass

    return False


def _parse_file_directive(line: str) -> Dict[str, bool]:
    """
    Parse file-level directive comment.

    Format: # logbook: log_on_failure_only=true

    Args:
        line: Comment line containing directive

    Returns:
        Dict with parsed configuration
    """
    config = {}

    # Remove '# logbook:' prefix
    directive = line.replace('# logbook:', '').strip()

    # Parse key=value pairs (comma-separated for future extensibility)
    for pair in directive.split(','):
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            key = key.strip()
            value = value.strip().lower()

            if key == 'log_on_failure_only':
                config[key] = value in ('true', '1', 'yes', 'on')

    return config


# Export
__all__ = ['FailureOnlyConfig']
