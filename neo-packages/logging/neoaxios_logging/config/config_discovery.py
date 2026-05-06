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
Configuration discovery module for telemetry.

This module provides functionality to discover test framework configuration files
in a project, supporting multiple formats and locations.
"""

import configparser
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


class ConfigDiscovery:
    """Discover and parse test framework configuration files."""

    # Default search paths for pytest configuration
    PYTEST_CONFIG_SEARCH_PATHS = [
        "pytest.ini",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "tests/pytest.ini",
        "test/pytest.ini",
    ]

    # Default search paths for other test frameworks
    UNITTEST_CONFIG_SEARCH_PATHS = [
        ".unittestrc",
        "setup.cfg",
    ]

    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize config discovery.

        Args:
            project_root: Root directory of the project. Defaults to current directory.
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()

    def find_pytest_config(self) -> Optional[Tuple[Path, str]]:
        """
        Find pytest configuration file in the project.

        Returns:
            Tuple of (config_path, config_type) or None if not found
            config_type is one of: 'ini', 'toml', 'cfg'
        """
        for config_name in self.PYTEST_CONFIG_SEARCH_PATHS:
            config_path = self.project_root / config_name

            if config_path.exists() and config_path.is_file():
                # Determine config type
                if config_name.endswith(".ini"):
                    config_type = "ini"
                elif config_name.endswith(".toml"):
                    config_type = "toml"
                elif config_name.endswith(".cfg") or config_name == "tox.ini":
                    config_type = "cfg"
                else:
                    continue

                # Verify it contains pytest configuration
                if self._has_pytest_config(config_path, config_type):
                    return config_path, config_type

        return None

    def _has_pytest_config(self, config_path: Path, config_type: str) -> bool:
        """
        Check if a config file contains pytest configuration.

        Args:
            config_path: Path to the configuration file
            config_type: Type of config file ('ini', 'toml', 'cfg')

        Returns:
            True if pytest configuration found
        """
        try:
            if config_type in ("ini", "cfg"):
                config = configparser.ConfigParser()
                config.read(config_path)

                # Check for pytest sections
                return any(
                    section in config for section in ["pytest", "tool:pytest", "tool.pytest"]
                )

            elif config_type == "toml" and tomllib:
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)

                # Check for pytest configuration in toml
                if "tool" in data:
                    if "pytest" in data["tool"]:
                        # Check both old and new style
                        pytest_data = data["tool"]["pytest"]
                        if isinstance(pytest_data, dict):
                            return True
                    return False
                return False

        except Exception:
            pass

        return False

    def parse_pytest_config(self, config_path: Path, config_type: str) -> Dict[str, Any]:
        """
        Parse pytest configuration from a file.

        Args:
            config_path: Path to the configuration file
            config_type: Type of config file ('ini', 'toml', 'cfg')

        Returns:
            Dictionary of pytest configuration options
        """
        pytest_config = {}

        try:
            if config_type in ("ini", "cfg"):
                config = configparser.ConfigParser()
                config.read(config_path)

                # Look for pytest configuration
                for section in ["pytest", "tool:pytest", "tool.pytest"]:
                    if section in config:
                        pytest_config.update(dict(config[section]))
                        break

            elif config_type == "toml" and tomllib:
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)

                # Extract pytest configuration
                if "tool" in data and "pytest" in data["tool"]:
                    pytest_data = data["tool"]["pytest"]
                    # Handle both direct config and ini_options style
                    if "ini_options" in pytest_data:
                        pytest_config = pytest_data["ini_options"]
                    else:
                        pytest_config = pytest_data

        except Exception as e:
            # Log error but don't fail
            pytest_config["_error"] = str(e)

        return pytest_config

    def get_test_paths(self, pytest_config: Dict[str, Any]) -> List[str]:
        """
        Extract test paths from pytest configuration.

        Args:
            pytest_config: Parsed pytest configuration

        Returns:
            List of test paths
        """
        test_paths = []

        # Check testpaths option
        if "testpaths" in pytest_config:
            paths = pytest_config["testpaths"]
            if isinstance(paths, str):
                # INI format: space or newline separated
                test_paths.extend(paths.split())
            elif isinstance(paths, list):
                # TOML format: already a list
                test_paths.extend(paths)

        # Default to common test directories if none specified
        if not test_paths:
            for default_dir in ["tests", "test"]:
                if (self.project_root / default_dir).exists():
                    test_paths.append(default_dir)

        return test_paths

    def get_pytest_options(self, pytest_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant pytest options for telemetry.

        Args:
            pytest_config: Parsed pytest configuration

        Returns:
            Dictionary of relevant options
        """
        options = {}

        # Extract markers
        if "markers" in pytest_config:
            markers = pytest_config["markers"]
            if isinstance(markers, str):
                # INI format
                options["markers"] = [m.strip() for m in markers.split("\n") if m.strip()]
            elif isinstance(markers, list):
                # TOML format
                options["markers"] = markers

        # Extract addopts
        if "addopts" in pytest_config:
            options["addopts"] = pytest_config["addopts"]

        # Extract python_files patterns
        if "python_files" in pytest_config:
            options["python_files"] = pytest_config["python_files"]

        # Extract python_classes patterns
        if "python_classes" in pytest_config:
            options["python_classes"] = pytest_config["python_classes"]

        # Extract python_functions patterns
        if "python_functions" in pytest_config:
            options["python_functions"] = pytest_config["python_functions"]

        return options

    def find_all_test_configs(self) -> Dict[str, Tuple[Path, str]]:
        """
        Find all test framework configuration files.

        Returns:
            Dictionary mapping framework name to (config_path, config_type)
        """
        configs = {}

        # Find pytest config
        pytest_config = self.find_pytest_config()
        if pytest_config:
            configs["pytest"] = pytest_config

        # Could be extended for other frameworks
        # unittest_config = self.find_unittest_config()
        # if unittest_config:
        #     configs['unittest'] = unittest_config

        return configs
