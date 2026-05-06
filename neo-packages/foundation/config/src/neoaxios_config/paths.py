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

"""Configuration file path resolution for multi-user environments.

This module provides platform-aware path resolution following XDG Base Directory
specification and platform conventions. Supports multi-user shared machines with
proper separation between system, user, and project configurations.
"""

import os
import platform
from pathlib import Path
from typing import Optional

from neoaxios_logging import get_telemetry, auto_trace, TraceDisabledReason

logger = get_telemetry(__name__)


class ConfigPathResolver:
    """
    Resolve config file locations following XDG Base Directory standard.

    Supports multi-user shared machines and follows platform conventions:
    - Linux: XDG Base Directory spec (~/.config, /etc)
    - macOS: ~/Library/Application Support
    - Windows: %APPDATA%, %PROGRAMDATA%

    The resolver can operate in two modes:
    - Default: Search from current working directory (cwd)
    - Context-aware: Search from a specified context_dir (e.g., application base_dir)

    Context-aware mode is useful when:
    - Tests create configs in temporary directories
    - Applications have a base_dir different from cwd
    - Multiple applications run from the same cwd with different configs
    """

    @auto_trace(logger)
    def __init__(self, package_name: str, context_dir: Optional[Path] = None):
        """
        Initialize path resolver for a package.

        Args:
            package_name: Name of the package (e.g., "logging", "neoaxios_fastapi_kit")
            context_dir: Optional directory to use as search root for project/environment/local
                        configs. If None, uses current working directory.
                        This enables applications to load configs relative to their base_dir
                        rather than the process cwd.
        """
        try:
            self.package_name = package_name
            self.config_filename = f"{package_name}.yaml"
            self.context_dir = context_dir
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _get_search_root(self) -> Path:
        """Get the root directory for project/environment/local config searches."""
        return self.context_dir if self.context_dir else Path.cwd()

    @auto_trace(logger)
    def get_system_config(self) -> Optional[Path]:
        """
        Layer 2: System-wide configuration.

        Location:
          - Linux/Mac: /etc/neoaxios/{package}.yaml
          - Windows: C:\\ProgramData\\NeoAxios\\{package}.yaml

        Used for: Shared defaults across all users on machine

        Returns:
            Path to system config if exists, None otherwise
        """
        try:
            if platform.system() == "Windows":
                base = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData"))
                path = base / "NeoAxios" / self.config_filename
            else:
                # Linux and macOS both use /etc
                path = Path("/etc/neoaxios") / self.config_filename

            result = path if path.exists() else None
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_user_config(self) -> Optional[Path]:
        """
        Layer 3: User-specific configuration.

        Location:
          - Linux: ~/.config/neoaxios/{package}.yaml (XDG_CONFIG_HOME)
          - Mac: ~/Library/Application Support/NeoAxios/{package}.yaml
          - Windows: %APPDATA%\\NeoAxios\\{package}.yaml

        Used for: User's personal preferences

        Returns:
            Path to user config if exists, None otherwise
        """
        try:
            if platform.system() == "Darwin":  # macOS
                base = Path.home() / "Library" / "Application Support" / "NeoAxios"
            elif platform.system() == "Windows":
                appdata = os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming"))
                base = Path(appdata) / "NeoAxios"
            else:  # Linux/Unix
                xdg_config = os.getenv("XDG_CONFIG_HOME", str(Path.home() / ".config"))
                base = Path(xdg_config) / "neoaxios"

            path = base / self.config_filename
            result = path if path.exists() else None
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_project_config(self) -> Optional[Path]:
        """
        Layer 4: Project workspace configuration.

        Location: ./config/packages/{package}.yaml

        Searches up the directory tree from context_dir (or cwd if not set)
        to find the project root (identified by presence of config/packages/).

        Used for: Team-shared project settings (typically in git)

        Returns:
            Path to project config if found, None otherwise
        """
        try:
            # Search up directory tree for config/packages/
            current = self._get_search_root()
            for parent in [current] + list(current.parents):
                path = parent / "config" / "packages" / self.config_filename
                if path.exists():
                    return path
            return None
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_environment_config(self) -> Optional[Path]:
        """
        Layer 5: Environment-specific configuration.

        Location: ./config/environments/{NEO_ENV}/{package}.yaml

        The environment is determined by NEO_ENV environment variable
        (defaults to "development" if not set).

        Searches up the directory tree from context_dir (or cwd if not set).

        Used for: dev/ci/staging/production environment overrides

        Returns:
            Path to environment config if found, None otherwise
        """
        try:
            env = os.getenv("NEO_ENV", "development")

            # Search up directory tree for config/environments/{env}/
            current = self._get_search_root()
            for parent in [current] + list(current.parents):
                path = parent / "config" / "environments" / env / self.config_filename
                if path.exists():
                    return path
            return None
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_local_override(self) -> Optional[Path]:
        """
        Layer 6: Local developer overrides (gitignored).

        Location: ./.neoaxios.local.yaml

        Searches up the directory tree from context_dir (or cwd if not set).

        Note: This file contains ALL packages in a single file (not per-package).
        The caller must extract the relevant section for this package.

        Used for: Developer's temporary local settings

        Returns:
            Path to local override file if found, None otherwise
        """
        try:
            # Search up directory tree for .neoaxios.local.yaml
            current = self._get_search_root()
            for parent in [current] + list(current.parents):
                path = parent / ".neoaxios.local.yaml"
                if path.exists():
                    return path
            return None
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_all_config_paths(self) -> dict[str, Optional[Path]]:
        """
        Get all configuration paths for debugging/diagnostics.

        Returns:
            Dict mapping layer name to path (or None if not found),
            plus context_dir if set
        """
        try:
            result = {
                "context_dir": self.context_dir,
                "system": self.get_system_config(),
                "user": self.get_user_config(),
                "project": self.get_project_config(),
                "environment": self.get_environment_config(),
                "local": self.get_local_override(),
            }
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise
