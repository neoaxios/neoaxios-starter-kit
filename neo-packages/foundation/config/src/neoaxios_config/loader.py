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
Configuration loading with 7-layer override hierarchy.

This is the AUTHORITATIVE implementation of NeoAxios config loading.
ALL packages import and use this class to ensure consistent behavior.

Configuration Override Priority (lowest → highest):
  1. Package bundled defaults
  2. System-wide config (/etc/neoaxios/)
  3. User config (~/.config/neoaxios/)
  4. Project workspace (./config/packages/)
  5. Environment-specific (./config/environments/{NEO_ENV}/)
  6. Local overrides (./.neoaxios.local.yaml)
  7. Environment variables
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from neoaxios_logging import get_telemetry, auto_trace

from .paths import ConfigPathResolver
from .merger import deep_merge
from .env_overrides import apply_env_overrides_recursive, expand_env_vars

logger = get_telemetry(__name__)


class ConfigLoader:
    """
    Multi-layer configuration loader with override hierarchy.

    This is the canonical implementation used by all NeoAxios packages.
    Changes to the priority order here automatically apply to all packages.

    Supports context-aware config loading where project/environment/local configs
    are searched relative to a context_dir rather than the current working directory.
    This is essential for:
    - Tests that create configs in temporary directories
    - Applications with a base_dir different from the process cwd
    - Multiple applications running from the same cwd with different configs
    """

    @auto_trace(logger)
    def __init__(
        self,
        package_name: str,
        env_prefix: str = "NEO",
        context_dir: Optional[Path] = None
    ):
        """
        Initialize config loader for a package.

        Args:
            package_name: Name of package (e.g., "logging", "neoaxios_fastapi_kit")
            env_prefix: Environment variable prefix (e.g., "NEO", "MYAPP")
            context_dir: Optional directory to use as search root for project/environment/local
                        configs. If None, uses current working directory.
                        Use this when the application has a base_dir that differs from cwd.

        Example:
            >>> # Default: search from cwd
            >>> loader = ConfigLoader("neoaxios_fastapi_kit")

            >>> # Context-aware: search from application's base_dir
            >>> loader = ConfigLoader("neoaxios_fastapi_kit", context_dir=Path("/app/my-project"))
        """
        try:
            self.package_name = package_name
            self.env_prefix = env_prefix
            self.context_dir = context_dir
            self.resolver = ConfigPathResolver(package_name, context_dir=context_dir)
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def load(
        self,
        bundled_defaults_path: Optional[Path] = None,
        explicit_override_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Load config from all layers in PRIORITY ORDER.

        This is the CANONICAL DEFINITION of the priority order.
        Changes here automatically apply to all packages.

        Priority (lowest → highest):
          1. Package bundled defaults (fallback)
          2. System-wide config (/etc/neoaxios/)
          3. User config (~/.config/neoaxios/)
          4. Project workspace (./config/packages/)
          5. Environment-specific (./config/environments/{NEO_ENV}/)
          6. Local overrides (./.neoaxios.local.yaml)
          7. Explicit override path (NEW - runtime override)
          8. Environment variables (highest)

        Args:
            bundled_defaults_path: Path to package's bundled defaults.yaml
            explicit_override_path: Path to runtime override config (e.g., --config custom.yaml)

        Returns:
            Merged configuration dict with all overrides applied

        Example:
            >>> loader = ConfigLoader("logging", env_prefix="NEO")
            >>> bundled = Path(__file__).parent / "defaults.yaml"
            >>> config = loader.load(bundled_defaults_path=bundled)

            >>> # With explicit override (e.g., CLI --config custom.yaml)
            >>> custom = Path("/path/to/custom.yaml")
            >>> config = loader.load(bundled_defaults_path=bundled, explicit_override_path=custom)
        """
        try:
            config: Dict[str, Any] = {}

            # Layer 1: Package bundled defaults (lowest priority)
            if bundled_defaults_path and bundled_defaults_path.exists():
                config = self._load_yaml(bundled_defaults_path)

            # Layer 2: System-wide config
            if system_config := self.resolver.get_system_config():
                config = deep_merge(config, self._load_yaml(system_config))

            # Layer 3: User config
            if user_config := self.resolver.get_user_config():
                config = deep_merge(config, self._load_yaml(user_config))

            # Layer 4: Project workspace
            if project_config := self.resolver.get_project_config():
                config = deep_merge(config, self._load_yaml(project_config))

            # Layer 5: Environment-specific
            if env_config := self.resolver.get_environment_config():
                config = deep_merge(config, self._load_yaml(env_config))

            # Layer 6: Local overrides (.neoaxios.local.yaml)
            if local_config := self.resolver.get_local_override():
                # Extract this package's section from multi-package file
                local_data = self._load_yaml(local_config)
                if self.package_name in local_data:
                    config = deep_merge(config, local_data[self.package_name])

            # Layer 7: Explicit override path (NEW - runtime override)
            # This allows runtime config specification (e.g., CLI --config custom.yaml)
            # If user explicitly provides a config path, it must exist (fail fast on typos/missing files)
            if explicit_override_path:
                if not explicit_override_path.exists():
                    raise FileNotFoundError(
                        f"Explicit config file not found: {explicit_override_path}"
                    )
                try:
                    config = deep_merge(config, self._load_yaml(explicit_override_path))
                except Exception as e:
                    # Include path context in error message for debugging
                    raise RuntimeError(
                        f"Failed to load explicit override config from {explicit_override_path}: {e}"
                    ) from e

            # Layer 8: Environment variables (highest priority)
            self._apply_env_overrides(config)

            # Expand ${VAR} placeholders after all layers merged
            # This allows secrets to be referenced from environment without committing to YAML
            expand_env_vars(config)

            return config
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """
        Load and parse YAML file.

        Args:
            path: Path to YAML file

        Returns:
            Parsed YAML as dict (empty dict if file is empty)
        """
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
                result = data if data is not None else {}
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def _apply_env_overrides(self, config: Dict[str, Any]) -> None:
        """
        Apply environment variable overrides (Layer 7).

        Modifies config dict in-place.

        Args:
            config: Configuration dict to modify
        """
        try:
            apply_env_overrides_recursive(
                config,
                env_prefix=self.env_prefix,
                current_path=[],
                deprecated_mappings=None,
                overrides_applied=None
            )
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_config_sources(
        self,
        bundled_defaults_path: Optional[Path] = None,
        explicit_override_path: Optional[Path] = None
    ) -> Dict[str, Optional[Path]]:
        """
        Get all config sources for debugging/diagnostics.

        Args:
            bundled_defaults_path: Path to package's bundled defaults.yaml
            explicit_override_path: Path to runtime override config

        Returns:
            Dict mapping layer name to path (or None if not found)

        Example:
            >>> loader = ConfigLoader("logging")
            >>> sources = loader.get_config_sources(Path("defaults.yaml"))
            >>> print(sources)
            {
                'context_dir': None,
                'bundled': PosixPath('defaults.yaml'),
                'system': None,
                'user': PosixPath('/home/alice/.config/neoaxios/logging.yaml'),
                'project': PosixPath('/home/alice/projects/config/packages/logging.yaml'),
                'environment': None,
                'local': None,
                'explicit_override': None
            }

            >>> # With context_dir
            >>> loader = ConfigLoader("logging", context_dir=Path("/app/base"))
            >>> sources = loader.get_config_sources(Path("defaults.yaml"))
            >>> print(sources['context_dir'])
            PosixPath('/app/base')
        """
        sources = {
            "context_dir": self.context_dir,
            "bundled": bundled_defaults_path if bundled_defaults_path and bundled_defaults_path.exists() else None,
            "system": self.resolver.get_system_config(),
            "user": self.resolver.get_user_config(),
            "project": self.resolver.get_project_config(),
            "environment": self.resolver.get_environment_config(),
            "local": self.resolver.get_local_override(),
            "explicit_override": explicit_override_path if explicit_override_path and explicit_override_path.exists() else None,
        }
        return sources
