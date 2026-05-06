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
Hierarchical configuration with named context overrides.

Provides generic pattern for stage/phase/worker-specific config overrides.
"""
from typing import Dict, Any, Optional

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


class HierarchicalSettings:
    """
    Generic hierarchical config with context-specific overrides.

    Enables patterns like stage-specific timeouts, worker-specific batch sizes,
    or phase-specific retry counts - any named context that needs custom settings.

    Usage:
        config = {
            "max_iterations": 1,
            "timeout": 600,
            "stage_overrides": {
                "document_extraction": {
                    "max_iterations": 3,
                    "timeout": 300
                }
            }
        }

        settings = HierarchicalSettings(config, override_key="stage_overrides")
        settings.get("max_iterations")  # Returns: 1
        settings.get("max_iterations", context="document_extraction")  # Returns: 3
    """

    @auto_trace(logger)
    def __init__(self, config: Dict[str, Any], override_key: str = "overrides"):
        """
        Initialize hierarchical settings.

        Args:
            config: Configuration dictionary
            override_key: Key name for context overrides (e.g., "stage_overrides", "worker_overrides")
        """
        try:
            self.config = config
            self.override_key = override_key
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get(self, key: str, context: Optional[str] = None, default: Any = None) -> Any:
        """
        Get configuration value with optional context-specific override.

        Lookup order:
        1. If context provided: check config[override_key][context][key]
        2. Fall back to: config[key]
        3. Fall back to: default

        Args:
            key: Configuration key
            context: Optional context name (stage, phase, worker, etc.)
            default: Default value if key not found

        Returns:
            Configuration value (context-specific if available, else global)

        Examples:
            # Global value
            >>> settings.get("timeout")
            600

            # Context override
            >>> settings.get("timeout", context="extraction")
            300

            # Fallback to global when context has no override for key
            >>> settings.get("max_retries", context="extraction")
            3
        """
        try:
            if context:
                # Check context-specific override first
                overrides = self.config.get(self.override_key, {})
                context_config = overrides.get(context, {})
                if key in context_config:
                    result = context_config[key]
                    return result

            # Fall back to global setting
            result = self.config.get(key, default)
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_all(self) -> Dict[str, Any]:
        """
        Get complete configuration dictionary.

        Returns:
            Copy of entire configuration
        """
        try:
            result = self.config.copy()
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def get_context_config(self, context: str) -> Dict[str, Any]:
        """
        Get all overrides for a specific context.

        Args:
            context: Context name

        Returns:
            Context-specific overrides (empty dict if none)

        Example:
            >>> settings.get_context_config("extraction")
            {'max_iterations': 3, 'timeout': 300}
        """
        try:
            overrides = self.config.get(self.override_key, {})
            result = overrides.get(context, {})
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise

    @auto_trace(logger)
    def list_contexts(self) -> list[str]:
        """
        List all defined context names.

        Returns:
            List of context names that have overrides

        Example:
            >>> settings.list_contexts()
            ['document_extraction', 'problem_definition']
        """
        try:
            overrides = self.config.get(self.override_key, {})
            result = list(overrides.keys())
            return result
        except Exception as e:
            logger.log_error(error=e)
            raise
