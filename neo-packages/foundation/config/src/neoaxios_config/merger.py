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

"""Deep merge utilities for layered configuration.

This module provides utilities for merging multiple configuration layers,
ensuring higher-priority layers properly override lower-priority ones while
preserving nested structure.
"""

from typing import Dict, Any

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger)
def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two configuration dictionaries.

    Override values replace base values. Nested dicts are merged recursively.
    Lists, strings, and other types are completely replaced (not merged).

    Args:
        base: Base configuration (lower priority)
        override: Override configuration (higher priority)

    Returns:
        Merged configuration dict

    Examples:
        >>> base = {"a": 1, "b": {"x": 10, "y": 20}}
        >>> override = {"b": {"y": 99}, "c": 3}
        >>> deep_merge(base, override)
        {'a': 1, 'b': {'x': 10, 'y': 99}, 'c': 3}

        >>> base = {"list": [1, 2, 3], "value": "old"}
        >>> override = {"list": [4, 5], "value": "new"}
        >>> deep_merge(base, override)
        {'list': [4, 5], 'value': 'new'}

    Note:
        The base dict is not modified. A new dict is returned.
    """
    try:
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge nested dicts
                result[key] = deep_merge(result[key], value)
            else:
                # Override value completely (works for scalars, lists, etc.)
                result[key] = value

        return result
    except Exception as e:
        logger.log_error(error=e)
        raise


@auto_trace(logger)
def merge_multiple(configs: list[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge multiple configuration dictionaries in priority order.

    Configurations are merged left-to-right, with later configs having
    higher priority.

    Args:
        configs: List of configuration dicts in priority order (low to high)

    Returns:
        Merged configuration dict

    Examples:
        >>> layer1 = {"a": 1, "b": 2}
        >>> layer2 = {"b": 20, "c": 3}
        >>> layer3 = {"c": 30, "d": 4}
        >>> merge_multiple([layer1, layer2, layer3])
        {'a': 1, 'b': 20, 'c': 30, 'd': 4}
    """
    try:
        if not configs:
            return {}

        result = configs[0].copy()
        for config in configs[1:]:
            result = deep_merge(result, config)

        return result
    except Exception as e:
        logger.log_error(error=e)
        raise
