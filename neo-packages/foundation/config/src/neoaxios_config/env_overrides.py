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
Environment variable override utilities for YAML configuration.

This module provides algorithmic environment variable override support.
Environment variable names are computed from YAML paths automatically.

Design Principle:
    YAML path: execution.max_iterations
    Env var:   NEO_EXECUTION_MAX_ITERATIONS

    The mapping is computed, not maintained. Adding a new YAML setting automatically
    enables its environment variable override - no code changes required.
"""

import os
from typing import Dict, Any, List, Optional

# Mandatory telemetry integration
from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger)
def yaml_path_to_env_var(path: List[str], prefix: str) -> str:
    """
    Convert YAML path to environment variable name.

    Algorithm:
        ["execution", "max_iterations"] + "NEO" → "NEO_EXECUTION_MAX_ITERATIONS"

    Args:
        path: List of YAML keys representing the path (e.g., ["execution", "max_iterations"])
        prefix: Environment variable prefix (e.g., "NEO", "MYAPP")

    Returns:
        Environment variable name in uppercase with underscores

    Examples:
        >>> yaml_path_to_env_var(["execution", "max_iterations"], "NEO")
        'NEO_EXECUTION_MAX_ITERATIONS'
        >>> yaml_path_to_env_var(["cache", "compression_enabled"], "MYAPP")
        'MYAPP_CACHE_COMPRESSION_ENABLED'
    """
    try:
        path_str = "_".join(path)
        result = f"{prefix}_{path_str}".upper()
        return result
    except Exception as e:
        logger.log_error(error=e)
        raise


@auto_trace(logger)
def convert_value(str_value: str, target_type: type) -> Any:
    """
    Convert string environment variable value to target type.

    Type inference is based on the YAML default value type.

    Args:
        str_value: String value from environment variable
        target_type: Target type (from YAML default)

    Returns:
        Converted value

    Raises:
        ValueError: If conversion fails
    """
    try:
        if target_type == bool:
            result = str_value.lower() in ("true", "1", "yes", "on")
        elif target_type == int:
            result = int(str_value)
        elif target_type == float:
            result = float(str_value)
        elif target_type == list:
            # Comma-separated list
            result = [item.strip() for item in str_value.split(",") if item.strip()]
        elif target_type == str:
            result = str_value
        else:
            # Unknown type - return as string
            result = str_value

        return result
    except Exception as e:
        logger.log_error(error=e)
        raise


# Valid type annotations for ${VAR:-default:type} syntax
VALID_TYPE_ANNOTATIONS = frozenset({"int", "float", "bool", "str", "list"})


@auto_trace(logger)
def _parse_interpolation(content: str) -> tuple:
    """
    Parse ${VAR:-default:type} interpolation syntax.

    Supports two forms:
    - "VAR" -> (var_name, None, None)
    - "VAR:-default:type" -> (var_name, default, type)

    Args:
        content: The content between ${ and } (e.g., "NEO_LLM_TIMEOUT:-120:int")

    Returns:
        Tuple of (var_name, default_value, explicit_type)
        - var_name: Environment variable name
        - default_value: Default value string, or None if not provided
        - explicit_type: Type annotation ("int", "float", "bool", "str", "list"), or None

    Examples:
        >>> _parse_interpolation("VAR")
        ('VAR', None, None)
        >>> _parse_interpolation("VAR:-4000:int")
        ('VAR', '4000', 'int')
        >>> _parse_interpolation("URL:-http://localhost:8080:str")
        ('URL', 'http://localhost:8080', 'str')
    """
    try:
        # No default value syntax
        if ":-" not in content:
            return (content, None, None)

        var_name, rest = content.split(":-", 1)

        # Check for :type suffix (must be a valid type annotation)
        # Handle URLs and other values with colons by checking from the end
        if ":" in rest:
            parts = rest.rsplit(":", 1)
            potential_type = parts[1]
            if potential_type in VALID_TYPE_ANNOTATIONS:
                return (var_name, parts[0], potential_type)

        # No explicit type found
        return (var_name, rest, None)
    except Exception as e:
        logger.log_error(error=e, content=content)
        raise


@auto_trace(logger)
def _convert_with_type(value: str, explicit_type: str) -> Any:
    """
    Convert a string value to the specified type (deterministic).

    Args:
        value: String value to convert
        explicit_type: Type name ("int", "float", "bool", "str", "list")

    Returns:
        Converted value

    Raises:
        ValueError: If conversion fails
        KeyError: If explicit_type is not recognized
    """
    try:
        if explicit_type == "int":
            return int(value)
        elif explicit_type == "float":
            return float(value)
        elif explicit_type == "bool":
            return value.lower() in ("true", "1", "yes", "on")
        elif explicit_type == "str":
            return value
        elif explicit_type == "list":
            return [item.strip() for item in value.split(",") if item.strip()]
        else:
            raise KeyError(f"Unknown type annotation: {explicit_type}")
    except Exception as e:
        logger.log_error(
            error=e,
            value=value,
            explicit_type=explicit_type,
            message=f"Failed to convert '{value}' to type '{explicit_type}'"
        )
        raise


@auto_trace(logger)
def expand_env_vars(obj: Any) -> None:
    """
    Recursively expand ${VAR}, ${VAR:-default:type} in config.

    Used for secrets management - allows API keys and other secrets to be
    referenced from environment variables without committing them to YAML files.

    Supports two syntaxes:
    - ${VAR} - expands to env var value (string), keeps original if not set
    - ${VAR:-default:type} - expands with explicit type (required when using defaults)

    Type annotations (required for defaults):
    - ${MAX_TOKENS:-4000:int} → returns int 4000 (or int from env var)
    - ${TIMEOUT:-1.5:float} → returns float 1.5 (or float from env var)
    - ${DEBUG:-false:bool} → returns bool False (or bool from env var)
    - ${MODEL:-gpt-4:str} → returns string "gpt-4" (or string from env var)
    - ${TAGS:-a,b,c:list} → returns list ["a", "b", "c"] (comma-separated)

    Modifies the object in-place.

    Args:
        obj: Configuration object (dict or list) to expand

    Raises:
        ValueError: If ${VAR:-default} syntax is used without explicit type annotation

    Example:
        >>> config = {"max_tokens": "${MAX_TOKENS:-4000:int}", "model": "${MODEL:-gpt-4:str}"}
        >>> expand_env_vars(config)
        >>> config["max_tokens"]
        4000
        >>> config["model"]
        'gpt-4'
    """
    try:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                    # Extract content between ${ and }
                    content = value[2:-1]

                    # Parse the interpolation syntax
                    var_name, default_value, explicit_type = _parse_interpolation(content)

                    # Get environment variable value
                    env_value = os.getenv(var_name)

                    if env_value is not None:
                        # Env var is set - use it
                        if explicit_type:
                            obj[key] = _convert_with_type(env_value, explicit_type)
                        else:
                            # No type annotation - keep as string
                            obj[key] = env_value
                    elif default_value is not None:
                        # Use default value - explicit type is required
                        if explicit_type:
                            obj[key] = _convert_with_type(default_value, explicit_type)
                        else:
                            raise ValueError(
                                f"Missing type annotation for '{value}'. "
                                f"Use ${{​{var_name}:-{default_value}:type}} where type is one of: "
                                f"{', '.join(sorted(VALID_TYPE_ANNOTATIONS))}"
                            )
                    # else: no env var, no default - keep original ${VAR} string

                elif isinstance(value, (dict, list)):
                    expand_env_vars(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    expand_env_vars(item)
    except Exception as e:
        logger.log_error(error=e)
        raise


@auto_trace(logger)
def apply_env_overrides_recursive(
    config: Dict[str, Any],
    env_prefix: str,
    current_path: List[str],
    deprecated_mappings: Optional[Dict[str, str]] = None,
    overrides_applied: Optional[List[str]] = None
) -> None:
    """
    Recursively walk YAML config and apply environment variable overrides.

    For each YAML path, computes the corresponding environment variable name
    and checks if it's set. If set, overrides the YAML value with type-safe
    conversion.

    Args:
        config: Configuration dictionary to modify in-place
        env_prefix: Environment variable prefix (e.g., "NEO")
        current_path: Current path in YAML structure (for recursion)
        deprecated_mappings: Optional dict mapping old env var → new env var
        overrides_applied: Optional list to track which overrides were applied

    Side Effects:
        Modifies config dict in-place with environment variable overrides
    """
    try:
        for key, value in list(config.items()):
            path = current_path + [key]

            # Generate standard env var name from YAML path
            env_var = yaml_path_to_env_var(path, env_prefix)

            # Check for override (new name first)
            env_value = os.getenv(env_var)
            deprecated_var_used = None

            # Check deprecated mappings
            if not env_value and deprecated_mappings:
                for old_var, new_var in deprecated_mappings.items():
                    if new_var == env_var and os.getenv(old_var):
                        env_value = os.getenv(old_var)
                        deprecated_var_used = old_var
                        break

            if env_value is not None:
                # Apply override with type-safe conversion
                try:
                    converted_value = convert_value(env_value, type(value))
                    config[key] = converted_value

                    if overrides_applied is not None:
                        override_str = f"{env_var}={env_value}"
                        if deprecated_var_used:
                            override_str += f" (via deprecated {deprecated_var_used})"
                        overrides_applied.append(override_str)

                    # Log deprecation warning
                    if deprecated_var_used:
                        logger.warning(
                            f"Deprecated variable in use: {deprecated_var_used}",
                            deprecated_var=deprecated_var_used,
                            new_var=env_var,
                            removal_version="v3.0.0"
                        )

                except (ValueError, TypeError) as e:
                    logger.error(
                        f"Failed to convert environment variable {env_var}={env_value}",
                        error=str(e),
                        env_var=env_var,
                        value=env_value,
                        expected_type=type(value).__name__
                    )

            elif isinstance(value, dict):
                # Recurse into nested dictionaries
                apply_env_overrides_recursive(
                    value,
                    env_prefix,
                    path,
                    deprecated_mappings,
                    overrides_applied
                )
    except Exception as e:
        logger.log_error(error=e)
        raise


@auto_trace(logger)
def load_config_with_env_overrides(
    yaml_path: "Path",
    env_prefix: str = "NEO",
    deprecated_mappings: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Load YAML config file and apply environment variable overrides.

    This is a convenience wrapper around apply_env_overrides_recursive for simple use cases.

    Args:
        yaml_path: Path to YAML configuration file
        env_prefix: Environment variable prefix (default: "NEO")
        deprecated_mappings: Optional dict mapping old env var → new env var

    Returns:
        Configuration dictionary with env var overrides applied

    Raises:
        FileNotFoundError: If YAML file doesn't exist

    Example:
        >>> config = load_config_with_env_overrides(Path("config.yaml"))
        >>> # With NEO_EXECUTION_MAX_ITERATIONS=5 set:
        >>> assert config["execution"]["max_iterations"] == 5
    """
    import yaml
    from pathlib import Path

    try:
        yaml_path = Path(yaml_path)
        if not yaml_path.exists():
            logger.log_error(error=FileNotFoundError(f"Config file not found: {yaml_path}"))
            raise FileNotFoundError(f"Config file not found: {yaml_path}")

        with open(yaml_path) as f:
            config = yaml.safe_load(f) or {}

        apply_env_overrides_recursive(
            config,
            env_prefix=env_prefix,
            current_path=[],
            deprecated_mappings=deprecated_mappings
        )

        return config
    except Exception as e:
        logger.log_error(error=e)
        raise


@auto_trace(logger)
def discover_available_overrides(
    yaml_path: "Path",
    env_prefix: str = "NEO"
) -> List[tuple]:
    """
    Discover all available environment variable overrides for a YAML config file.

    Walks the YAML structure and returns a list of (env_var, yaml_path, type, default_value)
    tuples for each overrideable setting.

    Args:
        yaml_path: Path to YAML configuration file
        env_prefix: Environment variable prefix (default: "NEO")

    Returns:
        List of tuples: (env_var_name, yaml_path_string, type_name, default_value)
        Returns empty list if file doesn't exist

    Example:
        >>> overrides = discover_available_overrides(Path("config.yaml"))
        >>> for env_var, path, type_name, default in overrides:
        ...     print(f"{env_var} -> {path} ({type_name}): {default}")
    """
    import yaml
    from pathlib import Path

    try:
        yaml_path = Path(yaml_path)
        if not yaml_path.exists():
            return []

        try:
            with open(yaml_path) as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            return []

        overrides = []

        def walk_config(data: Dict[str, Any], path: List[str]):
            """Recursively walk config and collect overrideable values."""
            for key, value in data.items():
                current_path = path + [key]

                if isinstance(value, dict):
                    # Recurse into nested dicts
                    walk_config(value, current_path)
                else:
                    # This is a leaf value - can be overridden
                    env_var = yaml_path_to_env_var(current_path, env_prefix)
                    yaml_path_str = ".".join(current_path)
                    type_name = type(value).__name__
                    overrides.append((env_var, yaml_path_str, type_name, value))

        walk_config(config, [])
        return overrides
    except Exception as e:
        logger.log_error(error=e)
        raise
