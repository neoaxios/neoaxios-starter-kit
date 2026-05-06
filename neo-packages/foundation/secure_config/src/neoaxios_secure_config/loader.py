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

"""Configuration loader with value resolution.

Loads configuration from JSON and YAML files, resolves value sources,
and validates against Pydantic schemas.

Security Note: Uses file descriptor-based operations to eliminate TOCTOU
(Time-of-Check-Time-of-Use) vulnerabilities. The file is opened once with
secure flags, permissions are checked on the open descriptor, and the same
descriptor is used to read the file contents. YAML parsing uses
yaml.safe_load exclusively to prevent code execution via unsafe tags.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Type, TypeVar

import yaml

from pydantic import ValidationError
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_config.errors import ConfigParseError, ConfigPermissionError, ConfigValidationError
from neoaxios_secure_config.limits import get_max_config_size
from neoaxios_secure_config.resolver import extract_env_vars, resolve_all_values
from neoaxios_secure_config.schema import ExtractedEnvVars, SecureSchema
from neoaxios_secure_config.validator import (
    validate_config_permissions_fd,
    validate_file_size_fd,
    validate_path_safety,
)

# Reserved key for declaring env vars to extract
EXTRACT_ENV_VARS_KEY = "extract_env_vars"

logger = get_telemetry(__name__)

T = TypeVar("T", bound=SecureSchema)


@dataclass(frozen=True)
class LoadedConfig:
    """Result of loading a secure configuration.

    Contains both the validated schema-based config and any
    extracted environment variables declared in the config file.

    Attributes:
        config: The validated configuration instance (schema-based)
        extracted_env_vars: Environment variables declared in extract_env_vars
    """

    config: SecureSchema
    extracted_env_vars: ExtractedEnvVars


@auto_trace(logger)
def validate_file_size(path: Path, max_size: int, file_type: str) -> None:
    """Validate file does not exceed maximum size.

    This function provides backward compatibility while using secure
    file descriptor operations internally.

    Args:
        path: Path to file
        max_size: Maximum allowed size in bytes
        file_type: Type of file for error message (e.g., "config", "secret")

    Raises:
        ConfigPermissionError: If file exceeds max_size
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            validate_file_size_fd(fd, path, max_size, file_type)
        finally:
            os.close(fd)
    except OSError as e:
        raise ConfigPermissionError(
            f"Failed to open {file_type.lower()} file for size validation: {path}: {e}",
            path=str(path),
        )


@auto_trace(logger)
def load_json_fd(fd: int, path: Path) -> dict:
    """Load and parse JSON from file descriptor.

    This function eliminates TOCTOU vulnerabilities by reading from
    an already-opened and validated file descriptor.

    Args:
        fd: Open file descriptor to read from
        path: Path for error messages (not used for reading)

    Returns:
        Parsed JSON as dictionary

    Raises:
        ConfigParseError: If JSON parsing fails
    """
    try:
        # Convert fd to file object for reading
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigParseError(str(path), str(e))
    except OSError as e:
        raise ConfigParseError(str(path), f"Failed to read file: {e}")

    if not isinstance(data, dict):
        raise ConfigParseError(str(path), "Root element must be a JSON object")

    return data


@auto_trace(logger)
def load_yaml_fd(fd: int, path: Path) -> dict:
    """Load and parse YAML from file descriptor.

    This function eliminates TOCTOU vulnerabilities by reading from
    an already-opened and validated file descriptor. Uses yaml.safe_load
    exclusively to prevent arbitrary code execution via YAML tags.

    Args:
        fd: Open file descriptor to read from
        path: Path for error messages (not used for reading)

    Returns:
        Parsed YAML as dictionary

    Raises:
        ConfigParseError: If YAML parsing fails or root is not a dict
    """
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigParseError(str(path), str(e))
    except OSError as e:
        raise ConfigParseError(str(path), f"Failed to read file: {e}")

    if not isinstance(data, dict):
        raise ConfigParseError(
            str(path),
            f"Root element must be a YAML mapping/dict, got {type(data).__name__}",
        )

    return data


@auto_trace(logger)
def load_config_file_fd(fd: int, path: Path) -> dict:
    """Load and parse config file from fd, selecting parser by file extension.

    Dispatches to load_json_fd for .json files and load_yaml_fd for
    .yaml/.yml files. Raises ConfigParseError for unsupported extensions.

    Args:
        fd: Open file descriptor to read from
        path: Path used for format detection (suffix) and error messages

    Returns:
        Parsed config as dictionary

    Raises:
        ConfigParseError: If file extension is unsupported or parsing fails
    """
    suffix = path.suffix.lower()

    if suffix == ".json":
        return load_json_fd(fd, path)
    elif suffix in (".yaml", ".yml"):
        return load_yaml_fd(fd, path)
    else:
        os.close(fd)
        raise ConfigParseError(
            str(path),
            f"Unsupported config file format: {suffix} (supported: .json, .yaml, .yml)",
        )


@auto_trace(logger)
def load_json(path: Path) -> dict:
    """Load and parse JSON file.

    This function provides backward compatibility while using secure
    file descriptor operations internally to prevent TOCTOU attacks.

    Args:
        path: Path to JSON file

    Returns:
        Parsed JSON as dictionary

    Raises:
        ConfigParseError: If JSON parsing fails
        ConfigPermissionError: If file exceeds size limit
    """
    max_size = get_max_config_size()

    try:
        # Open with secure flags - O_NOFOLLOW prevents symlink attacks
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        # Validate file size on the open descriptor
        validate_file_size_fd(fd, path, max_size, "Config")
        # Note: load_json_fd closes the fd via fdopen
        return load_json_fd(fd, path)
    except OSError as e:
        raise ConfigParseError(str(path), f"Failed to open file: {e}")


@auto_trace(logger)
def load_yaml(path: Path) -> dict:
    """Load and parse YAML file.

    Uses secure file descriptor operations internally to prevent TOCTOU
    attacks. YAML is parsed with yaml.safe_load exclusively.

    Args:
        path: Path to YAML file (.yaml or .yml)

    Returns:
        Parsed YAML as dictionary

    Raises:
        ConfigParseError: If YAML parsing fails
        ConfigPermissionError: If file exceeds size limit
    """
    max_size = get_max_config_size()

    try:
        # Open with secure flags - O_NOFOLLOW prevents symlink attacks
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        # Validate file size on the open descriptor
        validate_file_size_fd(fd, path, max_size, "Config")
        # Note: load_yaml_fd closes the fd via fdopen
        return load_yaml_fd(fd, path)
    except OSError as e:
        raise ConfigParseError(str(path), f"Failed to open file: {e}")


@auto_trace(logger)
def validate_against_schema(data: dict, schema: Type[T], path: Path) -> T:
    """Validate resolved data against Pydantic schema.

    Args:
        data: Resolved configuration data
        schema: Pydantic schema class
        path: Path for error messages

    Returns:
        Validated schema instance

    Raises:
        ConfigValidationError: If validation fails
    """
    try:
        return schema.model_validate(data)
    except ValidationError as e:
        errors = []
        for error in e.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            msg = error["msg"]
            errors.append(f"{field}: {msg}")

        raise ConfigValidationError(
            f"Configuration validation failed for {path}: {'; '.join(errors)}",
            errors=errors,
        )


@auto_trace(logger)
def load_secure_config(
    path: Path,
    schema: Type[T],
    component: str = "default",
    strict_permissions: bool = False,
    allowed_base_dirs: Optional[list[Path]] = None,
) -> T:
    """Load and validate secure configuration.

    This is the main entry point for loading configuration without
    using the registry. Returns only the schema-validated config.

    For access to extracted environment variables, use load_secure_config_with_env().

    Security: Uses file descriptor-based operations to prevent TOCTOU
    vulnerabilities. The file is opened once, validated, and read using
    the same file descriptor.

    Args:
        path: Path to JSON or YAML configuration file (.json, .yaml, .yml)
        schema: Pydantic schema class to validate against
        component: Component name for logging and error messages
        strict_permissions: If True, reject world-readable files
        allowed_base_dirs: Optional list of allowed base directories for file:// resolution.
                          If None, uses DEFAULT_ALLOWED_DIRS. Passing this explicitly provides
                          full traceability - the allowlist is defined in calling code, not
                          environment variables.

    Returns:
        Validated configuration instance

    Raises:
        ConfigNotFoundError: If file doesn't exist
        ConfigPermissionError: If file has insecure permissions or size limits
        ConfigParseError: If parsing fails or file format unsupported
        ConfigResolutionError: If value resolution fails
        ConfigValidationError: If schema validation fails
    """
    result = load_secure_config_with_env(
        path=path,
        schema=schema,
        component=component,
        strict_permissions=strict_permissions,
        allowed_base_dirs=allowed_base_dirs,
    )
    return result.config


@auto_trace(logger)
def load_secure_config_with_env(
    path: Path,
    schema: Type[T],
    component: str = "default",
    strict_permissions: bool = False,
    allowed_base_dirs: Optional[list[Path]] = None,
) -> LoadedConfig:
    """Load secure configuration with extracted environment variables.

    This is the full-featured entry point that returns both the schema-validated
    config and any environment variables declared in the `extract_env_vars` section.
    Supports both JSON and YAML file formats, detected by file extension.

    JSON config file format:
        {
            "field1": "value1",
            "field2": "env:SOME_VAR",
            "extract_env_vars": {
                "API_KEY": null,           // Required - no default
                "LOG_LEVEL": "INFO",       // Optional - default to "INFO"
                "DEBUG_MODE": "false"      // Optional - default to "false"
            }
        }

    YAML config file format:
        field1: value1
        field2: "env:SOME_VAR"
        extract_env_vars:
          API_KEY: null              # Required - no default
          LOG_LEVEL: INFO            # Optional - default to "INFO"
          DEBUG_MODE: "false"        # Optional - default to "false"

    Security: Uses file descriptor-based operations to prevent TOCTOU
    vulnerabilities. YAML is parsed with yaml.safe_load exclusively.
    All extracted env vars are wrapped in SecretStr.

    Args:
        path: Path to JSON or YAML configuration file (.json, .yaml, .yml)
        schema: Pydantic schema class to validate against
        component: Component name for logging and error messages
        strict_permissions: If True, reject world-readable files
        allowed_base_dirs: Optional list of allowed base directories for file:// resolution.

    Returns:
        LoadedConfig containing:
        - config: Validated configuration instance (schema fields only)
        - extracted_env_vars: ExtractedEnvVars container for declared env vars

    Raises:
        ConfigNotFoundError: If file doesn't exist
        ConfigPermissionError: If file has insecure permissions or size limits
        ConfigParseError: If parsing fails or file format unsupported
        ConfigResolutionError: If value resolution fails or required env vars missing
        ConfigValidationError: If schema validation fails
    """
    logger.info(
        "Loading secure config with env extraction",
        extra={
            "component": component,
            "path": str(path),
            "schema": schema.__name__,
        },
    )

    # Step 1: Validate path safety (before opening)
    validate_path_safety(path)

    # Step 2-4: Open file once and perform all validations on the fd
    # This eliminates TOCTOU by ensuring all checks and reads use the same file
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            # Validate permissions on the open file descriptor
            validate_config_permissions_fd(fd, path, strict=strict_permissions)

            # Validate file size on the open file descriptor
            max_size = get_max_config_size()
            validate_file_size_fd(fd, path, max_size, "Config")

            # Parse config from the validated file descriptor (JSON or YAML)
            # Note: load_config_file_fd closes the fd via fdopen, so no finally block
            raw_data = load_config_file_fd(fd, path)
        except Exception:
            # If we haven't transferred ownership to fdopen yet, close the fd
            try:
                os.close(fd)
            except OSError:
                pass
            raise
    except OSError as e:
        from neoaxios_secure_config.errors import ConfigNotFoundError
        raise ConfigNotFoundError(str(path)) if e.errno == 2 else ConfigParseError(
            str(path), f"Failed to open file: {e}"
        )

    # Step 5: Extract declared env vars if present
    env_var_spec = raw_data.pop(EXTRACT_ENV_VARS_KEY, None)
    extracted_env_vars: ExtractedEnvVars

    if env_var_spec is not None:
        if not isinstance(env_var_spec, dict):
            raise ConfigParseError(
                str(path),
                f"'{EXTRACT_ENV_VARS_KEY}' must be a JSON object mapping "
                "env var names to default values (use null for required vars)",
            )
        extracted = extract_env_vars(env_var_spec, component)
        extracted_env_vars = ExtractedEnvVars(extracted)
    else:
        # No env vars declared - empty container
        extracted_env_vars = ExtractedEnvVars({})

    # Step 6: Resolve value sources (env:, file://) for schema fields
    # Pass schema for type-aware resolution (auto-unwrap non-SecretStr fields)
    resolved_data = resolve_all_values(raw_data, component, schema, allowed_base_dirs)

    # Step 7: Validate against schema
    config = validate_against_schema(resolved_data, schema, path)

    logger.info(
        "Secure config loaded with env extraction",
        extra={
            "component": component,
            "path": str(path),
            "schema": schema.__name__,
            "fields": list(schema.model_fields.keys()),
            "secret_fields": schema.get_secret_fields(),
            "extracted_env_var_count": len(extracted_env_vars),
            "extracted_env_var_names": extracted_env_vars.keys(),
        },
    )

    return LoadedConfig(config=config, extracted_env_vars=extracted_env_vars)
