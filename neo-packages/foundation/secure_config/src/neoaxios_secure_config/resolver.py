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

"""Value source resolution for env: and file:// references.

Resolves configuration values from their declared sources:
- Literal values: used as-is
- env:VAR_NAME: read from environment variable (returns SecretStr)
- file:///path: read from file with permission validation (returns SecretStr)

Security: All env/file resolved values are wrapped in SecretStr immediately
to prevent accidental logging. This provides defense-in-depth protection.

Schema-Aware Resolution:
When a schema is provided, the resolver inspects field types to determine
whether to keep SecretStr wrapping or unwrap to plain string:
- Fields typed as SecretStr: Keep wrapped (for secrets)
- Fields typed as str: Unwrap to plain string (for non-sensitive URLs, etc.)
- Unknown fields: Keep wrapped (defense-in-depth default)
"""

import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Type, Union, overload

from pydantic import SecretStr
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_config.errors import ConfigPermissionError, ConfigResolutionError
from neoaxios_secure_config.limits import get_max_secret_size
from neoaxios_secure_config.validator import validate_file_size_fd

# Sentinel for distinguishing "no default provided" from default=None
_NO_DEFAULT = object()

if TYPE_CHECKING:
    from neoaxios_secure_config.schema import SecureSchema

logger = get_telemetry(__name__)

# Default allowed base directories for file:// resolution
# Priority: 1) explicit allowed_base_dirs parameter (recommended for traceability)
#           2) SECURE_CONFIG_ALLOWED_DIRS env var (fallback)
#           3) DEFAULT_ALLOWED_DIRS (last resort)
DEFAULT_ALLOWED_DIRS = [
    Path.cwd(),
    Path("/tmp"),
    Path("/run/secrets"),
    Path("/etc"),
]


@auto_trace(logger)
def _validate_secret_permissions_fd(fd: int, path: Path, field_name: str, component: str) -> None:
    """Validate secret file has restrictive permissions using file descriptor.

    This function eliminates TOCTOU vulnerabilities by checking permissions
    on an already-opened file descriptor.

    Args:
        fd: Open file descriptor
        path: Path for error messages
        field_name: Field name for error messages
        component: Component name for logging

    Raises:
        ConfigPermissionError: If file has insecure permissions
    """
    mode = os.fstat(fd).st_mode

    # Must not be world-readable
    if mode & stat.S_IROTH:
        raise ConfigPermissionError(
            f"Secret file is world-readable: {path}",
            path=str(path),
        )

    # Must not be world-writable
    if mode & stat.S_IWOTH:
        raise ConfigPermissionError(
            f"Secret file is world-writable: {path}",
            path=str(path),
        )

    # Warning if group-accessible
    if mode & 0o070:
        logger.warning(
            "Secret file permissions too open",
            extra={
                "mode": oct(mode),
                "recommended": "0400 or 0600",
                "component": component,
                "field": field_name,
            },
        )


@auto_trace(logger)
def _get_allowed_base_dirs(allowed_base_dirs: Optional[list[Path]] = None) -> list[Path]:
    """Get allowed base directories from parameter or environment variable.

    Args:
        allowed_base_dirs: Optional list of allowed base directories

    Returns:
        List of resolved absolute paths for allowed directories
    """
    if allowed_base_dirs is not None:
        # Use provided directories, resolve to absolute paths
        return [path.resolve() for path in allowed_base_dirs]

    # NOTE: This is the secure_config abstraction layer, so direct os.environ.get is appropriate here.
    # Consumers of secure_config should use resolve_value() instead of accessing os.environ directly.
    # See: tests/integration/test_config_env_resolution.py::TestNoRawEnvAccess
    env_dirs = os.environ.get("SECURE_CONFIG_ALLOWED_DIRS")
    if env_dirs:
        # Parse comma-separated paths from environment
        paths = [Path(d.strip()).resolve() for d in env_dirs.split(",") if d.strip()]
        logger.debug(
            "Using allowed directories from environment",
            extra={"env_var": "SECURE_CONFIG_ALLOWED_DIRS", "count": len(paths)},
        )
        return paths

    # Use defaults, resolve to absolute paths
    return [path.resolve() for path in DEFAULT_ALLOWED_DIRS]


@auto_trace(logger)
def _validate_path_in_allowed_dirs(
    path: Path, allowed_dirs: list[Path], field_name: str, source: str
) -> None:
    """Validate that resolved path is within allowed base directories.

    Args:
        path: Path to validate (should be resolved/absolute)
        allowed_dirs: List of allowed base directories
        field_name: Field name for error messages
        source: Original source string for error messages

    Raises:
        ConfigResolutionError: If path is not within any allowed directory
    """
    resolved_path = path.resolve()

    # Check if resolved path starts with any allowed directory
    for allowed_dir in allowed_dirs:
        try:
            if resolved_path.is_relative_to(allowed_dir):
                logger.debug(
                    "Path validated within allowed directory",
                    extra={
                        "allowed_dir": str(allowed_dir),
                        "field": field_name,
                    },
                )
                return
        except ValueError:
            continue

    # Path is not within any allowed directory
    allowed_dirs_str = ", ".join(str(d) for d in allowed_dirs)
    raise ConfigResolutionError(
        f"Path '{resolved_path}' is not within allowed base directories for field '{field_name}'. "
        f"Allowed directories: {allowed_dirs_str}. "
        f"Pass allowed_base_dirs parameter to configure allowed paths.",
        field=field_name,
        source=source,
    )


@overload
def resolve_env(value: str, field_name: str) -> SecretStr: ...

@overload
def resolve_env(value: str, field_name: str, default: None) -> SecretStr | None: ...

@overload
def resolve_env(value: str, field_name: str, default: str) -> SecretStr: ...

@auto_trace(logger)
def resolve_env(value: str, field_name: str, default: Any = _NO_DEFAULT) -> SecretStr | None:
    """Resolve env:VAR_NAME to environment variable value.

    Returns SecretStr to prevent accidental logging of sensitive values.
    Environment variables accessed via env: prefix are assumed to contain
    secrets and are protected immediately upon resolution.

    Args:
        value: String starting with "env:"
        field_name: Field name for error messages
        default: Value to return if env var is not set.  When omitted,
                 a missing env var raises ConfigResolutionError.

    Returns:
        SecretStr wrapping the environment variable value, or the default
        wrapped in SecretStr if the env var is not set and a default was
        provided.

    Raises:
        ConfigResolutionError: If environment variable not set and no default provided
    """
    var_name = value[4:]  # Strip "env:" prefix
    # NOTE: This is the secure_config abstraction layer, so direct os.environ.get is appropriate here.
    # The value is immediately wrapped in SecretStr below to prevent accidental logging.
    env_value = os.environ.get(var_name)

    if env_value is None:
        if default is not _NO_DEFAULT:
            logger.debug(
                "Environment variable not set, using default",
                extra={"field": field_name, "var_name": var_name},
            )
            if default is None:
                return None
            return SecretStr(str(default))
        raise ConfigResolutionError(
            f"Environment variable '{var_name}' not set for field '{field_name}'",
            field=field_name,
            source=value,
        )

    logger.debug(
        "Resolved environment variable",
        extra={"field": field_name, "var_name": var_name},
    )
    return SecretStr(env_value)


@auto_trace(logger)
def resolve_file(
    value: str,
    field_name: str,
    component: str,
    allowed_base_dirs: Optional[list[Path]] = None,
) -> SecretStr:
    """Resolve file:///path to file contents.

    Returns SecretStr to prevent accidental logging of sensitive values.
    File contents accessed via file:// prefix are assumed to contain
    secrets and are protected immediately upon resolution.

    Security: Uses file descriptor-based operations to prevent TOCTOU
    vulnerabilities. The file is opened once, validated, and read using
    the same file descriptor.

    Args:
        value: String starting with "file://"
        field_name: Field name for error messages
        component: Component name for logging
        allowed_base_dirs: Optional list of allowed base directories.
                          If None, uses DEFAULT_ALLOWED_DIRS or SECURE_CONFIG_ALLOWED_DIRS env var

    Returns:
        SecretStr wrapping the file contents (stripped of leading/trailing whitespace)

    Raises:
        ConfigResolutionError: If file not found or path outside allowed directories
        ConfigPermissionError: If file has insecure permissions
    """
    file_path = Path(value[7:])  # Strip "file://" prefix

    # Get allowed directories
    allowed_dirs = _get_allowed_base_dirs(allowed_base_dirs)

    # Validate path is within allowed directories BEFORE opening
    # This prevents information leakage about file existence outside allowed dirs
    _validate_path_in_allowed_dirs(file_path, allowed_dirs, field_name, value)

    # Open file once with secure flags - all validations use the same fd
    # O_NOFOLLOW prevents symlink attacks
    try:
        fd = os.open(str(file_path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ConfigResolutionError(
            f"Secret file not found: {file_path} for field '{field_name}'",
            field=field_name,
            source=value,
        )
    except OSError as e:
        # Check for symlink error (O_NOFOLLOW on symlink returns ELOOP)
        if e.errno == 40:  # ELOOP - Too many symbolic links
            raise ConfigResolutionError(
                f"Secret path is a symbolic link (not allowed for security): {file_path} for field '{field_name}'",
                field=field_name,
                source=value,
            )
        raise ConfigResolutionError(
            f"Failed to open secret file: {file_path}: {e}",
            field=field_name,
            source=value,
        )

    try:
        # Check if it's a directory (os.open() on directories succeeds on Linux)
        fd_stat = os.fstat(fd)
        if stat.S_ISDIR(fd_stat.st_mode):
            os.close(fd)
            raise ConfigResolutionError(
                f"Secret path is not a file: {file_path} for field '{field_name}'",
                field=field_name,
                source=value,
            )

        # Validate file size on the open file descriptor
        max_size = get_max_secret_size()
        validate_file_size_fd(fd, file_path, max_size, "Secret")

        # Validate permissions on the open file descriptor
        _validate_secret_permissions_fd(fd, file_path, field_name, component)

        # Read content from the validated file descriptor
        # fdopen takes ownership of the fd - it will close it
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except UnicodeDecodeError:
        raise ConfigResolutionError(
            f"Secret file contains invalid UTF-8: {file_path}",
            field=field_name,
            source=value,
        )
    except (ConfigPermissionError, ConfigResolutionError):
        # Re-raise our custom exceptions
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    except Exception:  # pragma: no cover - defensive cleanup for unexpected errors
        # Close fd if we haven't transferred ownership to fdopen yet
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    logger.debug(
        "Resolved file reference",
        extra={"field": field_name, "component": component},
    )
    return SecretStr(content)


@overload
def resolve_value(
    value: Any,
    field_name: str,
    component: str,
    allowed_base_dirs: Optional[list[Path]] = ...,
    should_wrap_as_secret: bool = ...,
) -> Union[Any, SecretStr]: ...

@overload
def resolve_value(
    value: Any,
    field_name: str,
    component: str,
    allowed_base_dirs: Optional[list[Path]] = ...,
    should_wrap_as_secret: bool = ...,
    *,
    default: None,
) -> Union[Any, SecretStr, None]: ...

@overload
def resolve_value(
    value: Any,
    field_name: str,
    component: str,
    allowed_base_dirs: Optional[list[Path]] = ...,
    should_wrap_as_secret: bool = ...,
    *,
    default: str,
) -> Union[Any, SecretStr]: ...

@auto_trace(logger)
def resolve_value(
    value: Any,
    field_name: str,
    component: str,
    allowed_base_dirs: Optional[list[Path]] = None,
    should_wrap_as_secret: bool = True,
    default: Any = _NO_DEFAULT,
) -> Union[Any, SecretStr, None]:
    """Resolve value from its declared source.

    Values from env: and file:// sources are returned as SecretStr to prevent
    accidental logging. Literal values are returned unchanged.

    Schema-Aware Resolution:
    When should_wrap_as_secret=False, env:/file:// values are unwrapped to plain
    strings. This is used when the target schema field is typed as str rather
    than SecretStr, indicating the value is not sensitive (e.g., URLs, log levels).

    Args:
        value: Value to resolve (may be literal, env:, or file://)
        field_name: Field name for error messages
        component: Component name for logging
        allowed_base_dirs: Optional list of allowed base directories for file:// resolution.
                          If None, uses DEFAULT_ALLOWED_DIRS. Passing this explicitly provides
                          full traceability - the allowlist is defined in calling code, not
                          environment variables.
        should_wrap_as_secret: If True (default), wrap env:/file:// values in SecretStr.
                              If False, unwrap to plain string (for non-sensitive fields).
        default: Value to return when an env: variable is not set.  When omitted,
                 a missing env var raises ConfigResolutionError (existing behavior).
                 Only applies to env: sources; file:// and literal sources ignore this.

    Returns:
        Resolved value - SecretStr or str for env/file sources (based on should_wrap_as_secret),
        original type for literals, or default when env var is missing

    Raises:
        ConfigResolutionError: If resolution fails and no default provided
        ConfigPermissionError: If file has insecure permissions
    """
    if not isinstance(value, str):
        return value  # Non-strings are literals

    if value.startswith("env:"):
        secret_value = resolve_env(value, field_name, default=default)
        if secret_value is None:
            return None  # default was None, env var not set
        # Unwrap if target field is not a secret
        return secret_value if should_wrap_as_secret else secret_value.get_secret_value()
    elif value.startswith("file://"):
        secret_value = resolve_file(value, field_name, component, allowed_base_dirs)
        # Unwrap if target field is not a secret
        return secret_value if should_wrap_as_secret else secret_value.get_secret_value()
    else:
        return value  # Literal string


@auto_trace(logger)
def resolve_all_values(
    data: dict[str, Any],
    component: str,
    schema: Optional[Type['SecureSchema']] = None,
    allowed_base_dirs: Optional[list[Path]] = None,
) -> dict[str, Any]:
    """Resolve all values in a configuration dictionary.

    Values from env: and file:// sources are wrapped in SecretStr automatically.
    This provides defense-in-depth protection against accidental logging.

    Schema-Aware Resolution:
    When schema is provided, field types are inspected to determine SecretStr wrapping:
    - Fields typed as SecretStr: Keep wrapped (for actual secrets)
    - Fields typed as str: Unwrap to plain string (for non-sensitive values like URLs)
    - Unknown fields (not in schema): Keep wrapped (defense-in-depth default)

    This eliminates the need for manual field validators in schema classes.

    Args:
        data: Raw configuration data
        component: Component name for logging
        schema: Optional schema class for type-aware resolution. If None, all env:/file://
                values are wrapped in SecretStr (backward compatible).
        allowed_base_dirs: Optional list of allowed base directories for file:// resolution.
                          If None, uses DEFAULT_ALLOWED_DIRS. Passing this explicitly provides
                          full traceability - the allowlist is defined in calling code, not
                          environment variables.

    Returns:
        Dictionary with all values resolved. env/file values are SecretStr or str
        based on schema field types (if provided).

    Raises:
        ConfigResolutionError: If any resolution fails
        ConfigPermissionError: If any file has insecure permissions
    """
    resolved = {}
    env_count = 0
    file_count = 0
    unwrapped_count = 0

    for field_name, value in data.items():
        # Determine if this field should be wrapped as secret
        should_wrap_as_secret = True  # Default: defense-in-depth

        if schema is not None and field_name in schema.model_fields:
            # Schema-aware: check if field is typed as SecretStr
            field_info = schema.model_fields[field_name]
            should_wrap_as_secret = schema._is_secret_str_field(field_info)

            # Track unwrapping for logging
            if not should_wrap_as_secret and isinstance(value, str) and (
                value.startswith("env:") or value.startswith("file://")
            ):
                unwrapped_count += 1

        # Count env/file sources
        if isinstance(value, str):
            if value.startswith("env:"):
                env_count += 1
            elif value.startswith("file://"):
                file_count += 1

        resolved[field_name] = resolve_value(
            value, field_name, component, allowed_base_dirs, should_wrap_as_secret
        )

    logger.info(
        "Resolved configuration values",
        extra={
            "component": component,
            "total_fields": len(data),
            "env_sources": env_count,
            "file_sources": file_count,
            "schema_aware": schema is not None,
            "unwrapped_fields": unwrapped_count,
        },
    )

    return resolved


@auto_trace(logger)
def extract_env_vars(
    env_var_spec: dict[str, Optional[str]],
    component: str,
    treat_empty_as_unset: bool = True,
) -> dict[str, SecretStr]:
    """Extract environment variables declared in config file.

    This function queries environment variables specified in the config file's
    `extract_env_vars` section and returns them as SecretStr values. This provides:
    - Explicit declaration of which env vars the component uses
    - Automatic SecretStr wrapping for security
    - Support for default values
    - Early failure if required vars are missing

    Defense in depth validations:
    - Max env var count limit (default 100, configurable via SECURE_CONFIG_MAX_ENV_VAR_COUNT)
    - Max value size limit (default 64KB, configurable via SECURE_CONFIG_MAX_ENV_VAR_SIZE)
    - Control character rejection (null bytes, etc.)
    - Empty string handling (configurable via treat_empty_as_unset)

    Args:
        env_var_spec: Dictionary mapping env var names to default values.
                     Use None for required vars (no default).
                     Example: {"API_KEY": None, "LOG_LEVEL": "INFO"}
        component: Component name for logging
        treat_empty_as_unset: If True (default), empty string values are treated
                             as "not set" and will use default or raise error.
                             Set to False to allow empty strings as valid values.

    Returns:
        Dictionary mapping env var names (lowercased) to SecretStr values.
        Keys are converted to lowercase for Pythonic attribute access.
        Example: {"api_key": SecretStr("..."), "log_level": SecretStr("INFO")}

    Raises:
        ConfigResolutionError: If validation fails:
            - Required env var not set (or empty when treat_empty_as_unset=True)
            - Too many env vars declared
            - Value exceeds size limit
            - Value contains control characters

    Example config file:
        {
            "timeout": 30,
            "extract_env_vars": {
                "API_KEY": null,
                "LOG_LEVEL": "INFO",
                "DEBUG_MODE": "false"
            }
        }
    """
    from neoaxios_secure_config.env_validation import (
        validate_env_var_count,
        validate_env_var_value,
        validate_not_empty_if_required,
    )

    # Defense: Limit number of env vars that can be extracted
    validate_env_var_count(len(env_var_spec), component)

    extracted: dict[str, SecretStr] = {}

    for var_name, default in env_var_spec.items():
        # NOTE: This is the secure_config abstraction layer, so direct os.environ.get is appropriate here.
        # SECURITY: Wrap ALL sensitive data in SecretStr IMMEDIATELY
        # SecretStr auto-masks in logs, so no special @auto_trace config needed
        raw_value = os.environ.get(var_name)
        secret_value: Optional[SecretStr] = SecretStr(raw_value) if raw_value is not None else None
        secret_default: Optional[SecretStr] = SecretStr(str(default)) if default is not None else None

        # Validate empty/required - all sensitive params are SecretStr (auto-masked)
        validated_or_default = validate_not_empty_if_required(
            value=secret_value,
            var_name=var_name,
            default=secret_default,
            component=component,
            treat_empty_as_unset=treat_empty_as_unset,
        )

        # Run defense in depth validations (size, control chars)
        # SECURITY: Takes SecretStr, raw access scoped inside validation functions
        final_value = validate_env_var_value(validated_or_default, var_name, component)

        # Store validated SecretStr
        extracted[var_name.lower()] = final_value

        source = "environment" if raw_value is not None and raw_value != "" else "default"
        logger.debug(
            "Extracted env var",
            extra={"var_name": var_name, "component": component, "source": source},
        )

    logger.info(
        "Extracted environment variables",
        extra={
            "component": component,
            "total_vars": len(extracted),
            "var_names": list(env_var_spec.keys()),
        },
    )

    return extracted
