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

"""Environment variable validation for defense in depth.

Provides validation functions for extracted environment variable values
to prevent injection attacks, DoS, and other security issues.

SECURITY NOTE: All validation functions work with SecretStr to prevent
accidental logging of sensitive values. Raw string access is strictly
scoped within validation logic and never passed as function arguments.
"""

import re
from typing import Optional

from pydantic import SecretStr
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_config.errors import ConfigResolutionError
from neoaxios_secure_config.limits import get_max_env_var_value_size, get_max_extract_env_var_count

logger = get_telemetry(__name__)

# Control characters (ASCII 0-31 except tab, newline, carriage return)
# Null byte is especially dangerous for C-based libraries
CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


@auto_trace(logger)
def validate_env_var_count(count: int, component: str) -> None:
    """Validate that env var count doesn't exceed limit.

    Defense against config file DoS via excessive env var declarations.

    Args:
        count: Number of env vars declared
        component: Component name for error messages

    Raises:
        ConfigResolutionError: If count exceeds limit
    """
    max_count = get_max_extract_env_var_count()
    if count > max_count:
        raise ConfigResolutionError(
            f"Too many environment variables declared for component '{component}': "
            f"{count} exceeds maximum of {max_count}. "
            f"Reduce extract_env_vars entries or increase SECURE_CONFIG_MAX_ENV_VAR_COUNT.",
            field="extract_env_vars",
            source=f"count: {count}",
        )

    logger.debug(
        "Env var count validated",
        extra={"count": count, "max_count": max_count, "component": component},
    )


@auto_trace(logger)
def validate_env_var_value_size(value: SecretStr, var_name: str, component: str) -> None:
    """Validate that env var value doesn't exceed size limit.

    Defense against DoS via extremely large environment variable values.

    SECURITY: Takes SecretStr to prevent accidental logging. Raw value
    access is scoped to the size calculation only.

    Args:
        value: The env var value wrapped in SecretStr
        var_name: Name of the env var for error messages
        component: Component name for error messages

    Raises:
        ConfigResolutionError: If value exceeds size limit
    """
    max_size = get_max_env_var_value_size()
    # SECURITY: Raw access scoped to this line only - never passed to functions
    value_size = len(value.get_secret_value().encode('utf-8'))

    if value_size > max_size:
        raise ConfigResolutionError(
            f"Environment variable '{var_name}' value exceeds maximum size for "
            f"component '{component}': {value_size:,} bytes > {max_size:,} bytes. "
            f"Reduce value size or increase SECURE_CONFIG_MAX_ENV_VAR_SIZE.",
            field=var_name,
            source=f"env:{var_name}",
        )

    logger.debug(
        "Env var value size validated",
        extra={
            "var_name": var_name,
            "value_size": value_size,
            "max_size": max_size,
            "component": component,
        },
    )


@auto_trace(logger)
def validate_no_control_characters(value: SecretStr, var_name: str, component: str) -> None:
    """Validate that env var value contains no dangerous control characters.

    Defense against injection attacks via control characters, especially
    null bytes which can cause issues in C-based libraries and file paths.

    Allowed control characters: tab (0x09), newline (0x0a), carriage return (0x0d)
    Rejected: null (0x00), and other control chars (0x01-0x08, 0x0b, 0x0c, 0x0e-0x1f)

    SECURITY: Takes SecretStr to prevent accidental logging. Raw value
    access is scoped to the regex check only.

    Args:
        value: The env var value wrapped in SecretStr
        var_name: Name of the env var for error messages
        component: Component name for error messages

    Raises:
        ConfigResolutionError: If value contains dangerous control characters
    """
    # SECURITY: Raw access scoped to this line only - never passed to functions
    raw_value = value.get_secret_value()
    match = CONTROL_CHAR_PATTERN.search(raw_value)
    if match:
        char_code = ord(match.group())
        raise ConfigResolutionError(
            f"Environment variable '{var_name}' contains dangerous control character "
            f"(0x{char_code:02x}) for component '{component}'. "
            f"Control characters (except tab, newline, CR) are not allowed in env var values.",
            field=var_name,
            source=f"env:{var_name}",
        )

    logger.debug(
        "Env var control character check passed",
        extra={"var_name": var_name, "component": component},
    )


@auto_trace(logger)
def validate_not_empty_if_required(
    value: Optional[SecretStr],
    var_name: str,
    default: Optional[SecretStr],
    component: str,
    treat_empty_as_unset: bool = True,
) -> SecretStr:
    """Validate and handle empty/None values, returning SecretStr.

    By default, empty strings are treated as "not set" for required vars.
    This prevents issues where an env var is set to empty string but the
    application expects a meaningful value.

    SECURITY: All sensitive parameters use SecretStr which auto-masks in logs.
    No special @auto_trace configuration needed - SecretStr handles masking.

    Args:
        value: The env var value wrapped in SecretStr, or None if not set
        var_name: Name of the env var
        default: Default value as SecretStr (None means required)
        component: Component name for error messages
        treat_empty_as_unset: If True, empty string treated as not set

    Returns:
        SecretStr wrapping the value to use.
        May wrap the original value, the default, or empty string.

    Raises:
        ConfigResolutionError: If required var is empty/unset
    """
    # Check if value is effectively "not set"
    is_unset = value is None or (
        treat_empty_as_unset and value.get_secret_value() == ""
    )

    if is_unset:
        if default is not None:
            logger.debug(
                "Using default for empty/unset env var",
                extra={"var_name": var_name, "component": component},
            )
            return default
        else:
            # Required var is not set
            raise ConfigResolutionError(
                f"Required environment variable '{var_name}' is not set "
                f"(or is empty) for component '{component}'. "
                f"Set the variable or provide a default in extract_env_vars.",
                field=var_name,
                source=f"env:{var_name}",
            )

    # Value is set and not empty (or empty allowed) - return as-is
    return value


@auto_trace(logger)
def validate_env_var_value(
    value: SecretStr,
    var_name: str,
    component: str,
) -> SecretStr:
    """Run all validations on an env var value.

    Combines size limit and control character checks.

    SECURITY: Takes and returns SecretStr. Raw value access is delegated
    to individual validation functions which scope access appropriately.

    Args:
        value: The env var value wrapped in SecretStr
        var_name: Name of the env var
        component: Component name for error messages

    Returns:
        The validated SecretStr (same instance, validated)

    Raises:
        ConfigResolutionError: If any validation fails
    """
    validate_env_var_value_size(value, var_name, component)
    validate_no_control_characters(value, var_name, component)
    return value
