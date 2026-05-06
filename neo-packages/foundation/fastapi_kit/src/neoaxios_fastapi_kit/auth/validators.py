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

"""Input validation for authorization framework.

Validates authorization parameters to prevent injection attacks and ensure
correct format. All validators use patterns from defaults.py.

Security Considerations:
- UUID validation prevents SQL injection via malformed identifiers
- Permission format validation prevents privilege escalation
- Path traversal detection blocks directory traversal attacks
- All validation failures are logged for security monitoring

Usage:
    from neoaxios_fastapi_kit.auth.validators import (
        validate_uuid,
        validate_permission,
        validate_resource_id,
        ValidationError,
    )

    # Validate UUID format (raises ValidationError if invalid)
    user_id = validate_uuid(user_id_str)

    # Validate permission format (raises ValidationError if invalid)
    permission = validate_permission(permission_str)

    # Validate resource ID and check for path traversal
    resource_id = validate_resource_id(resource_id_str)
"""

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.defaults import (
    DEFAULT_UUID_PATTERN,
    DEFAULT_PERMISSION_PATTERN,
    DEFAULT_ROLE_PATTERN,
    DEFAULT_PATH_TRAVERSAL_PATTERNS,
)
from neoaxios_fastapi_kit.auth.authz.errors import ValidationError

logger = get_telemetry(__name__)


@auto_trace(logger)
def validate_uuid(value: str) -> str:
    """Validate that value matches UUID v4 format.

    Uses pattern from DEFAULT_UUID_PATTERN to ensure value is a valid
    UUID v4 string. Used to validate user_id, tenant_id, and resource_id
    parameters before database queries.

    Args:
        value: String to validate as UUID

    Returns:
        The validated UUID string (unchanged)

    Raises:
        ValidationError: If value is not a valid UUID v4 format

    Example:
        >>> validate_uuid("550e8400-e29b-41d4-a716-446655440000")
        "550e8400-e29b-41d4-a716-446655440000"
        >>> validate_uuid("not-a-uuid")
        ValidationError: Invalid UUID format
    """
    if not value:
        error = ValidationError("UUID cannot be empty")
        logger.log_error(error, context={"value": value})
        raise error

    if not DEFAULT_UUID_PATTERN.match(value.lower()):
        error = ValidationError(f"Invalid UUID format: {value}")
        logger.log_error(error, context={"value": value})
        raise error

    return value


@auto_trace(logger)
def validate_permission(permission: str) -> str:
    """Validate that permission matches required format.

    Permissions must follow "resource:action" format (e.g., "document:read").
    Uses pattern from DEFAULT_PERMISSION_PATTERN.

    Args:
        permission: Permission string to validate

    Returns:
        The validated permission string (unchanged)

    Raises:
        ValidationError: If permission format is invalid

    Example:
        >>> validate_permission("document:read")
        "document:read"
        >>> validate_permission("invalid-permission")
        ValidationError: Invalid permission format
        >>> validate_permission("DOCUMENT:READ")
        ValidationError: Invalid permission format (must be lowercase)
    """
    if not permission:
        error = ValidationError("Permission cannot be empty")
        logger.log_error(error, context={"permission": permission})
        raise error

    if not DEFAULT_PERMISSION_PATTERN.match(permission):
        error = ValidationError(
            f"Invalid permission format: {permission}. "
            f"Expected pattern: resource:action (lowercase with underscores)"
        )
        logger.log_error(error, context={"permission": permission})
        raise error

    return permission


@auto_trace(logger)
def validate_resource_id(value: str) -> str:
    """Validate resource ID and check for path traversal attacks.

    Checks for common path traversal attack patterns including:
    - ../ and ..\\
    - URL-encoded variants (%2e%2e, %252e%252e)

    Uses patterns from DEFAULT_PATH_TRAVERSAL_PATTERNS.

    Args:
        value: Resource ID string to validate

    Returns:
        The validated resource ID string (unchanged)

    Raises:
        ValidationError: If path traversal pattern is detected

    Example:
        >>> validate_resource_id("document-123")
        "document-123"
        >>> validate_resource_id("../etc/passwd")
        ValidationError: Path traversal detected
    """
    if not value:
        error = ValidationError("Resource ID cannot be empty")
        logger.log_error(error, context={"value": value})
        raise error

    value_lower = value.lower()
    for pattern in DEFAULT_PATH_TRAVERSAL_PATTERNS:
        if pattern in value_lower:
            error = ValidationError(f"Path traversal detected: {pattern}")
            logger.log_error(error, context={"value": value, "pattern": pattern})
            raise error

    return value


@auto_trace(logger)
def validate_role(role: str) -> str:
    """Validate that role matches required format.

    Roles must be lowercase alphanumeric with underscores (e.g., "admin", "power_user").
    Uses pattern from DEFAULT_ROLE_PATTERN.

    Args:
        role: Role string to validate

    Returns:
        The validated role string (unchanged)

    Raises:
        ValidationError: If role format is invalid

    Example:
        >>> validate_role("admin")
        "admin"
        >>> validate_role("power_user")
        "power_user"
        >>> validate_role("Admin")
        ValidationError: Invalid role format (must be lowercase)
        >>> validate_role("admin-role")
        ValidationError: Invalid role format (hyphens not allowed)
    """
    if not role:
        error = ValidationError("Role cannot be empty")
        logger.log_error(error, context={"role": role})
        raise error

    if not DEFAULT_ROLE_PATTERN.match(role):
        error = ValidationError(
            f"Invalid role format: {role}. "
            f"Expected: lowercase alphanumeric with underscores only"
        )
        logger.log_error(error, context={"role": role})
        raise error

    return role


@auto_trace(logger)
def check_path_traversal(value: str) -> None:
    """Check for path traversal patterns and raise if detected.

    Scans value for common path traversal attack patterns including:
    - ../  and  ..\\
    - URL-encoded variants (%2e%2e, %252e%252e)

    Uses patterns from DEFAULT_PATH_TRAVERSAL_PATTERNS.

    Args:
        value: String to check for path traversal

    Raises:
        ValidationError: If path traversal pattern is detected

    Example:
        >>> check_path_traversal("safe_file.txt")
        # No exception raised
        >>> check_path_traversal("../etc/passwd")
        ValidationError: Path traversal detected: ../
    """
    if not value:
        return

    value_lower = value.lower()
    for pattern in DEFAULT_PATH_TRAVERSAL_PATTERNS:
        if pattern in value_lower:
            error = ValidationError(f"Path traversal detected: {pattern}")
            logger.log_error(error, context={"value": value, "pattern": pattern})
            raise error
