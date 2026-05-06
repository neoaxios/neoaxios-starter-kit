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

"""Sensitive permission detection for cache bypass.

This module provides detection of sensitive permissions that should bypass
cache entirely to eliminate TOCTOU race conditions.

Default Sensitive Patterns:
- admin:*     (administrative operations)
- delete:*    (deletion operations)
- sudo:*      (privilege escalation)
- perm:grant  (permission granting)
- perm:revoke (permission revocation)

Features:
- Prefix-based pattern matching
- Extensible pattern registration
- Cache bypass recommendation for sensitive permissions

Usage:
    from neoaxios_secure_cache.security.sensitive import (
        is_sensitive_permission,
        register_sensitive_pattern,
    )

    # Check if permission is sensitive
    if is_sensitive_permission("admin:users"):
        # Bypass cache, resolve from source
        return await resolve_from_source(permission)

    # Register custom sensitive pattern
    register_sensitive_pattern("critical:")

Implementation Notes:
- Pattern matching is prefix-based (startswith)
- Patterns stored in set for mutability during registration
- Thread-safe via lock for registration operations
- Applications integrate this in permission resolution layer
- Cache returns None for sensitive permissions (forcing source resolution)
- This eliminates TOCTOU between cache read and permission use
"""

import threading
from typing import FrozenSet

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)

# Default sensitive patterns - operations that require cache bypass
SENSITIVE_PATTERNS: set[str] = {
    "admin:",      # Admin operations
    "delete:",     # Delete operations
    "sudo:",       # Elevated privileges
    "perm:grant",  # Permission granting
    "perm:revoke", # Permission revocation
}

# Thread lock for pattern registration operations
_pattern_lock = threading.Lock()


@auto_trace(logger)
def is_sensitive_permission(permission: str) -> bool:
    """Check if permission matches sensitive patterns.

    Uses prefix matching to determine if a permission string
    matches any registered sensitive pattern. This enables
    wildcard-style matching (e.g., "admin:" matches "admin:users").

    Args:
        permission: Permission string to check (case-sensitive)

    Returns:
        True if permission matches any sensitive pattern, False otherwise

    Example:
        >>> is_sensitive_permission("admin:users")
        True
        >>> is_sensitive_permission("read:documents")
        False
        >>> is_sensitive_permission("perm:grant")
        True
    """
    if not permission:
        logger.debug("Empty permission provided, returning False")
        return False

    # Check if permission starts with any sensitive pattern
    for pattern in SENSITIVE_PATTERNS:
        if permission.startswith(pattern):
            logger.debug(
                f"Permission '{permission}' matches sensitive pattern '{pattern}'"
            )
            return True

    logger.debug(f"Permission '{permission}' is not sensitive")
    return False


@auto_trace(logger)
def register_sensitive_pattern(pattern: str) -> None:
    """Add custom pattern to sensitive patterns set.

    Thread-safe registration of new sensitive patterns. Allows
    applications to define custom sensitive permissions beyond
    the default set.

    Args:
        pattern: Pattern string to add (will be matched via startswith)

    Raises:
        ValueError: If pattern is empty or not a string

    Example:
        >>> register_sensitive_pattern("critical:")
        >>> is_sensitive_permission("critical:action")
        True
    """
    if not pattern or not isinstance(pattern, str):
        err = ValueError("pattern must be a non-empty string")
        logger.log_error(err)
        raise err

    with _pattern_lock:
        if pattern not in SENSITIVE_PATTERNS:
            SENSITIVE_PATTERNS.add(pattern)
            logger.info(f"Registered new sensitive pattern: '{pattern}'")
        else:
            logger.debug(f"Pattern '{pattern}' already registered")


@auto_trace(logger)
def unregister_sensitive_pattern(pattern: str) -> None:
    """Remove pattern from sensitive patterns set.

    Thread-safe removal of patterns. Useful for testing or
    dynamic configuration changes.

    Args:
        pattern: Pattern string to remove

    Raises:
        ValueError: If pattern is empty or not a string
        KeyError: If pattern was not registered

    Example:
        >>> register_sensitive_pattern("temp:")
        >>> unregister_sensitive_pattern("temp:")
    """
    if not pattern or not isinstance(pattern, str):
        val_err = ValueError("pattern must be a non-empty string")
        logger.log_error(val_err)
        raise val_err

    with _pattern_lock:
        if pattern not in SENSITIVE_PATTERNS:
            key_err = KeyError(f"Pattern '{pattern}' is not registered")
            logger.log_error(key_err)
            raise key_err

        SENSITIVE_PATTERNS.remove(pattern)
        logger.info(f"Unregistered sensitive pattern: '{pattern}'")


@auto_trace(logger)
def get_sensitive_patterns() -> FrozenSet[str]:
    """Get current set of sensitive patterns.

    Returns immutable snapshot of registered patterns.
    Thread-safe read operation.

    Returns:
        Frozen set of current sensitive patterns

    Example:
        >>> patterns = get_sensitive_patterns()
        >>> "admin:" in patterns
        True
    """
    with _pattern_lock:
        # Return immutable snapshot
        result = frozenset(SENSITIVE_PATTERNS)

    logger.debug(f"Retrieved {len(result)} sensitive patterns")
    return result
