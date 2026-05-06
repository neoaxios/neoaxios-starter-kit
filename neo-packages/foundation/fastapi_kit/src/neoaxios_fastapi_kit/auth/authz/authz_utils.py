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

"""Authorization utility functions shared across authz components.

This module provides common utilities used by multiple authorization components
to ensure consistent error handling, logging, and fail-closed behavior.
"""

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger)
def raise_auth_error(operation: str, error: Exception, message: str) -> None:
    """Log error and raise AuthError (fail-closed).

    Centralized error handling for authorization failures across all authz components.
    Ensures consistent logging and fail-closed behavior when authorization operations fail.

    This function consolidates the common pattern:
    1. Log error with context (logger.error)
    2. Log exception object for stack trace (logger.log_error)
    3. Raise AuthError to deny access (fail-closed)

    Args:
        operation: Description of operation that failed (e.g., "query user roles")
        error: Original exception that occurred
        message: User-facing error message for AuthError

    Raises:
        AuthError: Always raises with the provided message after logging

    Usage:
        from neoaxios_fastapi_kit.auth.authz.authz_utils import raise_auth_error

        try:
            result = await db.query(...)
        except Exception as e:
            raise_auth_error(
                "query user roles",
                e,
                "Unable to verify user permissions"
            )
    """
    logger.error(f"Failed to {operation}: {error}")
    logger.log_error(error)
    from .errors import AuthError  # Relative import within authz package

    raise AuthError(message)
