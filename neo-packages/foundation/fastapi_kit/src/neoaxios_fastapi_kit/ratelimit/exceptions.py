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

"""HTTP-specific rate limiting exceptions with cross-package inheritance.

Exception Hierarchy (cross-package):
    rk.RateLimitError (base, resilience-kit)
    +-- RateLimitExceeded(HTTPException, rk.RateLimitError) (HTTP 429)
    +-- rk.RateLimitBackendError (resilience-kit)
    |   +-- HTTPRateLimitBackendError(HTTPException, rk.RateLimitBackendError) (HTTP 503)
    +-- rk.RateLimitConfigError (resilience-kit, re-exported)

Base types (RateLimitError, RateLimitBackendError, RateLimitConfigError) live in
neoaxios_resilience_kit.ratelimit.exceptions. This module defines only the
HTTP-specific subclasses that add HTTPException behavior (status codes, headers).

Design:
- Split exceptions: base types in resilience-kit, HTTP subclasses here.
- RateLimitBackendError has its non-HTTP base in resilience-kit.

References:
- IETF draft-ietf-httpapi-ratelimit-headers: Standard RateLimit-* headers
"""

from typing import Optional

from fastapi import HTTPException

from neoaxios_resilience_kit.ratelimit import (
    RateLimitBackendError,
    RateLimitConfigError,
    RateLimitError,
)
from .utils import build_ratelimit_headers
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class RateLimitExceeded(HTTPException, RateLimitError):
    """Exception raised when rate limit is exceeded.

    Returns HTTP 429 Too Many Requests with IETF-compliant headers.

    Inherits from both HTTPException (for FastAPI HTTP response handling) and
    RateLimitError from resilience-kit (for cross-package isinstance checks).

    Headers emitted (per IETF draft-ietf-httpapi-ratelimit-headers):
        - RateLimit-Limit: Maximum requests per window
        - RateLimit-Remaining: 0 (exhausted)
        - RateLimit-Reset: Seconds until window reset
        - RateLimit-Policy: Rate limit policy definition
        - Retry-After: Seconds until retry is appropriate
        - X-RateLimit-*: Legacy headers for backward compatibility
    """

    @auto_trace(logger)
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        retry_after: int,
        message: str = "Rate limit exceeded",
        scope: Optional[str] = None,
        include_epoch: bool = False,
    ) -> None:
        headers = build_ratelimit_headers(
            limit=limit,
            remaining=0,
            reset_seconds=retry_after,
            window_seconds=window_seconds,
            include_retry_after=True,
            include_epoch=include_epoch,
        )

        HTTPException.__init__(
            self,
            status_code=429,
            detail=message,
            headers=headers,
        )
        RateLimitError.__init__(self, message)

        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after = retry_after
        self.scope = scope

        logger.warning(
            "Rate limit exceeded",
            limit=limit,
            window_seconds=window_seconds,
            retry_after=retry_after,
            scope=scope,
        )


class HTTPRateLimitBackendError(HTTPException, RateLimitBackendError):
    """Exception raised when rate limit backend is unavailable (HTTP context).

    Returns HTTP 503 Service Unavailable. All rate limiting is fail-closed
    -- there is no fail-open option.

    Inherits from both HTTPException (for FastAPI HTTP response handling) and
    RateLimitBackendError from resilience-kit (for cross-package isinstance
    checks). isinstance(exc, RateLimitError) is True because
    RateLimitBackendError extends RateLimitError in resilience-kit.
    """

    @auto_trace(logger)
    def __init__(
        self,
        message: str = "Rate limit backend unavailable",
        original_error: Optional[Exception] = None,
        backend_type: str = "unknown",
    ) -> None:
        headers = {
            "Retry-After": "60",
        }

        HTTPException.__init__(
            self,
            status_code=503,
            detail=message,
            headers=headers,
        )
        RateLimitBackendError.__init__(
            self,
            message=message,
            original_error=original_error,
            backend_type=backend_type,
        )
