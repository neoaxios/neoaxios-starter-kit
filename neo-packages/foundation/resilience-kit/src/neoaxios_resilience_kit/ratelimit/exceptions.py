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

"""Rate limiting exceptions for resilience patterns (no HTTP semantics).

Exception Hierarchy:
    RateLimitError (base)
    +-- RateLimitBackendError (backend failure)
    +-- RateLimitConfigError (configuration error)

These exceptions mirror the neoaxios_fastapi_kit rate limit exception hierarchy but
strip all HTTP semantics (no HTTPException inheritance, no status codes,
no response headers). They are suitable for use in non-HTTP contexts such
as background workers, CLI tools, and shared libraries.
"""

from typing import Optional

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class RateLimitError(Exception):
    """Base exception for all rate limiting errors."""

    @auto_trace(logger)
    def __init__(self, message: str = "Rate limit error") -> None:
        super().__init__(message)
        self.message = message


class RateLimitBackendError(RateLimitError):
    """Exception raised when rate limit backend is unavailable.

    All rate limiting is fail-closed -- there is no fail-open option.
    This exception signals that the backend (Redis, in-memory store, etc.)
    could not be reached, and the caller should treat the operation as denied.
    """

    @auto_trace(logger)
    def __init__(
        self,
        message: str = "Rate limit backend unavailable",
        original_error: Optional[Exception] = None,
        backend_type: str = "unknown",
    ) -> None:
        super().__init__(message)
        self.original_error = original_error
        self.backend_type = backend_type

        logger.log_error(
            Exception(f"Rate limit backend error: {message}"),
        )


class RateLimitConfigError(RateLimitError):
    """Exception raised for rate limit configuration errors.

    Raised during startup if configuration is invalid.
    """

    @auto_trace(logger)
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        invalid_value: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.config_key = config_key
        self.invalid_value = invalid_value

        logger.log_error(
            Exception(f"Rate limit config error: {message}"),
        )
