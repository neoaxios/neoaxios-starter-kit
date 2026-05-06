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

"""FastAPI exception handlers for authentication and authorization errors.

Provides centralized exception-to-HTTP conversion for auth framework errors.
Applications register these handlers once at startup to ensure consistent
error responses across all endpoints.

Usage:
    from fastapi import FastAPI
    from neoaxios_fastapi_kit.auth.exception_handlers import register_auth_exception_handlers

    app = FastAPI()
    register_auth_exception_handlers(app)

    # Exceptions raised by auth dependencies are automatically converted to HTTP responses
    # TokenExpiredError → 401 with WWW-Authenticate header
    # TokenInvalidError → 401 with WWW-Authenticate header
    # PermissionDeniedError → 403 Forbidden
    # TenantMismatchError → 404 Not Found (prevents resource enumeration)

References:
    - RFC 7235: WWW-Authenticate header for 401 responses
"""

from typing import Callable, Dict, Optional, Type

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from neoaxios_fastapi_kit.auth.authz.errors import (
    PermissionDeniedError,
    TenantMismatchError,
)
from neoaxios_fastapi_kit.auth.errors import AuthError

logger = get_telemetry(__name__)


@auto_trace(logger)
def _build_auth_error_response(
    exc: AuthError,
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """Build standardized auth error JSON response.
    
    Args:
        exc: Auth framework exception with error_code and message
        status_code: HTTP status code (401, 403, etc.)
        headers: Optional HTTP headers (e.g., WWW-Authenticate)
        
    Returns:
        JSONResponse with standardized error format
    """
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": exc.error_code, "message": str(exc)}},
        headers=headers or {},
    )


@auto_trace(logger)
def register_auth_exception_handlers(
    app: FastAPI,
    include_www_authenticate: bool = True,
    custom_handlers: Optional[Dict[Type[Exception], Callable]] = None,
) -> None:
    """Register exception handlers for authentication/authorization errors.

    Converts auth framework exceptions to HTTP responses with appropriate
    status codes and headers. Provides default handlers for all auth errors
    with support for custom overrides.

    Args:
        app: FastAPI application instance
        include_www_authenticate: Include WWW-Authenticate header on 401 responses
                                 per RFC 7235 (default: True)
        custom_handlers: Optional dict mapping exception types to custom handler
                        functions. Allows applications to override specific handlers
                        while using defaults for others.

    Example:
        # Use default handlers
        app = FastAPI()
        register_auth_exception_handlers(app)

        # Custom handler for token expired
        async def custom_expired_handler(request: Request, exc: TokenExpiredError):
            return JSONResponse(
                status_code=401,
                content={"error": "session_expired", "redirect": "/login"}
            )

        register_auth_exception_handlers(
            app,
            custom_handlers={TokenExpiredError: custom_expired_handler}
        )

    References:
        - RFC 7235: WWW-Authenticate header requirements
    """
    custom_handlers = custom_handlers or {}

    # Token Expired → 401 Unauthorized
    if TokenExpiredError not in custom_handlers:

        @app.exception_handler(TokenExpiredError)
        @auto_trace(logger)
        async def handle_token_expired(request: Request, exc: TokenExpiredError):
            """Convert TokenExpiredError to 401 HTTP response.

            Returns 401 Unauthorized with WWW-Authenticate header per RFC 7235.
            Client should obtain a new token and retry the request.
            """
            logger.warning(
                "token_expired",
                path=request.url.path,
                method=request.method,
            )

            headers = {}
            if include_www_authenticate:
                headers["WWW-Authenticate"] = "Bearer"

            return _build_auth_error_response(exc, status.HTTP_401_UNAUTHORIZED, headers)

    else:
        app.add_exception_handler(TokenExpiredError, custom_handlers[TokenExpiredError])

    # Token Invalid → 401 Unauthorized
    if TokenInvalidError not in custom_handlers:

        @app.exception_handler(TokenInvalidError)
        @auto_trace(logger)
        async def handle_token_invalid(request: Request, exc: TokenInvalidError):
            """Convert TokenInvalidError to 401 HTTP response.

            Returns 401 Unauthorized with WWW-Authenticate header per RFC 7235.
            Token signature failed validation or claims are malformed.
            """
            logger.warning(
                "token_invalid",
                path=request.url.path,
                method=request.method,
            )

            headers = {}
            if include_www_authenticate:
                headers["WWW-Authenticate"] = "Bearer"

            return _build_auth_error_response(exc, status.HTTP_401_UNAUTHORIZED, headers)

    else:
        app.add_exception_handler(TokenInvalidError, custom_handlers[TokenInvalidError])

    # Token Revoked → 401 Unauthorized
    if TokenRevokedError not in custom_handlers:

        @app.exception_handler(TokenRevokedError)
        @auto_trace(logger)
        async def handle_token_revoked(request: Request, exc: TokenRevokedError):
            """Convert TokenRevokedError to 401 HTTP response.

            Returns 401 Unauthorized with WWW-Authenticate header.
            Token has been explicitly revoked and should not be used.
            """
            logger.warning(
                "token_revoked",
                path=request.url.path,
                method=request.method,
            )

            headers = {}
            if include_www_authenticate:
                headers["WWW-Authenticate"] = "Bearer"

            return _build_auth_error_response(exc, status.HTTP_401_UNAUTHORIZED, headers)

    else:
        app.add_exception_handler(TokenRevokedError, custom_handlers[TokenRevokedError])

    # Permission Denied → 403 Forbidden
    if PermissionDeniedError not in custom_handlers:

        @app.exception_handler(PermissionDeniedError)
        @auto_trace(logger)
        async def handle_permission_denied(
            request: Request, exc: PermissionDeniedError
        ):
            """Convert PermissionDeniedError to 403 HTTP response.

            Returns 403 Forbidden when authenticated user lacks required permission.
            Identity is valid but not authorized for this operation.
            """
            logger.warning(
                "permission_denied",
                path=request.url.path,
                method=request.method,
                required_permission=getattr(exc, "permission", None),
            )

            return _build_auth_error_response(exc, status.HTTP_403_FORBIDDEN)

    else:
        app.add_exception_handler(
            PermissionDeniedError, custom_handlers[PermissionDeniedError]
        )

    # Tenant Mismatch → 404 Not Found (prevents resource enumeration)
    if TenantMismatchError not in custom_handlers:

        @app.exception_handler(TenantMismatchError)
        @auto_trace(logger)
        async def handle_tenant_mismatch(request: Request, exc: TenantMismatchError):
            """Convert TenantMismatchError to 404 HTTP response.

            Returns 404 (not 403) to prevent resource enumeration (OWASP API1:2023).
            """
            logger.warning(
                "tenant_mismatch",
                path=request.url.path,
                method=request.method,
            )

            # Use static message to prevent tenant ID leakage.
            # Do NOT pass str(exc) — it contains identity/resource tenant IDs
            # that would enable resource enumeration via the 404 response body.
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.error_code, "message": "Not Found"}},
                headers={},
            )

    else:
        app.add_exception_handler(
            TenantMismatchError, custom_handlers[TenantMismatchError]
        )

    logger.info(
        "auth_exception_handlers_registered",
        include_www_authenticate=include_www_authenticate,
        custom_handler_count=len(custom_handlers),
    )
