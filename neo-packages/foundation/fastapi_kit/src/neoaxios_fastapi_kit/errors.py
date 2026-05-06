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

"""Standardized error handling for FastAPI services."""

from __future__ import annotations

import http
import os
import traceback
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException as FastAPIHTTPException
from fastapi import Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.utils import is_body_allowed_for_status_code
from neoaxios_resilience_kit import CircuitBreakerOpenError
from starlette.exceptions import HTTPException as StarletteHTTPException
from neoaxios_logging import auto_trace, get_telemetry

# Two HTTPException classes coexist:
#
#   - ``starlette.exceptions.HTTPException`` — the dispatch key
#     FastAPI's app initialiser registers (``fastapi/applications.py:1001``
#     does ``self.exception_handlers.setdefault(HTTPException,
#     http_exception_handler)`` where the import is from
#     ``starlette.exceptions``).  Type-keyed handlers must register
#     against this class so the unmatched-route 404 (which Starlette
#     raises directly) flows through our handler.
#
#   - ``fastapi.HTTPException`` — a subclass of Starlette's, the
#     idiomatic class route handlers and ``pytest.raises`` clauses
#     reach for.  Registering the handler on the parent class catches
#     both via Starlette's MRO walk.
#
# ``StructuredHTTPException`` therefore inherits from the FastAPI class
# (so ``pytest.raises(fastapi.HTTPException)`` catches it) while the
# handler is keyed on the Starlette parent (so framework-raised 404 +
# every route-raised HTTPException both flow through our wrap).

logger = get_telemetry(__name__)


class StructuredHTTPException(FastAPIHTTPException):
    """HTTPException carrying structured-envelope intent.

    Use this in route handlers instead of
    ``HTTPException(detail={"error": {"code": ..., "message": ...}})`` so
    the structured-envelope contract is encoded by type, not by detail
    shape inspection.

    The :func:`add_error_handlers`-registered HTTPException handler
    detects the structured detail produced by this class and emits the
    structured envelope ``{"error": {"code", "message", "correlation_id"}}``.

    Example::

        raise StructuredHTTPException(
            status_code=404,
            code="resource_not_found",
            message="Resource not found",
        )
    """

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        details: list | dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if details is not None:
            error["details"] = details
        super().__init__(
            status_code=status_code,
            detail={"error": error},
            headers=headers,
        )


def _status_code_name(status_code: int) -> str:  # notrace: pure stdlib lookup
    """Return the canonical name for a status code (e.g. 404 -> NOT_FOUND).

    Falls back to ``HTTP_<code>`` for status codes the stdlib doesn't
    register.  Sourcing names from :mod:`http.HTTPStatus` keeps the
    mapping in lockstep with IANA registrations and prevents drift from
    a hand-rolled table.
    """
    try:
        return http.HTTPStatus(status_code).name
    except ValueError:
        return f"HTTP_{status_code}"


def _get_correlation_id(request: Request) -> str:  # notrace: simple attr lookup
    """Get correlation ID from request state or generate a new one.

    Args:
        request: FastAPI request object.

    Returns:
        Correlation ID string.
    """
    # Try to get correlation ID from RequestCorrelationMiddleware
    correlation_id = getattr(request.state, "correlation_id", None)
    if correlation_id:
        return correlation_id
    # Generate new UUID if not set by middleware
    return str(uuid.uuid4())


def _is_debug_enabled() -> bool:  # notrace: pure bool check, no I/O
    """Check if debug error responses are enabled.

    Returns:
        True if DEBUG_ERROR_RESPONSES env var is truthy.
    """
    debug_env = os.environ.get("DEBUG_ERROR_RESPONSES", "").lower()
    return debug_env in ("true", "1", "yes", "on")


@auto_trace(logger)
def add_error_handlers(
    app: FastAPI,
    include_correlation_id: bool = True,
    correlation_header: str = "X-Correlation-ID",
) -> None:
    """Add standardized error handlers for common HTTP errors.

    Provides a consistent error response format:
    {
        "error": {
            "code": "ERROR_CODE",
            "message": "Human-readable message",
            "correlation_id": "uuid"
        }
    }

    Debug information (stack traces, exception details) is controlled by the
    DEBUG_ERROR_RESPONSES environment variable. When disabled (default), no
    debug information is exposed.

    Routes raise :class:`HTTPException` (idiomatic FastAPI) and the
    type-keyed handler installed below produces the structured envelope.
    For routes that want explicit typing of the structured-detail
    contract, raise :class:`StructuredHTTPException` (defined in this
    module) instead — both produce identical wire output.

    Args:
        app: FastAPI application instance
        include_correlation_id: Include correlation_id in error responses (default: True)
        correlation_header: Header name for correlation ID in response headers

    Prerequisites:
        :class:`RequestCorrelationMiddleware` (from
        ``neoaxios_fastapi_kit.middleware``) MUST be installed before this call
        when ``include_correlation_id=True``.  Without it, every error
        response gets a freshly-generated correlation UUID with no
        relation to the request — useless for log correlation.

    Usage:
        app = FastAPI()
        app.add_middleware(RequestCorrelationMiddleware)  # REQUIRED
        add_error_handlers(app)

        # Enable debug responses via environment variable (NOT in production)
        # export DEBUG_ERROR_RESPONSES=true

    Handles:
        - HTTPException (any status code, route- or framework-raised)
          with structured-detail unwrap or generic envelope
        - 400 Bad Request (ValueError)
        - 422 Validation Error (Pydantic RequestValidationError)
        - 500 Internal Server Error (all uncaught Exception subclasses)
        - 503 Service Unavailable (CircuitBreakerOpenError, with Retry-After)

    Note:
        The :class:`HTTPException` handler is type-keyed, not
        status-code-keyed.  This is load-bearing — registering
        ``@app.exception_handler(404)`` would intercept route-raised
        ``HTTPException(404, detail={"error": ...})`` and discard the
        structured detail, producing a generic NOT_FOUND envelope
        regardless of the route's intent.  Type-keyed dispatch falls
        through Starlette's status-handler check, so framework-raised
        and route-raised HTTPException are handled uniformly.

    """

    def _build_error_response(
        request: Request,
        code: str,
        message: str,
        details: list | dict | None = None,
        exception: Exception | None = None,
    ) -> tuple[dict, dict]:
        """Build error response and headers for the structured envelope.

        Args:
            request: FastAPI request object.
            code: Error code string.
            message: Human-readable error message.
            details: Optional error details (validation errors, etc.)
            exception: Optional exception for debug info.

        Returns:
            Tuple of (response_body, headers).
        """
        correlation_id = _get_correlation_id(request) if include_correlation_id else None

        error_body: dict = {
            "code": code,
            "message": message,
        }

        if correlation_id:
            error_body["correlation_id"] = correlation_id

        if details:
            error_body["details"] = details

        # Debug information only when explicitly enabled
        if _is_debug_enabled() and exception is not None:
            error_body["debug"] = {
                "exception_type": type(exception).__name__,
                "exception_message": str(exception),
                "traceback": traceback.format_exc(),
            }

        response_body = {"error": error_body}

        # Add correlation ID to response headers
        headers = {}
        if correlation_id:
            headers[correlation_header] = correlation_id

        return response_body, headers

    # NOTE: No @auto_trace on exception handlers below - FastAPI exception handlers,
    # not route handlers. Called automatically by FastAPI when errors occur. Tracing
    # the setup function (add_error_handlers) is sufficient for debugging.
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Handle Pydantic validation errors (422)."""
        error_details = []
        for error in exc.errors():
            error_details.append({
                "field": ".".join(str(loc) for loc in error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            })

        response_body, headers = _build_error_response(
            request=request,
            code="VALIDATION_ERROR",
            message="Request validation failed",
            details=error_details,
            exception=exc,
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=response_body,
            headers=headers,
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(
        request: Request,
        exc: ValueError,
    ) -> JSONResponse:
        """Handle ValueError as 400 Bad Request."""
        response_body, headers = _build_error_response(
            request=request,
            code="INVALID_INPUT",
            message=str(exc),
            exception=exc,
        )

        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=response_body,
            headers=headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> Response:
        """Handle every HTTPException with the structured envelope.

        Three input shapes for ``exc.detail``:

        1. ``{"error": {"code": ..., "message": ..., ["details": ...]}}`` —
           the route emitted a structured envelope (typically via
           :class:`StructuredHTTPException`).  The error block is
           unwrapped and re-emitted with ``correlation_id`` added.
        2. ``dict`` of any other shape — emitted as a generic envelope
           with the dict serialised into ``message`` and the code
           derived from ``exc.status_code``.
        3. ``str`` / ``None`` — emitted as a generic envelope with the
           detail string as ``message`` and the code derived from
           ``exc.status_code`` via :func:`http.HTTPStatus`.

        This is a type-keyed handler (registered against the
        :class:`HTTPException` class), not a status-code-keyed handler.
        Per Starlette's exception dispatch
        (``starlette/_exception_handler.py:46-50``), status-code
        handlers fire FIRST for HTTPException — registering
        ``@app.exception_handler(404)`` would intercept ALL
        HTTPException(404), including route-raised exceptions whose
        structured detail must be preserved.  The type-keyed
        registration falls through Starlette's status-handler dispatch,
        so framework-raised HTTPException (e.g. unmatched routes,
        OAuth2 dependencies) and route-raised HTTPException both end up
        here uniformly.

        :class:`RequestValidationError`, :class:`ValueError`, and
        :class:`CircuitBreakerOpenError` are routed through their
        dedicated type-keyed handlers below — those exception trees do
        NOT inherit from HTTPException, so MRO dispatch picks the more
        specific handler before reaching this one.

        Body-less status codes (204, 304, 1xx) return a
        :class:`Response` without body per the HTTP spec
        (RFC 9110 §6.1).
        """
        detail = exc.detail
        details: list | dict | None = None

        if (
            isinstance(detail, dict)
            and isinstance(detail.get("error"), dict)
            and "code" in detail["error"]
            and "message" in detail["error"]
        ):
            # Shape 1a: full structured envelope.
            #   detail = {"error": {"code": ..., "message": ...,
            #                       ["details": ...]}}
            err = detail["error"]
            code = str(err["code"])
            message = str(err["message"])
            details = err.get("details")
        elif (
            isinstance(detail, dict)
            and isinstance(detail.get("error"), str)
        ):
            # Shape 1b: short-form envelope where ``error`` is a code
            # string, optionally accompanied by ``message`` and/or
            # extra context fields at the top level.  Examples:
            #   detail = {"error": "service_unavailable"}
            #   detail = {"error": "resource_not_found", "resource_id": "X"}
            #   detail = {"error": "sync_rejected", "message": "..."}
            # The route's chosen ``error`` string becomes the canonical
            # ``code``.  Top-level ``message`` (if present) is the
            # message; otherwise we fall back to the status phrase.
            # Any other top-level keys flow through as ``details`` so
            # context (account IDs, attempt counts, transition states)
            # reaches the client without losing the structured
            # envelope shape.
            code = detail["error"]
            if "message" in detail:
                message = str(detail["message"])
            else:
                try:
                    message = http.HTTPStatus(exc.status_code).phrase
                except ValueError:
                    message = f"HTTP {exc.status_code}"
            extras = {
                k: v for k, v in detail.items()
                if k not in ("error", "message")
            }
            if extras:
                details = extras
        elif isinstance(detail, dict):
            # Shape 2: dict of other shape — flatten to message.  The
            # full dict is JSON-serialised into the message so
            # operators can recover the original payload, but the
            # structured-envelope contract is preserved.
            code = _status_code_name(exc.status_code)
            message = str(detail)
        else:
            # Shape 3: bare string / None.
            code = _status_code_name(exc.status_code)
            # Detect the framework-default detail.  Starlette's
            # ``HTTPException.__init__`` (``starlette/exceptions.py:9-10``)
            # fills missing ``detail`` with ``http.HTTPStatus(status_code).phrase``
            # — for 404 that is ``"Not Found"``.  A bare phrase carries
            # no information beyond the status code itself, so when the
            # detail equals that phrase enrich it with the request path
            # so logs and clients see which resource missed.  Routes
            # supplying their own ``detail="..."`` keep their message
            # verbatim.
            try:
                framework_default = http.HTTPStatus(exc.status_code).phrase
            except ValueError:
                framework_default = None
            if detail and detail != framework_default:
                message = str(detail)
            elif exc.status_code == 404:
                message = f"Resource not found: {request.url.path}"
            elif detail:
                message = str(detail)
            else:
                message = f"HTTP {exc.status_code}"

        # Body-less status codes per RFC 9110 §6.1 — must not emit a
        # JSON body.  Mirrors FastAPI's default http_exception_handler
        # bail at fastapi/exception_handlers.py:13.
        if not is_body_allowed_for_status_code(exc.status_code):
            response_headers: dict[str, str] = {}
            if getattr(exc, "headers", None):
                response_headers.update(exc.headers)
            return Response(status_code=exc.status_code, headers=response_headers)

        response_body, response_headers = _build_error_response(
            request=request,
            code=code,
            message=message,
            details=details,
            exception=exc,
        )

        # Header merge order: route-attached headers first
        # (e.g. ``WWW-Authenticate`` for 401, ``Allow`` for 405), then
        # request-level headers (correlation_id) — request-level wins
        # so the correlation header is always the request's, never a
        # route-supplied override.
        merged_headers: dict[str, str] = {}
        if getattr(exc, "headers", None):
            merged_headers.update(exc.headers)
        merged_headers.update(response_headers)

        return JSONResponse(
            status_code=exc.status_code,
            content=response_body,
            headers=merged_headers,
        )

    @app.exception_handler(CircuitBreakerOpenError)
    async def circuit_breaker_open_handler(
        request: Request,
        exc: CircuitBreakerOpenError,
    ) -> JSONResponse:
        """Handle CircuitBreakerOpenError as 503 with Retry-After."""
        logger.warning(
            "circuit_breaker_open",
            service=exc.service,
            operation=exc.operation,
            retry_after=exc.retry_after,
            path=str(request.url.path),
        )

        response_body, headers = _build_error_response(
            request=request,
            code="CIRCUIT_BREAKER_OPEN",
            message="Service temporarily unavailable",
            exception=exc,
        )
        headers["Retry-After"] = str(exc.retry_after)

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response_body,
            headers=headers,
        )

    # NOTE: No explicit @app.exception_handler(500) - the generic Exception handler
    # below catches all unhandled exceptions and returns 500. In Starlette/FastAPI,
    # status-code handlers (like 500) only trigger for HTTPException with that status,
    # not for arbitrary exceptions. The generic handler also logs the error.

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Handle all uncaught exceptions as 500 Internal Server Error."""
        # Log the exception for debugging
        logger.error(
            "unhandled_exception",
            exception_type=type(exc).__name__,
            exception_message=str(exc),
            path=str(request.url.path),
        )

        response_body, headers = _build_error_response(
            request=request,
            code="INTERNAL_ERROR",
            message="An internal error occurred",
            exception=exc,
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=response_body,
            headers=headers,
        )
