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

"""Authentication middleware for FastAPI services.

Provides AuthMiddleware for token validation at the middleware layer,
setting validated IdentityContext on scope["state"] for downstream
middleware and route handlers.

Pure ASGI implementation — no BaseHTTPMiddleware or run_in_threadpool.

Skip paths must be a subset of ``ALLOWED_SKIP_PATHS``.
"""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import TYPE_CHECKING

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.authn.errors import TokenExpiredError, TokenInvalidError
from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_HEADER, DEFAULT_TOKEN_PREFIX
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.middleware import get_asgi_header

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from neoaxios_fastapi_kit.auth.config.schemas import AuthMode
    from neoaxios_fastapi_kit.auth.protocols import TokenDecoder

logger = get_telemetry(__name__)

# Loopback addresses for DISABLED mode restriction.
_LOOPBACK_ADDRESSES: frozenset[str] = frozenset({
    "127.0.0.1",
    "::1",
    "localhost",
})


# =============================================================================
# Path Exclusion Configuration
# =============================================================================

# Allowlist of paths that MAY bypass authentication (security allowlist).
# Only these paths can be added to skip_paths — any other path rejected at init.
ALLOWED_SKIP_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/live",
    "/health/ready",
    "/live",
    "/ready",
    "/metrics",
    "/info",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/openapi.json",
    "/favicon.ico",
    "/robots.txt",
})

# Allowlist of prefixes that MAY bypass authentication.
ALLOWED_SKIP_PREFIXES: frozenset[str] = frozenset({
    "/docs/",
    "/redoc/",
    "/openapi/",
})

# Default skip configuration (subset of allowlist).
DEFAULT_SKIP_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/live",
    "/health/ready",
    "/live",
    "/ready",
    "/metrics",
    "/info",
})

# Default prefix skip configuration (subset of allowlist).
DEFAULT_SKIP_PREFIXES: frozenset[str] = frozenset({
    "/docs/",
    "/redoc/",
    "/openapi/",
})

# DISABLED mode hardcoded identity (no header back-channel).
# Must match AnonymousDecoder defaults for consistency.
DEV_TENANT_ID: str = "dev-tenant"
DEV_USER_ID: str = "dev-user-001"

# Token validation limits.
MAX_TOKEN_LENGTH: int = 8192  # 8KB max for JWT + claims

# Pre-encode header name for ASGI lookup (lowercase bytes).
_AUTH_HEADER_NAME: bytes = DEFAULT_TOKEN_HEADER.lower().encode("latin-1")
_TOKEN_PREFIX: str = DEFAULT_TOKEN_PREFIX


# =============================================================================
# Read-Only Identity Wrapper
# =============================================================================


class ReadOnlyIdentityWrapper:
    """Prevents identity modification after middleware validation.

    Wraps an IdentityContext and delegates read access while blocking
    attribute assignment to enforce immutability after auth validation.
    """

    __slots__ = ("_identity", "_sealed")

    def __init__(self, identity: IdentityContext) -> None:
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_sealed", True)

    @property
    def identity(self) -> IdentityContext:
        """Read-only access to wrapped identity."""
        return self._identity

    @property
    def tenant_id(self) -> str:
        """Delegated read-only tenant_id."""
        return self._identity.tenant_id

    @property
    def user_id(self) -> str:
        """Delegated read-only user_id."""
        return self._identity.user_id

    @property
    def roles(self) -> frozenset[str]:
        """Delegated read-only roles."""
        return self._identity.roles

    @property
    def permissions(self) -> frozenset[str]:
        """Delegated read-only permissions."""
        return self._identity.permissions

    @property
    def provider(self) -> str:
        """Delegated read-only provider."""
        return self._identity.provider

    @property
    def attributes(self) -> MappingProxyType:
        """Delegated read-only attributes (immutable view)."""
        return MappingProxyType(self._identity.attributes)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            "Identity is read-only after middleware validation"
        )

    def __repr__(self) -> str:
        return (
            f"ReadOnlyIdentityWrapper(user_id={self._identity.user_id!r}, "
            f"tenant_id={self._identity.tenant_id!r})"
        )


# =============================================================================
# ASGI Error Response Helper
# =============================================================================


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
async def _send_error_response(
    send: Send,
    status_code: int,
    code: str,
    message: str,
    correlation_id: str | None = None,
) -> None:
    """Send a JSON error response via raw ASGI messages.

    Args:
        send: ASGI send callable.
        status_code: HTTP status code.
        code: Machine-readable error code.
        message: Human-readable error message (generic, no internals).
        correlation_id: Request correlation ID if available.
    """
    body_dict: dict[str, str] = {
        "code": code,
        "message": message,
    }
    if correlation_id:
        body_dict["correlation_id"] = correlation_id

    body_bytes = json.dumps(body_dict).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body_bytes)).encode("latin-1")),
    ]

    await send({
        "type": "http.response.start",
        "status": status_code,
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body_bytes,
    })


# =============================================================================
# ASGI Header Helpers
# =============================================================================

@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def _extract_token_from_scope(scope: Scope) -> str:
    """Extract bearer token from Authorization header in ASGI scope.

    Args:
        scope: ASGI scope dict.

    Returns:
        JWT token string.

    Raises:
        AuthError: If authorization header is missing or malformed.
    """
    auth_header = get_asgi_header(scope, _AUTH_HEADER_NAME)

    if not auth_header:
        raise AuthError("Missing authorization token")

    if not auth_header.startswith(_TOKEN_PREFIX):
        raise AuthError(
            f"Invalid authorization header format. Expected '{_TOKEN_PREFIX}' prefix"
        )

    token = auth_header[len(_TOKEN_PREFIX):].strip()

    if not token:
        raise AuthError("Empty authorization token")

    return token


# =============================================================================
# Auth Middleware
# =============================================================================


class AuthMiddleware:
    """Validates tokens and sets immutable scope["state"]["identity"].

    Pure ASGI middleware implementing __call__(scope, receive, send).
    Sits in the middleware stack before any middleware that needs
    tenant identity (idempotency, rate limiting). Extracts bearer
    token, validates via configured decoder, checks revocation,
    and stores validated IdentityContext in scope["state"].

    Fail-closed: ANY error during authentication results in access
    denial (401 or 503). There is no fallback or fail-open path.
    """

    def __init__(
        self,
        app: ASGIApp,
        decoder: TokenDecoder | None = None,
        mode: AuthMode | None = None,
        skip_paths: frozenset[str] = DEFAULT_SKIP_PATHS,
        skip_path_prefixes: frozenset[str] = DEFAULT_SKIP_PREFIXES,
    ) -> None:
        """Initialize AuthMiddleware.

        Args:
            app: ASGI application.
            decoder: Token decoder for validation. Required for
                non-DISABLED modes.
            mode: Authentication mode. Defaults to OIDC if not specified.
            skip_paths: Exact paths that bypass auth. Must be subset
                of ALLOWED_SKIP_PATHS.
            skip_path_prefixes: Path prefixes that bypass auth. Must be
                subset of ALLOWED_SKIP_PREFIXES.

        Raises:
            ValueError: If skip_paths or skip_path_prefixes contain
                paths not in the respective allowlists.
        """
        self.app = app

        # Import here to avoid circular import at module level
        from neoaxios_fastapi_kit.auth.config.schemas import AuthMode as _AuthMode

        self._decoder = decoder
        self._mode = mode or _AuthMode.OIDC
        self._skip_paths = skip_paths
        self._skip_path_prefixes = skip_path_prefixes

        # Validate skip paths against allowlist
        invalid_paths = skip_paths - ALLOWED_SKIP_PATHS
        if invalid_paths:
            msg = (
                f"Skip paths not in ALLOWED_SKIP_PATHS: {invalid_paths}. "
                f"Only infrastructure/documentation paths can skip auth."
            )
            raise ValueError(msg)

        invalid_prefixes = skip_path_prefixes - ALLOWED_SKIP_PREFIXES
        if invalid_prefixes:
            msg = (
                f"Skip prefixes not in ALLOWED_SKIP_PREFIXES: {invalid_prefixes}. "
                f"Only infrastructure/documentation prefixes can skip auth."
            )
            raise ValueError(msg)

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _should_skip_auth(self, path: str) -> bool:
        """Check if path should skip authentication.

        Args:
            path: Request URL path.

        Returns:
            True if path is excluded from auth.
        """
        if path in self._skip_paths:
            return True
        return any(path.startswith(prefix) for prefix in self._skip_path_prefixes)

    @auto_trace(logger)
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point — validate token and set scope state.

        Non-HTTP scopes (websocket, lifespan) are passed through unchanged.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        await self._handle_http(scope, receive, send)

    @auto_trace(logger)
    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Validate token and set scope["state"] identity.

        Validation flow:
        1. Check path exclusion
        2. Check auth mode (DISABLED -> decoder or localhost check)
        3. Extract and validate token format
        4. Decode token via decoder
        5. Check revocation
        6. Wrap identity in ReadOnlyIdentityWrapper
        7. Set scope["state"] and proceed
        """
        from neoaxios_fastapi_kit.auth.config.schemas import AuthMode as _AuthMode

        # Ensure scope["state"] dict exists for downstream consumers
        if "state" not in scope:
            scope["state"] = {}

        path: str = scope["path"]
        state: dict = scope["state"]
        correlation_id: str | None = state.get("correlation_id")

        # 1. Check path exclusion
        if self._should_skip_auth(path):
            state["identity"] = None
            state["auth_skipped"] = True
            state["_identity_validated"] = True
            await self.app(scope, receive, send)
            return

        # 2. Check DISABLED mode
        if self._mode == _AuthMode.DISABLED:
            if self._decoder is not None:
                # Decoder provided (e.g., AnonymousDecoder) — use it directly
                try:
                    identity = await self._decoder.decode(None)
                except Exception as exc:
                    logger.error(
                        "auth_disabled_decoder_exception",
                        error=str(exc),
                        path=path,
                    )
                    await _send_error_response(
                        send,
                        503,
                        "AUTH_SERVICE_UNAVAILABLE",
                        "Authentication service unavailable",
                        correlation_id,
                    )
                    return
                wrapped = ReadOnlyIdentityWrapper(identity)
                state["identity"] = wrapped
                state["auth_skipped"] = False
                state["_identity_validated"] = True
                await self.app(scope, receive, send)
                return

            # No decoder — use hardcoded identity with localhost restriction
            await self._handle_disabled_mode(scope, receive, send, correlation_id)
            return

        # 3. Validate decoder is configured
        if self._decoder is None:
            logger.error(
                "auth_middleware_misconfigured",
                mode=str(self._mode),
                path=path,
            )
            await _send_error_response(
                send,
                401,
                "AUTH_REQUIRED",
                "Authentication required",
                correlation_id,
            )
            return

        # 4. Extract token from ASGI headers
        try:
            token = _extract_token_from_scope(scope)
        except AuthError:
            await _send_error_response(
                send,
                401,
                "AUTH_MISSING",
                "Missing authorization",
                correlation_id,
            )
            return

        # 5. Token input validation
        validation_error = self._validate_token_format(token)
        if validation_error:
            await _send_error_response(
                send,
                401,
                "AUTH_INVALID_FORMAT",
                "Invalid token format",
                correlation_id,
            )
            return

        # 6. Decode token
        try:
            identity = await self._decoder.decode(token)
        except (TokenInvalidError, TokenExpiredError):
            await _send_error_response(
                send,
                401,
                "AUTH_INVALID_TOKEN",
                "Invalid or expired token",
                correlation_id,
            )
            return
        except Exception as exc:
            logger.error(
                "auth_decoder_exception",
                error=str(exc),
                error_type=type(exc).__name__,
                path=path,
            )
            await _send_error_response(
                send,
                503,
                "AUTH_SERVICE_UNAVAILABLE",
                "Authentication service unavailable",
                correlation_id,
            )
            return

        # 7. Check revocation (fail-closed)
        try:
            if await self._decoder.is_revoked(token):
                await _send_error_response(
                    send,
                    401,
                    "AUTH_REVOKED",
                    "Token is no longer valid",
                    correlation_id,
                )
                return
        except Exception as exc:
            logger.error(
                "auth_revocation_check_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                path=path,
            )
            await _send_error_response(
                send,
                503,
                "AUTH_VERIFICATION_FAILED",
                "Unable to verify token status",
                correlation_id,
            )
            return

        # 8. Set validated identity on scope state
        wrapped = ReadOnlyIdentityWrapper(identity)
        state["identity"] = wrapped
        state["auth_skipped"] = False
        state["_identity_validated"] = True

        logger.info(
            "auth_identity_validated",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            path=path,
        )

        await self.app(scope, receive, send)

    @auto_trace(logger)
    async def _handle_disabled_mode(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        correlation_id: str | None,
    ) -> None:
        """Handle DISABLED auth mode with localhost restriction.

        Args:
            scope: ASGI scope dict.
            receive: ASGI receive callable.
            send: ASGI send callable.
            correlation_id: Request correlation ID.
        """
        state: dict = scope["state"]
        path: str = scope["path"]

        # Verify request is from localhost/loopback using the socket peer
        # address only. X-Forwarded-For is NOT checked here because DISABLED
        # mode is a dev-only security boundary: trusting a client-provided
        # header would allow any remote client to spoof localhost access.
        client = scope.get("client")
        client_host: str | None = client[0] if client else None
        if client_host not in _LOOPBACK_ADDRESSES:
            logger.warning(
                "disabled_mode_non_localhost",
                client_host=client_host,
                path=path,
            )
            await _send_error_response(
                send,
                401,
                "AUTH_REQUIRED",
                "Authentication required",
                correlation_id,
            )
            return

        # Create hardcoded dev identity with minimal permissions.
        # DISABLED mode is development-only; grant read/write but not admin.
        identity = IdentityContext(
            user_id=DEV_USER_ID,
            tenant_id=DEV_TENANT_ID,
            roles=frozenset(["anonymous"]),
            permissions=frozenset(["read", "write", "execute"]),
            provider="disabled",
        )

        wrapped = ReadOnlyIdentityWrapper(identity)
        state["identity"] = wrapped
        state["auth_skipped"] = False
        state["_identity_validated"] = True

        await self.app(scope, receive, send)

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _validate_token_format(token: str) -> str | None:
        """Validate token format before decoding.

        Checks:
        - Length within MAX_TOKEN_LENGTH
        - ASCII-only characters (no unicode homoglyphs)
        - No null bytes

        Args:
            token: Raw token string.

        Returns:
            Error description if invalid, None if valid.
        """
        if len(token) > MAX_TOKEN_LENGTH:
            return "Token exceeds maximum length"

        try:
            token.encode("ascii")
        except UnicodeEncodeError:
            return "Token contains non-ASCII characters"

        if "\x00" in token:
            return "Token contains null bytes"

        return None
