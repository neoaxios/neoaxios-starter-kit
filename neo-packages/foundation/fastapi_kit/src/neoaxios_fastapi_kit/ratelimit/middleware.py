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

"""Global rate limiting middleware for FastAPI.

This middleware applies rate limits before route handlers are invoked.
Use for:
- Per-tenant API quotas
- Global rate limits across all endpoints
- Defense-in-depth behind nginx

For per-endpoint limits, use the @limiter.limit() decorator instead.

Cross-package imports:
    RateLimitEnforcer and RateLimitBackendError are sourced from
    neoaxios_resilience_kit.ratelimit (framework-agnostic base layer).
    The enforcer raises the non-HTTP RateLimitBackendError on backend
    failure; this middleware catches it and returns JSONResponse(503).
"""

import time
from typing import Callable, Optional, List

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_resilience_kit.ratelimit import (
    RateLimitBackend,
    RateLimitBackendError,
    RateLimitEnforcer,
    parse_rate,
)

from .utils import build_ratelimit_headers, epoch_to_ttl

from neoaxios_secure_cache.defaults import DEFAULT_RETRY_SECONDS

from .key_builder import RateLimitKeyBuilder
from .metrics import RateLimitMetrics, create_metrics

logger = get_telemetry(__name__)


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware for global per-tenant rate limiting.

    Applies rate limits before route handlers are invoked.
    All rate limiting is fail-closed.

    Attributes:
        enforcer: Rate limit enforcer
        key_builder: Key construction utility
        rate: Global rate limit (e.g., "10000/3600s")
        scope: Rate limit scope ("tenant", "user", "ip", "global")
        exclude_paths: Paths to exclude from limiting

    Example:
        app.add_middleware(
            GlobalRateLimitMiddleware,
            backend=redis_backend,
            hmac_key=b"secret-key",
            rate="10000/3600s",
            scope="tenant",
            exclude_paths=["/health", "/metrics"],
        )
    """

    @auto_trace(logger)
    def __init__(
        self,
        app: ASGIApp,
        backend: RateLimitBackend,
        hmac_key: bytes,
        rate: str,
        scope: str = "tenant",
        exclude_paths: Optional[List[str]] = None,
        key_prefix: str = "ratelimit:global:",
        trusted_proxies: Optional[List[str]] = None,
        include_epoch_timestamp: bool = False,
        metrics: RateLimitMetrics | None = None,
    ) -> None:
        """Initialize global rate limit middleware.

        All rate limiting is fail-closed.
        When the backend is unavailable, requests receive 503 Service Unavailable.

        Args:
            app: ASGI application
            backend: Rate limit storage backend
            hmac_key: HMAC key for key obfuscation
            rate: Global rate limit string
            scope: Rate limit scope
            exclude_paths: Paths to exclude from rate limiting
            key_prefix: Prefix for rate limit keys
            trusted_proxies: Trusted proxy IPs
            include_epoch_timestamp: Include X-RateLimit-Reset-At epoch header
            metrics: Optional metrics instance for Prometheus instrumentation
        """
        super().__init__(app)

        self.enforcer = RateLimitEnforcer(backend=backend)
        self.key_builder = RateLimitKeyBuilder(
            hmac_key=hmac_key,
            key_prefix=key_prefix,
            trusted_proxies=trusted_proxies,
        )
        self._metrics = metrics or create_metrics()

        self.rate = rate
        self.scope = scope
        self.exclude_paths = set(exclude_paths or ["/health", "/metrics", "/ready"])
        self.include_epoch_timestamp = include_epoch_timestamp

        self.limit, self.window_seconds = parse_rate(rate)

        logger.info(
            "Initialized GlobalRateLimitMiddleware",
            rate=rate,
            scope=scope,
            exclude_paths=list(self.exclude_paths),
        )

    @auto_trace(logger)
    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through rate limiter."""
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Build rate limit key (fail-closed)
        try:
            key = self._build_key(request)
        except ValueError as e:
            # Scope requires identity (tenant/user) but not authenticated.
            # Fail-closed: deny request rather than silently skipping rate limit.
            logger.warning(
                "Rate limit key unavailable - denying request (fail-closed)",
                scope=self.scope,
                error=str(e),
                path=request.url.path,
            )
            return JSONResponse(
                status_code=503,
                content={"detail": "Rate limiting service unavailable"},
                headers={"Retry-After": str(DEFAULT_RETRY_SECONDS)},
            )

        # Fail-closed: if backend is unavailable, return 503 Service Unavailable.
        # We catch the exception here and return a JSONResponse instead of
        # letting it propagate, because BaseHTTPMiddleware
        # converts all unhandled exceptions to 500 responses.
        start = time.monotonic()
        try:
            result = await self.enforcer.check_and_record(
                key=key,
                limit=self.limit,
                window_seconds=self.window_seconds,
                cost=1,
            )
        except RateLimitBackendError as e:
            duration_seconds = time.monotonic() - start
            logger.warning(
                "Rate limit backend unavailable - rejecting request (fail-closed)",
                error=str(e),
                duration_seconds=duration_seconds,
            )
            self._metrics.record_backend_error(
                backend="redis",
                error_type="backend_unavailable",
            )
            self._metrics.record_check(
                scope=self.scope,
                allowed=False,
                remaining=0,
                limit=self.limit,
                duration_seconds=duration_seconds,
                cost=1,
                endpoint=request.url.path,
            )
            self._metrics.set_backend_health(backend="redis", healthy=False)
            return JSONResponse(
                status_code=503,
                content={"detail": "Rate limit backend unavailable"},
                headers={"Retry-After": str(DEFAULT_RETRY_SECONDS)},
            )
        duration_seconds = time.monotonic() - start

        # Record Prometheus metrics on non-error path (both allowed and denied)
        self._metrics.record_check(
            scope=self.scope,
            allowed=result.allowed,
            remaining=result.remaining,
            limit=self.limit,
            duration_seconds=duration_seconds,
            cost=1,
            endpoint=request.url.path,
        )
        self._metrics.set_backend_health(backend="redis", healthy=True)

        if not result.allowed:
            logger.warning(
                "Global rate limit exceeded",
                key=key,
                scope=self.scope,
                limit=self.limit,
            )
            # Return 429 response directly instead of raising exception
            # to avoid ExceptionGroup wrapping in BaseHTTPMiddleware
            headers = build_ratelimit_headers(
                limit=self.limit,
                remaining=0,
                reset_seconds=epoch_to_ttl(result.reset_at),
                window_seconds=self.window_seconds,
                include_retry_after=True,
                include_epoch=self.include_epoch_timestamp,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers=headers,
            )

        # Continue to route handler
        response = await call_next(request)

        # Add IETF-compliant rate limit headers to successful responses
        headers = build_ratelimit_headers(
            limit=self.limit,
            remaining=result.remaining,
            reset_seconds=epoch_to_ttl(result.reset_at),
            window_seconds=self.window_seconds,
            include_retry_after=False,
            include_epoch=self.include_epoch_timestamp,
        )
        for name, value in headers.items():
            response.headers[name] = value

        return response

    @auto_trace(logger)
    def _build_key(self, request: Request) -> str:
        """Build rate limit key based on scope."""
        return self.key_builder.resolve_scope_key(request, self.scope)
