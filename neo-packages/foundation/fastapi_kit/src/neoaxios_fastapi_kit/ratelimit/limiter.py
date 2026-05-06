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

"""Rate limiter with decorator-based endpoint limiting."""

import time
from functools import wraps
from posixpath import normpath
from typing import Any, Callable, Optional, Union

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_resilience_kit.ratelimit import (
    FixedWindowAlgorithm,
    RateLimitAlgorithm,
    RateLimitBackend,
    RateLimitBackendError as ResilienceBackendError,
    RateLimitConfig,
    RateLimitEnforcer,
    RateLimitResult,
    parse_rate,
)

from .utils import build_ratelimit_headers, epoch_to_ttl

from .exceptions import HTTPRateLimitBackendError, RateLimitExceeded
from .key_builder import RateLimitKeyBuilder
from .metrics import RateLimitMetrics, create_metrics

logger = get_telemetry(__name__)

# =============================================================================
# FastAPI Kit Default Algorithm
# =============================================================================

DEFAULT_ALGORITHM = FixedWindowAlgorithm
"""Default rate limiting algorithm for all FastAPI rate limiters.

All code in neoaxios_fastapi_kit that needs a default algorithm references this variable.
To change the default across the entire FastAPI stack, change this single line.
"""


class RateLimiter:
    """Redis-backed rate limiter for FastAPI applications.

    Provides decorator-based rate limiting with support for:
    - Per-user, per-tenant, per-endpoint limits
    - Cost-based limiting for expensive operations

    All rate limiting is fail-closed.
    When the backend is unavailable, requests receive 503 Service Unavailable.

    Attributes:
        enforcer: Rate limit enforcer
        key_builder: Key construction with HMAC obfuscation
        config: Global configuration

    Example:
        limiter = create_rate_limiter(
            hmac_key=b"secret-key",
        )

        @app.get("/api/resource")
        @limiter.limit("100/60s")
        async def get_resource(request: Request):
            return {"data": "..."}
    """

    @auto_trace(logger)
    def __init__(
        self,
        backend: RateLimitBackend,
        key_builder: RateLimitKeyBuilder,
        algorithm: Optional[RateLimitAlgorithm] = None,
        config: Optional[RateLimitConfig] = None,
        metrics: Optional[RateLimitMetrics] = None,
    ) -> None:
        """Initialize rate limiter.

        Use create_rate_limiter() factory function instead.
        """
        self.config = config or RateLimitConfig()
        self.key_builder = key_builder
        self._metrics = metrics or create_metrics()
        self.enforcer = RateLimitEnforcer(
            backend=backend,
            algorithm=algorithm,
            config=self.config,
        )

        logger.info(
            "Initialized RateLimiter",
            prefix=self.config.key_prefix,
        )

    @auto_trace(logger)
    def limit(
        self,
        rate: str,
        key_func: Optional[Callable[[Request], str]] = None,
        cost: Union[int, Callable[[Request], int]] = 1,
        scope: str = "user",
    ) -> Callable:
        """Decorator to apply rate limiting to an endpoint.

        All rate limiting is fail-closed.
        When the backend is unavailable, requests receive 503 Service Unavailable.

        Args:
            rate: Rate limit string (e.g., "100/60s", "10/1s")
            key_func: Custom function to extract rate limit key
            cost: Cost per request (int or callable)
            scope: Key scope - "user", "tenant", "ip", or "global"

        Returns:
            Decorated async function with rate limiting

        Raises:
            RateLimitExceeded: When rate limit exceeded (HTTP 429)
            RateLimitBackendError: When backend fails (HTTP 503, fail-closed)
        """
        limit_value, window_seconds = parse_rate(rate)

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Any:
                # Build rate limit key
                key = self._get_key(request, scope, key_func)

                # Calculate cost
                request_cost = cost(request) if callable(cost) else cost

                start = time.monotonic()
                try:
                    # Check rate limit (fail-closed: raises on backend error)
                    result = await self.enforcer.check_and_record(
                        key=key,
                        limit=limit_value,
                        window_seconds=window_seconds,
                        cost=request_cost,
                    )
                    duration_seconds = time.monotonic() - start

                    # Record Prometheus metrics on non-error path
                    self._metrics.record_check(
                        scope=scope,
                        allowed=result.allowed,
                        remaining=result.remaining,
                        limit=limit_value,
                        duration_seconds=duration_seconds,
                        cost=request_cost,
                        endpoint=request.url.path,
                    )
                    self._metrics.set_backend_health(
                        backend="redis", healthy=True,
                    )

                    if not result.allowed:
                        raise RateLimitExceeded(
                            limit=limit_value,
                            window_seconds=window_seconds,
                            retry_after=result.retry_after,
                            scope=scope,
                        )

                    # Call the wrapped function
                    response = await func(request, *args, **kwargs)

                    # Add IETF-compliant rate limit headers
                    return self._add_headers(
                        response, result, limit_value, window_seconds
                    )

                except (RateLimitExceeded, HTTPException, ValueError):
                    raise
                except ResilienceBackendError as exc:
                    # Catch resilience-kit's non-HTTP backend error and
                    # wrap it in the HTTP 503 version for FastAPI
                    logger.log_error(exc)
                    self._metrics.record_backend_error(
                        backend="redis", error_type="backend_unavailable",
                    )
                    self._metrics.set_backend_health(
                        backend="redis", healthy=False,
                    )
                    raise HTTPRateLimitBackendError(
                        message="Rate limiting service unavailable",
                        original_error=exc.original_error,
                        backend_type=exc.backend_type,
                    )
                except Exception as exc:
                    # Fail-closed: return 503 on backend/infrastructure errors
                    logger.log_error(exc)
                    self._metrics.record_backend_error(
                        backend="redis", error_type="backend_unavailable",
                    )
                    self._metrics.set_backend_health(
                        backend="redis", healthy=False,
                    )
                    raise HTTPRateLimitBackendError(
                        message="Rate limiting service unavailable",
                        original_error=exc,
                    )

            return wrapper
        return decorator

    @auto_trace(logger)
    def _get_key(
        self,
        request: Request,
        scope: str,
        key_func: Optional[Callable[[Request], str]],
    ) -> str:
        """Build rate limit key based on scope or custom function.

        For decorator-based limiting, includes endpoint path in the key
        so different endpoints have separate rate limit buckets.
        """
        if key_func:
            raw_key = key_func(request)
            return f"{self.config.key_prefix}{raw_key}"

        # Resolve base key via centralized scope dispatch
        base_key = self.key_builder.resolve_scope_key(request, scope)

        if scope == "global":
            # Global scope is shared across all endpoints
            return base_key

        # Include endpoint path in key for per-endpoint rate limiting.
        # Normalize to prevent path traversal bypass (e.g. /api/../api).
        # Strip trailing slashes so /api/resource and /api/resource/ share a bucket.
        endpoint_path = normpath(request.url.path).rstrip("/") or "/"
        return f"{base_key}:ep:{endpoint_path}"

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _add_headers(
        self,
        response: Any,
        result: RateLimitResult,
        limit: int,
        window_seconds: int,
    ) -> Any:
        """Add IETF-compliant rate limit headers to response.

        Emits both IETF RateLimit-* headers and legacy X-RateLimit-* headers
        for backward compatibility.

        Handles both Response objects and dict/model responses by wrapping
        the latter in JSONResponse with the appropriate headers.
        """
        include_epoch = self.config.include_epoch_timestamp
        headers = build_ratelimit_headers(
            limit=limit,
            remaining=result.remaining,
            reset_seconds=epoch_to_ttl(result.reset_at),
            window_seconds=window_seconds,
            include_retry_after=False,
            include_epoch=include_epoch,
        )

        # If response is a Response object, add headers directly
        if hasattr(response, "headers"):
            for key, value in headers.items():
                response.headers[key] = value
            return response

        # If it's a dict/model, wrap in JSONResponse with headers
        return JSONResponse(content=response, headers=headers)


@auto_trace(logger)
def create_rate_limiter(
    backend: RateLimitBackend,
    hmac_key: bytes,
    algorithm: Optional[RateLimitAlgorithm] = None,
    key_prefix: str = "ratelimit:",
    trusted_proxies: Optional[list[str]] = None,
) -> RateLimiter:
    """Factory function for RateLimiter.

    All rate limiting is fail-closed.

    Args:
        backend: Rate limit storage backend
        hmac_key: HMAC key for key obfuscation (min 16 bytes)
        algorithm: Rate limiting algorithm (default: DEFAULT_ALGORITHM)
        key_prefix: Prefix for all rate limit keys
        trusted_proxies: Trusted proxy IPs for X-Forwarded-For

    Returns:
        Configured RateLimiter instance
    """
    key_builder = RateLimitKeyBuilder(
        hmac_key=hmac_key,
        key_prefix=key_prefix,
        trusted_proxies=trusted_proxies,
    )

    config = RateLimitConfig(
        key_prefix=key_prefix,
    )

    return RateLimiter(
        backend=backend,
        key_builder=key_builder,
        algorithm=algorithm or DEFAULT_ALGORITHM(),
        config=config,
    )
