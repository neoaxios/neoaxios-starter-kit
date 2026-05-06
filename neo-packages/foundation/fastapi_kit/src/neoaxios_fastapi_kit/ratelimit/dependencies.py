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

"""FastAPI dependencies for rate limiting.

This module provides FastAPI dependency injection functions for
integrating rate limiting into route handlers.

Usage:
    from neoaxios_fastapi_kit.ratelimit.dependencies import (
        get_rate_limiter,
        RateLimitDep,
    )

    @app.get("/api/resource")
    async def get_resource(
        request: Request,
        limiter: RateLimiter = Depends(get_rate_limiter),
    ):
        ...
"""

import inspect
import time
from typing import Awaitable, Callable, Optional, Union

from fastapi import Depends, HTTPException, Request, Response

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_resilience_kit.ratelimit import parse_rate

from .utils import build_ratelimit_headers, epoch_to_ttl

from .exceptions import RateLimitExceeded, RateLimitBackendError
from .limiter import RateLimiter
from .metrics import create_metrics

logger = get_telemetry(__name__)


# Global rate limiter instance (initialized at startup)
_rate_limiter: Optional[RateLimiter] = None

# Flag to indicate rate limiting is explicitly disabled
_rate_limiter_disabled: bool = False


@auto_trace(logger)
def configure_rate_limiter(limiter: RateLimiter) -> None:
    """Configure the global rate limiter instance.

    Call this during application startup to configure the rate limiter
    that will be injected into route handlers.

    Args:
        limiter: Configured RateLimiter instance

    Example:
        from contextlib import asynccontextmanager
        from fastapi import FastAPI

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            limiter = create_rate_limiter(
                backend=redis_backend,
                hmac_key=b"secret",
            )
            configure_rate_limiter(limiter)
            yield

        app = FastAPI(lifespan=lifespan)
    """
    global _rate_limiter, _rate_limiter_disabled
    _rate_limiter = limiter
    _rate_limiter_disabled = False
    logger.info("Rate limiter configured for dependency injection")


@auto_trace(logger)
def disable_rate_limiter() -> None:
    """Explicitly disable rate limiting.

    Call this during application startup when rate limiting should be
    completely disabled. All rate limit checks will pass through without
    any enforcement.

    Use this for testing environments or when rate limiting infrastructure
    is not available.

    Example:
        from contextlib import asynccontextmanager
        from fastapi import FastAPI

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            if os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "false":
                disable_rate_limiter()
            else:
                configure_rate_limiter(limiter)
            yield

        app = FastAPI(lifespan=lifespan)
    """
    global _rate_limiter_disabled
    _rate_limiter_disabled = True
    logger.info("Rate limiting explicitly disabled")


@auto_trace(logger)
def is_rate_limiter_disabled() -> bool:
    """Check if rate limiting is explicitly disabled.

    Returns:
        True if disable_rate_limiter() was called, False otherwise
    """
    return _rate_limiter_disabled


@auto_trace(logger)
def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance.

    Use as a FastAPI dependency to inject the rate limiter.

    Returns:
        Configured RateLimiter instance

    Raises:
        RuntimeError: If rate limiter not configured and not disabled

    Example:
        @app.get("/api/resource")
        async def get_resource(
            limiter: RateLimiter = Depends(get_rate_limiter),
        ):
            ...
    """
    if _rate_limiter_disabled:
        raise RuntimeError(
            "Rate limiter is disabled. "
            "Use is_rate_limiter_disabled() to check before calling get_rate_limiter()."
        )
    if _rate_limiter is None:
        raise RuntimeError(
            "Rate limiter not configured. "
            "Call configure_rate_limiter() or disable_rate_limiter() during application startup."
        )
    return _rate_limiter


# Type alias for cleaner dependency injection
RateLimitDep = RateLimiter


@auto_trace(logger)
def require_rate_limit(
    rate: str,
    scope: str = "user",
    cost: int = 1,
    limit_resolver: Union[
        Callable[[Request], Union[tuple[int, int], None]],
        Callable[[Request], Awaitable[Union[tuple[int, int], None]]],
        None,
    ] = None,
):
    """Create a dependency that enforces a rate limit.

    Use as a dependency to apply rate limiting to a route without
    using the decorator.

    When rate limiting is disabled via disable_rate_limiter(), this
    dependency becomes a no-op that always allows the request through.

    Args:
        rate: Rate limit string (e.g., "100/60s")
        scope: Rate limit scope
        cost: Cost per request
        limit_resolver: Optional callback that dynamically overrides the
            base rate limit at request time.  Accepts both sync and async
            callables.  Return ``(requests, window_seconds)`` to override
            or ``None`` to keep the base limit.

    Returns:
        Dependency function that enforces rate limit

    Example:
        @app.get("/api/resource", dependencies=[Depends(require_rate_limit("100/60s"))])
        async def get_resource():
            ...
    """
    # Pre-compute constant values once at definition time, not per-request
    _metrics = create_metrics()
    _parsed_limit, _parsed_window = parse_rate(rate)
    # Hoist sync/async discrimination. Reflection on the callable is
    # constant for a given resolver and does not belong on the hot path.
    _resolver_is_async = (
        inspect.iscoroutinefunction(limit_resolver)
        if limit_resolver is not None
        else False
    )

    async def rate_limit_dependency(
        request: Request,
        response: Response,
    ) -> None:
        # Check if rate limiting is disabled - if so, skip all checks
        if _rate_limiter_disabled:
            return

        # Get the rate limiter - will raise if not configured
        if _rate_limiter is None:
            raise RuntimeError(
                "Rate limiter not configured. "
                "Call configure_rate_limiter() or disable_rate_limiter() during application startup."
            )
        limiter = _rate_limiter
        metrics = _metrics

        # Use pre-parsed rate values (hoisted to outer scope)
        limit_value, window = _parsed_limit, _parsed_window

        if limit_resolver is not None:
            if _resolver_is_async:
                resolved = await limit_resolver(request)
            else:
                resolved = limit_resolver(request)
            if resolved is not None:
                limit_value, window = resolved

        try:
            # Build key using limiter's method
            key = limiter._get_key(request, scope, None)
        except ValueError as e:
            # Identity missing or invalid — fail-closed (503)
            logger.warning(
                "Rate limit identity extraction failed - denying request (fail-closed)",
                scope=scope,
                error=str(e),
                path=request.url.path,
            )
            metrics.record_backend_error(
                backend="identity",
                error_type="extraction_failed",
            )
            raise HTTPException(
                status_code=503,
                detail="Rate limiting service unavailable",
            ) from e

        # Check rate limit
        _check_start = time.monotonic()
        try:
            result = await limiter.enforcer.check_and_record(
                key=key,
                limit=limit_value,
                window_seconds=window,
                cost=cost,
            )
        except RateLimitBackendError as exc:
            _check_duration = time.monotonic() - _check_start
            logger.warning(
                "Rate limit backend unavailable - denying request (fail-closed)",
                scope=scope,
                error=str(exc),
                path=request.url.path,
                duration_seconds=_check_duration,
            )
            metrics.record_backend_error(
                backend="redis",
                error_type="backend_unavailable",
            )
            metrics.set_backend_health(backend="redis", healthy=False)
            raise HTTPException(
                status_code=503,
                detail="Rate limiting service unavailable",
            ) from exc
        _check_duration = time.monotonic() - _check_start

        # Record Prometheus metrics
        metrics.record_check(
            scope=scope,
            allowed=result.allowed,
            remaining=result.remaining,
            limit=limit_value,
            duration_seconds=_check_duration,
            endpoint=request.url.path,
            cost=cost,
        )
        metrics.set_backend_health(backend="redis", healthy=True)

        if not result.allowed:
            raise RateLimitExceeded(
                limit=limit_value,
                window_seconds=window,
                retry_after=result.retry_after,
                scope=scope,
            )

        # Set IETF-compliant rate limit headers on successful responses
        include_epoch = limiter.config.include_epoch_timestamp
        headers = build_ratelimit_headers(
            limit=limit_value,
            remaining=result.remaining,
            reset_seconds=epoch_to_ttl(result.reset_at),
            window_seconds=window,
            include_retry_after=False,
            include_epoch=include_epoch,
        )
        for name, value in headers.items():
            response.headers[name] = value

    return rate_limit_dependency
