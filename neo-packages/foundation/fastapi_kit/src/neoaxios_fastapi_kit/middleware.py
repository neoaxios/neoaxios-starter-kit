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

"""Middleware helpers for FastAPI services.

Provides middleware components:
- RequestCorrelationMiddleware: Request Correlation IDs
- RetryAfterMiddleware: Retry-After Headers
- IdempotencyMiddleware: Idempotency Support
- SecurityHeadersMiddleware: Security Headers
- HttpMetricsMiddleware: HTTP request metrics for Prometheus
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time as _time
import uuid
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram
from starlette.datastructures import State
from starlette.responses import Response
from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import (
    CACHE_TTL_LONG,
    DEFAULT_RETRY_SECONDS,
    IDEMPOTENCY_CACHE_RETRY_DELAY_S,
    IDEMPOTENCY_MAX_BODY_SIZE_BYTES,
)

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from neoaxios_secure_cache import CacheBackend

logger = get_telemetry(__name__)

# Methods that support idempotency
IDEMPOTENT_METHODS = {"POST", "PUT", "PATCH"}


def get_asgi_header(scope: Any, name: bytes) -> str | None:  # notrace: hotpath — called per-request in ASGI middleware
    """Extract a header value from ASGI scope headers.

    Shared helper for ASGI header extraction across middleware.
    Header names in ASGI are lowercase bytes per the spec.

    Builds and caches a header dict in scope on first access to avoid
    repeated O(n) scans when called multiple times per request.

    Args:
        scope: ASGI scope dict.
        name: Lowercase header name as bytes.

    Returns:
        Header value as string, or None if not present.
    """
    header_cache = scope.get("_header_cache")
    if header_cache is None:
        header_cache = {k: v for k, v in scope.get("headers", [])}
        scope["_header_cache"] = header_cache
    raw = header_cache.get(name)
    return raw.decode("latin-1") if raw is not None else None


class RequestCorrelationMiddleware:
    """Middleware that generates and propagates request correlation IDs.

    Generates or propagates X-Correlation-ID header for request tracing.
    Stores correlation_id in request.state for use by error handlers.

    Raw ASGI implementation (was BaseHTTPMiddleware) — BaseHTTPMiddleware
    adds ~120-180 µs per request from its task-wrap + body-buffer
    machinery and is known to interact poorly with StreamingResponse.
    The raw-ASGI form is feature-parity and 3-4× faster per request.

    Attributes:
        header_name: Header name for correlation ID (default: X-Correlation-ID)

    Usage:
        app.add_middleware(RequestCorrelationMiddleware)

        # Or with custom header name
        app.add_middleware(
            RequestCorrelationMiddleware,
            header_name="X-Request-ID"
        )
    """

    def __init__(self, app, header_name: str = "X-Correlation-ID") -> None:
        """Initialize correlation middleware.

        Args:
            app: ASGI application.
            header_name: Header name for correlation ID.
        """
        self.app = app
        self._header_name = header_name
        # Pre-encoded byte forms for the ASGI hot path (scope["headers"]
        # carries bytes; encoding once at init avoids per-request work).
        self._header_bytes = header_name.encode("latin-1")
        self._header_bytes_lower = self._header_name.lower().encode("latin-1")

    async def __call__(
        self,
        scope: "Scope",
        receive: "Receive",
        send: "Send",
    ) -> None:
        """ASGI entrypoint.

        1. Pass non-HTTP scopes through unchanged.
        2. Extract incoming correlation ID from scope headers (case-insensitive).
        3. Generate UUID if absent.
        4. Populate request.state.correlation_id via scope["state"] (State()).
        5. Inject header on http.response.start, replacing any existing
           same-named header (preserves the BaseHTTPMiddleware overwrite
           semantic — the route may have set its own X-Correlation-ID and
           the middleware's value wins, matching prior behavior).
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read or generate the correlation ID.
        cid_bytes: Optional[bytes] = None
        for k, v in scope["headers"]:
            if k == self._header_bytes_lower:
                cid_bytes = v
                break
        if not cid_bytes:
            cid_bytes = str(uuid.uuid4()).encode("ascii")

        cid_str = cid_bytes.decode("latin-1")

        # Populate request.state.correlation_id. Starlette's Request.state
        # property does ``scope.setdefault("state", State())`` but FastAPI
        # 0.103+ pre-populates ``scope["state"]`` as a plain dict from
        # lifespan state, so attribute-style writes would fail on the
        # dict. Wrap any pre-existing dict in a State() that uses it as
        # the backing store, so both attribute-style reads
        # (``request.state.correlation_id``, used by error handlers and
        # this kit's structured logger) and mapping-style reads
        # (``request.state["foo"]``, used by some lifespan consumers)
        # continue to work.
        state = scope.get("state")
        if state is None:
            state = State()
            scope["state"] = state
        elif not isinstance(state, State):
            # FastAPI 0.103+ pre-populates scope["state"] as a plain
            # dict from lifespan state. Wrap it in State so attribute-
            # style reads continue to work.
            if isinstance(state, dict):
                state = State(state)
            else:
                state = State()
            scope["state"] = state
        state.correlation_id = cid_str

        # Wrap send() to inject the response header on http.response.start.
        # Drop any existing same-named header so the middleware's value
        # is the single authoritative value (overwrite semantic).
        async def send_with_header(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                existing = message.get("headers") or []
                # Build a new headers list with our header guaranteed once.
                filtered: List[Any] = [
                    (k, v) for (k, v) in existing
                    if k.lower() != self._header_bytes_lower
                ]
                filtered.append((self._header_bytes, cid_bytes))
                message["headers"] = filtered
            await send(message)

        await self.app(scope, receive, send_with_header)


class RetryAfterMiddleware:
    """Middleware that injects Retry-After headers on 429/503 responses.

    Injects Retry-After header on 429 (Too Many Requests) and 503
    (Service Unavailable) responses when not already present.

    Raw ASGI implementation (was BaseHTTPMiddleware) — same speedup
    rationale as :class:`RequestCorrelationMiddleware`.

    Attributes:
        default_retry_seconds: Default Retry-After value in seconds.

    Usage:
        app.add_middleware(RetryAfterMiddleware, default_retry_seconds=60)
    """

    _RETRY_AFTER_KEY = b"retry-after"

    def __init__(self, app, default_retry_seconds: int = DEFAULT_RETRY_SECONDS) -> None:
        """Initialize retry-after middleware.

        Args:
            app: ASGI application.
            default_retry_seconds: Default Retry-After value in seconds.
        """
        self.app = app
        self._default_retry_seconds = default_retry_seconds
        self._retry_value_bytes = str(default_retry_seconds).encode("ascii")

    async def __call__(
        self,
        scope: "Scope",
        receive: "Receive",
        send: "Send",
    ) -> None:
        """ASGI entrypoint — add Retry-After on 429/503 if not already set."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_retry(message: Dict[str, Any]) -> None:
            if (
                message["type"] == "http.response.start"
                and message.get("status") in (429, 503)
            ):
                existing = message.get("headers") or []
                has_retry_after = any(
                    k.lower() == self._RETRY_AFTER_KEY for (k, _v) in existing
                )
                if not has_retry_after:
                    headers = list(existing)
                    headers.append((b"Retry-After", self._retry_value_bytes))
                    message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_retry)


class IdempotencyMiddleware:
    """Middleware that provides idempotency support for mutating requests.

    Pure ASGI middleware -- no BaseHTTPMiddleware or run_in_threadpool.

    For POST/PUT/PATCH requests with Idempotency-Key header:
    - If key not seen before: process request, cache response
    - If key seen before: return cached response

    Idempotency keys are scoped by:
    - Tenant ID (from validated scope["state"]["identity"], NOT from headers)
    - The key header value
    - Request method
    - Request path (including query string)
    - Request body hash (optional, for extra safety)

    SECURITY: Tenant ID MUST come from AuthMiddleware-validated identity.
    Never use X-Tenant-ID header directly - it can be spoofed by clients.

    Note: Cache store is retrieved from scope["app"].state.cache at request time,
    allowing async initialization during app startup.

    Usage:
        # AuthMiddleware MUST be registered before IdempotencyMiddleware
        app.add_middleware(IdempotencyMiddleware, ttl_seconds=86400)
        app.add_middleware(AuthMiddleware, decoder=decoder, mode=mode)
    """

    def __init__(
        self,
        app: ASGIApp,
        ttl_seconds: int = CACHE_TTL_LONG,
        include_body_hash: bool = True,
        key_prefix: str = "idempotency",
        max_body_size_bytes: int = IDEMPOTENCY_MAX_BODY_SIZE_BYTES,
    ) -> None:
        """Initialize idempotency middleware.

        Args:
            app: ASGI application.
            ttl_seconds: TTL for idempotency keys in seconds.
            include_body_hash: Include request body hash in cache key.
            key_prefix: Prefix for cache keys.
            max_body_size_bytes: Maximum body size to hash (default 1MB).
                Bodies larger than this skip hashing to avoid memory issues.
                Note: FastAPI buffers the full body for JSON parsing regardless,
                so this limit only prevents additional memory allocation for hashing.
        """
        self.app = app
        self._ttl_seconds = ttl_seconds
        self._include_body_hash = include_body_hash
        self._key_prefix = key_prefix
        self._max_body_size_bytes = max_body_size_bytes

    @auto_trace(logger)
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point -- dispatch HTTP requests or pass through.

        Non-HTTP scopes (websocket, lifespan) are forwarded unchanged.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        await self._handle_http(scope, receive, send)

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _get_cache_from_scope(self, scope: Scope) -> CacheBackend | None:
        """Get cache from app state via ASGI scope.

        Checks for cache at scope["app"].state.cache or
        scope["app"].state.stores.cache_store for compatibility
        with neoaxios_fastapi_kit patterns.

        Returns None if cache not initialized (e.g., during startup).
        """
        app = scope.get("app")
        if app is None:
            return None

        state = getattr(app, "state", None)
        if state is None:
            return None

        # Check direct cache attribute
        cache = getattr(state, "cache", None)
        if cache is not None:
            return cache

        # Check stores.cache_store pattern (neoaxios_fastapi_kit compat)
        stores = getattr(state, "stores", None)
        if stores is not None:
            return getattr(stores, "cache_store", None)

        return None

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _build_cache_key(
        self,
        tenant_id: str,
        idempotency_key: str,
        method: str,
        path: str,
        query_string: str | None = None,
        body_hash: str | None = None,
    ) -> str:
        """Build cache key for idempotency lookup.

        Key format: ``{key_prefix}:{tenant_id}:{idempotency_key}:{request_hash}``

        The request_hash is a SHA-256 digest of method+path+query_string+body_hash,
        keeping the key length bounded regardless of URL length.

        Registry entry: ``workflow:cache:idempotency``.

        Args:
            tenant_id: Tenant identifier from validated identity (NOT from headers).
            idempotency_key: Client-provided idempotency key.
            method: HTTP method.
            path: Request path.
            query_string: Query string (e.g., "force=true&flag=1").
            body_hash: Optional hash of request body.

        Returns:
            Cache key string.

        Security:
            tenant_id MUST come from scope["state"]["identity"].tenant_id
            (AuthMiddleware) to prevent cross-tenant cache key collisions
            via header spoofing.
        """
        # Build a deterministic request discriminator from method/path/qs/body
        discriminator_parts = [method, path]
        if query_string:
            discriminator_parts.append(query_string)
        if body_hash:
            discriminator_parts.append(body_hash)
        request_hash = hashlib.sha256(
            ":".join(discriminator_parts).encode("utf-8")
        ).hexdigest()[:16]
        return ":".join([self._key_prefix, tenant_id, idempotency_key, request_hash])

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _hash_body(body: bytes) -> str:
        """Hash request body for cache key uniqueness."""
        return hashlib.sha256(body).hexdigest()[:16]

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _resolve_tenant_id(
        self, scope: Scope, idempotency_key: str, path: str,
    ) -> str | None:
        """Extract tenant_id from validated identity in scope state.

        Returns tenant_id string, or None if identity is missing/incomplete
        (caller should skip idempotency or forward the request).
        """
        if "state" not in scope:
            scope["state"] = {}
        state: dict = scope["state"]

        identity = state.get("identity")
        if identity is None:
            logger.debug(
                "idempotency_skipped_no_identity",
                idempotency_key=idempotency_key,
                path=path,
            )
            return None

        tenant_id = getattr(identity, "tenant_id", None)
        if tenant_id is None:
            logger.warning(
                "idempotency_skipped_no_tenant",
                idempotency_key=idempotency_key,
                path=path,
            )
        return tenant_id

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _compute_body_hash(self, buffered_body: bytes) -> str | None:
        """Compute body hash if enabled and body is within size limit."""
        if not self._include_body_hash:
            return None
        if len(buffered_body) <= self._max_body_size_bytes:
            return self._hash_body(buffered_body)
        logger.debug(
            "idempotency_body_hash_skipped",
            body_size=len(buffered_body),
            max_size=self._max_body_size_bytes,
            reason="body exceeds max_body_size_bytes",
        )
        return None

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    async def _check_cache_and_reply(
        self,
        cache: CacheBackend,
        cache_key: str,
        idempotency_key: str,
        path: str,
        correlation_id: str | None,
        send: Send,
    ) -> bool:
        """Check cache for existing response and send it if found.

        Returns True if a cached response was sent (caller should return).
        Returns False if no cached response (caller should proceed).
        Sends 503 on cache failure or corrupt entry (fail-closed).
        """
        try:
            cached = await cache.get(cache_key)
        except Exception as exc:
            logger.warning(
                "idempotency_cache_get_failed",
                idempotency_key=idempotency_key,
                path=path,
                error=str(exc),
                error_type=type(exc).__name__,
                retry=True,
            )
            await asyncio.sleep(IDEMPOTENCY_CACHE_RETRY_DELAY_S)
            try:
                cached = await cache.get(cache_key)
            except Exception as retry_exc:
                logger.warning(
                    "idempotency_cache_get_retry_failed",
                    idempotency_key=idempotency_key,
                    path=path,
                    error=str(retry_exc),
                    error_type=type(retry_exc).__name__,
                )
                await self._send_503(send, correlation_id)
                return True

        if cached is not None:
            logger.info(
                "idempotency_cache_hit",
                idempotency_key=idempotency_key,
                path=path,
            )
            try:
                await self._send_cached_response(send, cached)
            except ValueError:
                await self._send_503(send, correlation_id)
            return True

        return False

    @auto_trace(logger)
    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process HTTP request with idempotency support.

        1. Check method eligibility and Idempotency-Key header
        2. Resolve cache and identity from scope
        3. Buffer request body for hashing
        4. On cache hit: send cached response directly
        5. On cache miss: forward to inner app, intercept response, cache 2xx
        """
        method: str = scope["method"]
        if method not in IDEMPOTENT_METHODS:
            await self.app(scope, receive, send)
            return

        idempotency_key = get_asgi_header(scope, b"idempotency-key")
        if not idempotency_key:
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]

        cache = self._get_cache_from_scope(scope)
        if cache is None:
            logger.warning(
                "idempotency_cache_unavailable",
                idempotency_key=idempotency_key,
                path=path,
            )
            correlation_id = scope.get("state", {}).get("correlation_id")
            await self._send_503(send, correlation_id)
            return

        tenant_id = self._resolve_tenant_id(scope, idempotency_key, path)
        if tenant_id is None:
            await self.app(scope, receive, send)
            return

        buffered_body = await self._buffer_request_body(receive)
        body_hash = self._compute_body_hash(buffered_body)

        raw_qs: bytes = scope.get("query_string", b"")
        query_string = raw_qs.decode("latin-1") if raw_qs else None

        cache_key = self._build_cache_key(
            tenant_id=tenant_id,
            idempotency_key=idempotency_key,
            method=method,
            path=path,
            query_string=query_string,
            body_hash=body_hash,
        )

        correlation_id = scope.get("state", {}).get("correlation_id")
        handled = await self._check_cache_and_reply(
            cache, cache_key, idempotency_key, path, correlation_id, send,
        )
        if handled:
            return

        # Create a replay receive callable so the inner app can read the body
        replay_called = False

        async def replay_receive() -> dict:
            nonlocal replay_called
            if not replay_called:
                replay_called = True
                return {
                    "type": "http.request",
                    "body": buffered_body,
                    "more_body": False,
                }
            return await receive()

        # Intercept response via wrapped send
        response_started = False
        response_status: int = 0
        response_headers: list[tuple[bytes, bytes]] = []
        response_body = bytearray()

        async def intercept_send(message: dict) -> None:
            nonlocal response_started, response_status, response_headers, response_body

            if message["type"] == "http.response.start":
                response_started = True
                response_status = message["status"]
                response_headers = list(message.get("headers", []))
                await send(message)

            elif message["type"] == "http.response.body":
                body_chunk = message.get("body", b"")
                more_body = message.get("more_body", False)
                response_body.extend(body_chunk)
                await send(message)

                if not more_body and 200 <= response_status < 300:
                    await self._cache_intercepted_response(
                        cache=cache,
                        cache_key=cache_key,
                        status_code=response_status,
                        headers=response_headers,
                        body=bytes(response_body),
                        idempotency_key=idempotency_key,
                    )
            else:
                await send(message)

        await self.app(scope, replay_receive, intercept_send)

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    async def _buffer_request_body(receive: Receive) -> bytes:
        """Consume all receive() messages and return concatenated body.

        In ASGI, receive() yields http.request messages with body chunks.
        We consume until more_body is False.

        Args:
            receive: ASGI receive callable.

        Returns:
            Complete request body as bytes.
        """
        body = bytearray()
        while True:
            message = await receive()
            msg_type = message.get("type", "")
            if msg_type == "http.request":
                body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            elif msg_type == "http.disconnect":
                break
            else:
                break
        return bytes(body)

    @auto_trace(logger)
    async def _cache_intercepted_response(
        self,
        cache: CacheBackend,
        cache_key: str,
        status_code: int,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        idempotency_key: str,
    ) -> None:
        """Cache response data intercepted from the send wrapper.

        Args:
            cache: Cache backend instance.
            cache_key: Cache key for storage.
            status_code: HTTP status code.
            headers: ASGI header tuples [(name_bytes, value_bytes), ...].
            body: Complete response body.
            idempotency_key: Original idempotency key for logging.
        """
        try:
            # Convert ASGI header tuples to dict for serialization
            headers_dict: dict[str, str] = {}
            for key, value in headers:
                headers_dict[key.decode("latin-1")] = value.decode("latin-1")

            cached_data: dict[str, Any] = {
                "status_code": status_code,
                "headers": headers_dict,
                "body": body.decode("utf-8"),
            }

            await cache.set(
                cache_key,
                cached_data,
                ttl_seconds=self._ttl_seconds,
            )

            logger.debug(
                "idempotency_response_cached",
                idempotency_key=idempotency_key,
                status_code=status_code,
                ttl_seconds=self._ttl_seconds,
            )

        except Exception as e:
            logger.warning(
                "idempotency_cache_failed",
                idempotency_key=idempotency_key,
                error=str(e),
            )

    @staticmethod
    @auto_trace(logger)
    async def _send_cached_response(send: Send, cached_data: dict[str, Any]) -> None:
        """Send a cached response directly via ASGI send.

        Args:
            send: ASGI send callable.
            cached_data: Cached response data dict with status_code, headers, body.

        Raises:
            ValueError: If cached_data is malformed (missing keys, wrong types).
        """
        try:
            status_code = cached_data["status_code"]
            headers_dict = cached_data["headers"]
            body_str = cached_data["body"]
            body_bytes = body_str.encode("utf-8") if isinstance(body_str, str) else body_str

            # Build ASGI header list, adding X-Idempotency-Replayed
            headers: list[tuple[bytes, bytes]] = []
            for key, value in headers_dict.items():
                # Update content-length to match actual body
                if key.lower() == "content-length":
                    headers.append(
                        (b"content-length", str(len(body_bytes)).encode("latin-1"))
                    )
                else:
                    headers.append(
                        (key.encode("latin-1"), value.encode("latin-1"))
                    )
            headers.append((b"x-idempotency-replayed", b"true"))
        except (AttributeError, TypeError, UnicodeDecodeError, KeyError) as exc:
            logger.warning(
                "idempotency_cached_data_corrupt",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise ValueError(f"Corrupted idempotency cache entry: {exc}") from exc

        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": body_bytes,
        })

    @staticmethod
    @auto_trace(logger)
    async def _send_503(send: Send, correlation_id: str | None = None) -> None:
        """Send a 503 JSON error response for unavailable cache.

        Args:
            send: ASGI send callable.
            correlation_id: Request correlation ID if available.
        """
        body_dict: dict[str, Any] = {
            "code": "idempotency_unavailable",
            "message": "Idempotency service unavailable. Retry later.",
        }
        if correlation_id:
            body_dict["correlation_id"] = correlation_id
        body_bytes = json.dumps(body_dict).encode("utf-8")

        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body_bytes)).encode("latin-1")),
            (b"retry-after", str(DEFAULT_RETRY_SECONDS).encode("latin-1")),
        ]

        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": body_bytes,
        })


@auto_trace(logger)
def add_cors_config(
    app: FastAPI,
    allowed_origins: Optional[List[str]] = None,
    allow_credentials: bool = True,
    allow_methods: Optional[List[str]] = None,
    allow_headers: Optional[List[str]] = None,
) -> None:
    """
    Add CORS middleware with explicit origin configuration.

    Args:
        app: FastAPI application instance
        allowed_origins: List of allowed origins (REQUIRED - no default)
        allow_credentials: Allow credentials (cookies, auth headers)
        allow_methods: Allowed HTTP methods (default: all)
        allow_headers: Allowed HTTP headers (default: all)

    Usage:
        # Development (allow specific local origins)
        add_cors_config(app, allowed_origins=["http://localhost:3000"])

        # Production (specific origins only)
        add_cors_config(app, allowed_origins=["https://app.example.com"])

        # Multiple origins
        add_cors_config(app, allowed_origins=[
            "https://app.example.com",
            "https://admin.example.com"
        ])

    Security:
        - allowed_origins is REQUIRED to prevent accidental permissive CORS
        - Never use ["*"] with allow_credentials=True (browser error)
        - Always specify exact origins for production

    Raises:
        ValueError: If allowed_origins is not specified or invalid configuration
    """
    # Fail-safe default - require explicit configuration
    if allowed_origins is None:
        raise ValueError(
            "allowed_origins must be explicitly specified. "
            "For development: allowed_origins=['http://localhost:3000']. "
            "For production: allowed_origins=['https://app.example.com']"
        )

    # Validate credentials + wildcard combination
    if allow_credentials and "*" in allowed_origins:
        raise ValueError(
            "Cannot use allow_credentials=True with allowed_origins=['*']. "
            "Specify exact origins when using credentials."
        )

    if allow_methods is None:
        allow_methods = ["*"]

    if allow_headers is None:
        allow_headers = ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
    )


class SecurityHeadersMiddleware:
    """Middleware to add security headers to all responses.

    Pure ASGI middleware -- no BaseHTTPMiddleware or run_in_threadpool.
    Wraps the ``send`` callable to intercept ``http.response.start`` messages
    and append security headers to the headers list before forwarding.
    Non-HTTP scope types pass through unchanged.
    """

    @auto_trace(logger)
    def __init__(self, app: ASGIApp, headers: Dict[str, str]) -> None:
        """Initialize with custom headers.

        Args:
            app: ASGI application.
            headers: Dictionary of security headers to add.
        """
        self.app = app
        self.headers = headers
        # Pre-compute ASGI header tuples for performance (avoid per-request encoding)
        self._header_tuples: list[tuple[bytes, bytes]] = [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in headers.items()
        ]
        # Pre-compute set of security header names for overwrite filtering
        self._header_names: frozenset[bytes] = frozenset(
            name for name, _ in self._header_tuples
        )

    @auto_trace(logger)
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point -- inject security headers on HTTP responses.

        Non-HTTP scopes (websocket, lifespan) are forwarded unchanged.

        Args:
            scope: ASGI scope dict.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                # Filter out existing headers that match security header names,
                # then append our hardened values. This guarantees the middleware's
                # values win regardless of what downstream components set.
                existing = [
                    (k, v) for k, v in message.get("headers", [])
                    if k not in self._header_names
                ]
                existing.extend(self._header_tuples)
                message = {**message, "headers": existing}
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


@auto_trace(logger)
def add_security_headers(
    app: FastAPI,
    x_frame_options: str = "DENY",
    x_content_type_options: str = "nosniff",
    strict_transport_security: Optional[str] = "max-age=31536000; includeSubDomains",
    content_security_policy: Optional[str] = "default-src 'self'",
    x_xss_protection: Optional[str] = "1; mode=block",
    referrer_policy: Optional[str] = "strict-origin-when-cross-origin",
    custom_headers: Optional[Dict[str, str]] = None,
) -> None:
    """Add security headers middleware to protect against common vulnerabilities.

    Args:
        app: FastAPI application instance
        x_frame_options: Prevents clickjacking (DENY, SAMEORIGIN, ALLOW-FROM)
        x_content_type_options: Prevents MIME-type sniffing (nosniff)
        strict_transport_security: Enforces HTTPS (max-age in seconds)
        content_security_policy: Controls resource loading to prevent XSS
        x_xss_protection: Legacy XSS protection for older browsers
        referrer_policy: Controls referrer information leakage
        custom_headers: Additional custom security headers

    Usage:
        # Production (strict security - RECOMMENDED)
        add_security_headers(app)  # Use all secure defaults

        # Production with custom CSP (strict)
        add_security_headers(
            app,
            content_security_policy=(
                "default-src 'self'; "
                "script-src 'self' https://cdn.example.com; "
                "style-src 'self' 'unsafe-inline'; "  # If CSS requires it
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        )

        # Development ONLY (relaxed CSP)
        # WARNING: 'unsafe-inline' and 'unsafe-eval' DEFEAT XSS PROTECTION
        # NEVER use this configuration in production
        add_security_headers(
            app,
            content_security_policy="default-src 'self' 'unsafe-inline' 'unsafe-eval'",
            strict_transport_security=None  # Disable HSTS for local development
        )

        # Advanced: Additional security headers (Permissions-Policy)
        add_security_headers(
            app,
            x_frame_options="SAMEORIGIN",
            custom_headers={
                "Permissions-Policy": (
                    "geolocation=(), "
                    "microphone=(), "
                    "camera=(), "
                    "payment=(), "
                    "usb=()"
                )
            }
        )

    Security Headers:
        - X-Frame-Options: Prevents clickjacking by controlling iframe embedding
        - X-Content-Type-Options: Prevents MIME-type confusion attacks
        - Strict-Transport-Security: Forces HTTPS for specified duration
        - Content-Security-Policy: Mitigates XSS by controlling resource sources
        - X-XSS-Protection: Legacy browser XSS filter (deprecated but harmless)
        - Referrer-Policy: Controls information sent in Referer header

    Production Security Notes:
        - CSP 'unsafe-inline'/'unsafe-eval' defeat XSS protection - avoid
        - Use strict CSP in production with explicit whitelisted sources only
        - HSTS should be enabled in production (max-age=31536000 minimum)
        - Disable HSTS for local development (set to None)
        - Apply this middleware EARLY in the middleware stack
        - Headers are added to ALL responses automatically
        - Consider adding Permissions-Policy for browser feature restrictions

    References:
        - OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
        - OWASP CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
    """
    headers = {}

    # X-Frame-Options: Prevents clickjacking
    if x_frame_options:
        headers["X-Frame-Options"] = x_frame_options

    # X-Content-Type-Options: Prevents MIME-type sniffing
    if x_content_type_options:
        headers["X-Content-Type-Options"] = x_content_type_options

    # Strict-Transport-Security: Forces HTTPS
    if strict_transport_security:
        headers["Strict-Transport-Security"] = strict_transport_security

    # Content-Security-Policy: Mitigates XSS attacks
    if content_security_policy:
        headers["Content-Security-Policy"] = content_security_policy

    # X-XSS-Protection: Legacy XSS filter for older browsers
    if x_xss_protection:
        headers["X-XSS-Protection"] = x_xss_protection

    # Referrer-Policy: Controls referrer information
    if referrer_policy:
        headers["Referrer-Policy"] = referrer_policy

    # Add any custom headers
    if custom_headers:
        headers.update(custom_headers)

    # Add middleware to application
    app.add_middleware(SecurityHeadersMiddleware, headers=headers)

    logger.info(
        "Security headers middleware configured",
        extra={
            "headers_count": len(headers),
            "headers": list(headers.keys()),
        },
    )


@auto_trace(logger)
def auto_trace_routes(
    app: FastAPI,
    route_logger,
    exclude_paths: Optional[List[str]] = None,
) -> None:
    """
    Apply @auto_trace decorator to all routes for automatic telemetry.

    Args:
        app: FastAPI application instance
        route_logger: Telemetry logger instance (from get_telemetry) to apply to routes
        exclude_paths: Paths to exclude from tracing (default: health/metrics)

    Usage:
        from neoaxios_logging import get_telemetry
        from neoaxios_fastapi_kit import auto_trace_routes

        app = FastAPI()
        logger = get_telemetry(__name__)

        # Define routes
        @app.post("/v1/analyze")
        async def analyze(req): ...

        # Apply auto-trace to all routes
        auto_trace_routes(app, logger)

    Note:
        This should be called AFTER all routes are registered.
        Routes added after this call will NOT be traced.
    """
    try:
        from neoaxios_logging import auto_trace
    except ImportError:
        raise ImportError(
            "neoaxios-logging is required for auto_trace_routes. "
            "Install with: pip install neoaxios-logging"
        )

    if exclude_paths is None:
        exclude_paths = [
            "/health",
            "/metrics",
            "/info",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

    # Wrap each route endpoint with @auto_trace
    for route in app.routes:
        # Skip non-HTTP routes (websockets, etc.)
        if not hasattr(route, "endpoint") or not hasattr(route, "path"):
            continue

        # Skip excluded paths
        if route.path in exclude_paths:
            continue

        # Wrap endpoint with auto_trace
        original_endpoint = route.endpoint
        route.endpoint = auto_trace(route_logger)(original_endpoint)

        # Preserve original endpoint attributes for FastAPI
        route.endpoint.__name__ = original_endpoint.__name__
        route.endpoint.__doc__ = original_endpoint.__doc__


# ---------------------------------------------------------------------------
# HTTP Request Metrics Middleware
# ---------------------------------------------------------------------------

# Module-level Prometheus metrics — created once, shared across all instances.
# prometheus_client handles deduplication internally via the default registry.
_HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests by method, endpoint, and status code.",
    ["method", "endpoint", "status_code"],
)

_HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds by method and endpoint.",
    ["method", "endpoint"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Paths excluded from per-endpoint labeling to prevent cardinality explosion
# (health/metrics are high-frequency infrastructure endpoints)
_METRICS_EXCLUDE_PATHS: frozenset[str] = frozenset({
    "/health", "/metrics", "/info", "/docs", "/redoc", "/openapi.json",
})


class HttpMetricsMiddleware:
    """Pure ASGI middleware that records HTTP request metrics in Prometheus.

    Exposes two metrics consumed by Grafana dashboards:

    - ``http_requests_total`` (Counter): Labeled by ``method``, ``endpoint``,
      ``status_code``.  Enables server-side RPS via
      ``rate(http_requests_total[15s])``.

    - ``http_request_duration_seconds`` (Histogram): Labeled by ``method``,
      ``endpoint``.  Enables server-side latency percentiles via
      ``histogram_quantile(0.99, ...)``.

    High-frequency infrastructure paths (/health, /metrics) are labeled as
    a single ``/_infra`` bucket to prevent label cardinality explosion.

    Usage::

        from neoaxios_fastapi_kit.middleware import add_http_metrics
        add_http_metrics(app)
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:  # notrace: hotpath — called per-request
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "UNKNOWN")
        start = _time.monotonic()
        status_code = 500  # default if response never starts
        metrics_recorded = False

        def _resolve_endpoint() -> str:
            # Use the matched route template (set by the Starlette router
            # before the response starts), NOT the raw URL path.  Raw paths
            # contain path-parameter values (e.g., workflow UUIDs), which
            # would create a unique Prometheus series per value — an
            # unbounded label cardinality explosion.
            route = scope.get("route")
            if route is not None and hasattr(route, "path"):
                ep = route.path  # e.g. "/v1/test/{workflow_id}"
            else:
                # No matched route — use a fixed label to avoid unbounded
                # cardinality from scanner traffic, 404 paths, or raw URLs
                # containing path-parameter values (e.g., UUIDs).
                ep = "/_unmatched"
            # Collapse high-frequency infrastructure paths into a single
            # bucket to prevent cardinality growth from polling.
            return "/_infra" if ep in _METRICS_EXCLUDE_PATHS else ep

        def _record(ep: str, dur: float, code: int) -> None:
            _HTTP_REQUESTS_TOTAL.labels(
                method=method, endpoint=ep, status_code=str(code),
            ).inc()
            _HTTP_REQUEST_DURATION_SECONDS.labels(
                method=method, endpoint=ep,
            ).observe(dur)

        async def send_with_metrics(message: dict) -> None:
            nonlocal status_code, metrics_recorded
            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
                _record(_resolve_endpoint(), _time.monotonic() - start, status_code)
                metrics_recorded = True
            await send(message)

        try:
            await self.app(scope, receive, send_with_metrics)
        finally:
            # Guard: record metrics even if the response never started
            # (e.g., client disconnected before any response was sent).
            if not metrics_recorded:
                _record(_resolve_endpoint(), _time.monotonic() - start, status_code)


@auto_trace(logger)
def add_http_metrics(app: FastAPI) -> None:
    """Add HTTP request metrics middleware for Prometheus/Grafana observability.

    Records ``http_requests_total`` (counter) and
    ``http_request_duration_seconds`` (histogram) for all HTTP requests.
    These metrics enable server-side RPS and latency monitoring in Grafana
    without additional instrumentation.

    Should be added early in the middleware stack (outermost) to capture
    the full request duration including other middleware processing time.

    Args:
        app: FastAPI application instance.

    Usage::

        app = FastAPI()
        add_http_metrics(app)
        # Grafana query for server-side RPS:
        #   rate(http_requests_total{endpoint="/v1/workflows"}[15s])
        # Grafana query for p99 latency:
        #   histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
    """
    app.add_middleware(HttpMetricsMiddleware)
