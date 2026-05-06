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

"""FastAPI Request adapter for rate limit key construction.

This module bridges FastAPI's Request object to the framework-agnostic
HmacRateLimitKeyBuilder in resilience-kit. It handles:
- Extracting validated identity from request.state (via auth middleware)
- Extracting client IP from request with trusted proxy support
- Dispatching scope-based key resolution from Request context

The HMAC core (build_key, build_global_key, _obfuscate, _obfuscate_raw)
lives in resilience-kit's HmacRateLimitKeyBuilder. This subclass adds
only the Request-dependent methods.

Security:
- Identity context must be validated (from auth middleware, not spoofable)
- IP addresses are extracted from trusted proxies only
- HMAC obfuscation delegated to parent class

Design:
- Single responsibility for Request-to-key bridging.
- Centralized key logic prevents duplication.
"""

from typing import List, Optional

from fastapi import Request

from neoaxios_resilience_kit.ratelimit import (
    HmacRateLimitKeyBuilder,
    RateLimitIdentity,
)
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@auto_trace(logger)
def _extract_identity(request: Request) -> RateLimitIdentity:
    """Extract and validate identity from request state.

    Validates that identity was set by auth middleware (via _identity_validated flag)
    and returns the identity object satisfying RateLimitIdentity protocol.

    Args:
        request: FastAPI request with identity set by auth middleware.

    Returns:
        Identity object with .user_id and .tenant_id properties.

    Raises:
        ValueError: If identity context is not validated or missing.
    """
    identity_validated = getattr(request.state, "_identity_validated", False)
    if not identity_validated:
        logger.warning(
            "Identity context not validated - possible bypass attempt",
            path=request.url.path,
        )
        raise ValueError(
            "Identity context not validated. "
            "Ensure neoaxios_fastapi_kit.auth middleware is applied before rate limiting."
        )

    identity = getattr(request.state, "identity", None)
    if identity is None:
        raise ValueError(
            "Identity not found in request state. "
            "Ensure auth middleware sets request.state.identity."
        )

    return identity


class RateLimitKeyBuilder(HmacRateLimitKeyBuilder):
    """FastAPI Request adapter for HMAC-obfuscated rate limit keys.

    Subclasses HmacRateLimitKeyBuilder to add Request-dependent methods
    for extracting identity and IP from FastAPI Request objects. The HMAC
    core (build_key, build_global_key, _obfuscate, _obfuscate_raw) and
    __init__ are inherited from the parent class.

    Attributes:
        hmac_key: Secret key for HMAC obfuscation (min 16 bytes)
        key_prefix: Prefix for all rate limit keys
        trusted_proxies: List of trusted proxy IP addresses
    """

    @auto_trace(logger)
    def resolve_scope_key(self, request: Request, scope: str) -> str:
        """Resolve rate limit key for a scope from request context.

        Single dispatch point for scope-based key resolution.
        Used by both middleware and limiter to avoid scope dispatch duplication.

        Args:
            request: FastAPI request with identity/IP context.
            scope: Rate limit scope - "user", "tenant", "ip", or "global".

        Returns:
            Resolved rate limit key for the scope.

        Raises:
            ValueError: If identity is missing for user/tenant scope or scope is invalid.
        """
        if scope in ("user", "tenant"):
            identity = _extract_identity(request)
            return self.build_key(identity, scope)
        elif scope == "ip":
            return self.build_ip_key(request)
        elif scope == "global":
            return self.build_global_key()
        else:
            raise ValueError(f"Invalid scope: {scope}")

    @auto_trace(logger)
    def build_ip_key(self, request: Request) -> str:
        """Build HMAC-obfuscated key for per-IP rate limiting.

        Args:
            request: FastAPI request object

        Returns:
            Obfuscated rate limit key for IP scope
        """
        client_ip = self._get_client_ip(request)
        return self._obfuscate(f"ip:{client_ip}")

    @auto_trace(logger)
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, respecting trusted proxies.

        Args:
            request: FastAPI request object

        Returns:
            Client IP address
        """
        direct_ip = request.client.host if request.client else "unknown"

        if direct_ip in self._trusted_proxies:
            forwarded_for = request.headers.get("X-Forwarded-For", "")
            if forwarded_for:
                client_ip = forwarded_for.split(",")[0].strip()
                logger.debug(
                    "Using X-Forwarded-For IP",
                    client_ip=client_ip,
                    proxy_ip=direct_ip,
                )
                return client_ip

        return direct_ip


@auto_trace(logger)
def create_key_builder(
    hmac_key: bytes,
    key_prefix: str = "ratelimit:",
    trusted_proxies: Optional[List[str]] = None,
) -> RateLimitKeyBuilder:
    """Factory function for RateLimitKeyBuilder.

    Args:
        hmac_key: Secret key for HMAC obfuscation (min 16 bytes recommended)
        key_prefix: Prefix for all rate limit keys
        trusted_proxies: List of trusted proxy IPs for X-Forwarded-For extraction

    Returns:
        Configured RateLimitKeyBuilder instance

    Raises:
        ValueError: If hmac_key is too short (< 16 bytes)
    """
    return RateLimitKeyBuilder(
        hmac_key=hmac_key,
        key_prefix=key_prefix,
        trusted_proxies=trusted_proxies,
    )
