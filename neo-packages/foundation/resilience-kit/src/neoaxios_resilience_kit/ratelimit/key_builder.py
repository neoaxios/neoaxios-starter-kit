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

"""Framework-agnostic rate limit key construction with HMAC obfuscation.

This module provides the HMAC core for rate limit key construction:
- RateLimitIdentity protocol for structural typing of identity objects
- HmacRateLimitKeyBuilder for HMAC-SHA256 obfuscated key construction

The key builder handles scope dispatch (user, tenant, ip, global) and
HMAC obfuscation to prevent Redis key enumeration attacks. It accepts
identity and IP address as explicit parameters rather than extracting
them from HTTP framework objects.

Security:
- Keys are HMAC-obfuscated to prevent Redis key enumeration
- HMAC key must be at least 16 bytes
- Identity context is accepted via protocol, not extracted from requests
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List, Optional, Protocol, runtime_checkable

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@runtime_checkable
class RateLimitIdentity(Protocol):
    """Protocol for rate limit identity input.

    Structural subtyping contract -- any object with `.user_id: str` and
    `.tenant_id: str` properties satisfies this protocol without explicit
    registration. Compatible types include:
    - `ReadOnlyIdentityWrapper` from neoaxios_fastapi_kit.auth
    - `IdentityContext` from neoaxios_fastapi_kit.auth
    - Any `@dataclass` with matching attributes (used in tests)
    """

    @property
    def user_id(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...


class HmacRateLimitKeyBuilder:
    """Builds HMAC-obfuscated rate limit keys.

    Keys are constructed from identity context and obfuscated using HMAC-SHA256
    to prevent key enumeration attacks in Redis. This class contains the
    framework-agnostic HMAC core; HTTP-specific key resolution lives in
    neoaxios_fastapi_kit's RateLimitKeyBuilder subclass.

    Attributes:
        hmac_key: Secret key for HMAC obfuscation (min 16 bytes)
        key_prefix: Prefix for all rate limit keys
        trusted_proxies: List of trusted proxy IP addresses
    """

    @auto_trace(logger)
    def __init__(
        self,
        hmac_key: bytes,
        key_prefix: str = "ratelimit:",
        trusted_proxies: Optional[List[str]] = None,
    ) -> None:
        """Initialize key builder.

        Args:
            hmac_key: Secret key for HMAC obfuscation (min 16 bytes).
            key_prefix: Prefix for all rate limit keys.
            trusted_proxies: List of trusted proxy IPs for X-Forwarded-For extraction.

        Raises:
            ValueError: If hmac_key is too short (< 16 bytes).
        """
        if len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")

        self._hmac_key = hmac_key
        self._key_prefix = key_prefix
        self._trusted_proxies = set(trusted_proxies or [])

        logger.info(
            "Initialized HmacRateLimitKeyBuilder",
            prefix=key_prefix,
            trusted_proxies_count=len(self._trusted_proxies),
        )

    @auto_trace(logger)
    def build_key(
        self,
        identity: RateLimitIdentity | None,
        scope: str,
        *,
        ip_address: str | None = None,
    ) -> str:
        """Build HMAC-obfuscated rate limit key for the given scope.

        Dispatches key construction based on scope:
        - "user": Hierarchical key t:{tid}:u:{uid} (requires identity)
        - "tenant": Tenant key t:{tid} (requires identity)
        - "ip": IP key ip:{addr} (requires ip_address)
        - "global": Global key (no identity needed)

        Args:
            identity: Identity with user_id and tenant_id (required for user/tenant scopes).
            scope: Rate limit scope - "user", "tenant", "ip", or "global".
            ip_address: Client IP address (required for ip scope).

        Returns:
            HMAC-obfuscated rate limit key.

        Raises:
            ValueError: If identity is missing for user/tenant scope.
            ValueError: If user_id or tenant_id is empty.
            ValueError: If scope is invalid.
        """
        if scope == "user":
            if identity is None:
                raise ValueError("identity required for user scope")
            if not identity.tenant_id:
                raise ValueError("tenant_id must be non-empty")
            if not identity.user_id:
                raise ValueError("user_id must be non-empty")
            # Hierarchical key: tenant prefix + user suffix
            tenant_hash = self._obfuscate_raw(f"t:{identity.tenant_id}")
            user_hash = self._obfuscate_raw(
                f"t:{identity.tenant_id}:u:{identity.user_id}"
            )
            return f"{self._key_prefix}t:{tenant_hash}:u:{user_hash}"

        elif scope == "tenant":
            if identity is None:
                raise ValueError("identity required for tenant scope")
            if not identity.tenant_id:
                raise ValueError("tenant_id must be non-empty")
            tenant_hash = self._obfuscate_raw(f"t:{identity.tenant_id}")
            return f"{self._key_prefix}t:{tenant_hash}"

        elif scope == "ip":
            ip = ip_address or "unknown"
            return self._obfuscate(f"ip:{ip}")

        elif scope == "global":
            return self.build_global_key()

        else:
            raise ValueError(
                f"Invalid scope: {scope} (expected user, tenant, ip, global)"
            )

    @auto_trace(logger)
    def build_global_key(self) -> str:
        """Build key for global rate limiting (not obfuscated - single key).

        Returns:
            Global rate limit key.
        """
        return f"{self._key_prefix}global"

    @auto_trace(logger)
    def _obfuscate(self, raw_key: str) -> str:
        """Obfuscate key using HMAC-SHA256.

        Args:
            raw_key: Raw key to obfuscate (e.g., "ip:192.168.1.1").

        Returns:
            Obfuscated key with format: {prefix}{scope}:{hash}
        """
        mac = hmac.new(self._hmac_key, raw_key.encode(), hashlib.sha256)
        obfuscated = mac.hexdigest()[:32]
        scope_prefix = raw_key.split(":")[0]
        return f"{self._key_prefix}{scope_prefix}:{obfuscated}"

    @auto_trace(logger)
    def _obfuscate_raw(self, raw_key: str) -> str:
        """HMAC-SHA256 hash without key prefix.

        Args:
            raw_key: Raw key to hash.

        Returns:
            32-character hex hash string.
        """
        mac = hmac.new(self._hmac_key, raw_key.encode(), hashlib.sha256)
        return mac.hexdigest()[:32]
