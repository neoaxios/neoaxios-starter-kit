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

"""Auth-specific cache key builders using CacheNamespace scope tiers.

This module provides key builder functions for all auth-domain cache entries.
Each builder accepts a `CacheNamespace` and domain-specific identifiers,
producing fully-qualified keys using the tiered scope hierarchy.

Key Format:
    {scope_tier}:{feature}

    Scope tiers provide consistent labeled segments (`t:` for tenant, `u:` for user)
    so that prefix-based invalidation works naturally at every level:
      - tenant_prefix matches ALL keys for a tenant (all users, all features)
      - user_prefix matches ALL keys for a specific user (all features)

    Example: org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:u:user456:permissions

Features:
    - permissions: User permission sets
    - jwks: OIDC JWKS key sets (issuer URL-safe base64 encoded)
    - roles: Role enrichment from external providers
    - graph_token: Microsoft Graph API tokens

Usage:
    from neoaxios_secure_cache import CacheNamespace
    from neoaxios_fastapi_kit.auth.cache_keys import permissions_key, jwks_key

    ns = CacheNamespace(
        org="neo",
        env="prod",
        service="auth-api",
        app="gateway",
    )

    # Build permission cache key
    key = permissions_key(ns, "tenant123", "user456")
    # Returns: "org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:u:user456:permissions"

    # Build JWKS cache key (issuer is base64 encoded)
    key = jwks_key(ns, "https://login.microsoftonline.com/tenant/v2.0")

"""

import base64
from typing import TYPE_CHECKING

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace

logger = get_telemetry(__name__)


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def _encode_issuer(issuer: str) -> str:
    """Encode OIDC issuer as URL-safe base64 without padding.

    OIDC issuers contain characters that conflict with the colon-delimited
    key format (`:`, `/`, `?`, `#`, etc.). URL-safe base64 encoding handles
    all issuer formats safely.

    Args:
        issuer: OIDC issuer URL or URN

    Returns:
        URL-safe base64 encoded string (no padding)

    Example:
        >>> _encode_issuer("https://login.microsoftonline.com/tenant/v2.0")
        'aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC92Mi4w'
    """
    return base64.urlsafe_b64encode(issuer.encode()).decode().rstrip("=")


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def permissions_key(ns: "CacheNamespace", tenant_id: str, user_id: str) -> str:
    """Build cache key for user permission sets.

    Args:
        ns: Cache namespace
        tenant_id: Tenant identifier
        user_id: User identifier

    Returns:
        Cache key: `{ns.user(tenant_id, user_id)}:permissions`

    Raises:
        ValueError: If tenant_id or user_id is empty

    TTL: Typically 300 seconds (5 minutes)
    Value Type: FrozenSet[str] of permission strings

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> permissions_key(ns, "tenant123", "user456")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:u:user456:permissions'
    """
    return f"{ns.user(tenant_id, user_id)}:permissions"


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def jwks_key(ns: "CacheNamespace", issuer: str) -> str:
    """Build cache key for OIDC JWKS key sets.

    The issuer URL is encoded as URL-safe base64 to prevent conflicts with
    the colon-delimited key format. Special characters in URLs (`:`, `/`,
    `?`, `#`) are safely encoded.

    JWKS keys are global (not tenant-scoped) because OIDC issuers serve
    the same signing keys to all tenants.

    Args:
        ns: Cache namespace
        issuer: OIDC issuer URL (e.g., "https://login.microsoftonline.com/tenant/v2.0")

    Returns:
        Cache key: `{ns.base()}:jwks:{base64_issuer}`

    Raises:
        ValueError: If issuer is empty

    TTL: Typically 86400 seconds (24 hours)
    Value Type: Dict with JWKS keys (parsed from provider's /.well-known/jwks.json)

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> jwks_key(ns, "https://login.microsoftonline.com/tenant/v2.0")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:jwks:aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC92Mi4w'
    """
    if not issuer:
        raise ValueError("issuer cannot be empty")
    safe_issuer = _encode_issuer(issuer)
    return f"{ns.base()}:jwks:{safe_issuer}"


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def role_enrichment_key(ns: "CacheNamespace", tenant_id: str, user_id: str) -> str:
    """Build cache key for role enrichment from external providers.

    Used by Azure AD decoder and other providers that enrich roles from
    external sources (Microsoft Graph API, LDAP, etc.).

    Args:
        ns: Cache namespace
        tenant_id: Tenant identifier
        user_id: User identifier

    Returns:
        Cache key: `{ns.user(tenant_id, user_id)}:roles`

    Raises:
        ValueError: If tenant_id or user_id is empty

    TTL: Typically 3600 seconds (1 hour, from GraphAPIEnrichmentConfig)
    Value Type: FrozenSet[str] of role names

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> role_enrichment_key(ns, "tenant123", "user456")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:u:user456:roles'
    """
    return f"{ns.user(tenant_id, user_id)}:roles"


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def graph_token_key(ns: "CacheNamespace", tenant_id: str) -> str:
    """Build cache key for Microsoft Graph API tokens.

    Used by MicrosoftGraphAPIClient to cache OAuth tokens acquired for
    Graph API calls (role enrichment, group membership queries).

    Args:
        ns: Cache namespace
        tenant_id: Azure AD tenant identifier

    Returns:
        Cache key: `{ns.tenant(tenant_id)}:graph_token`

    Raises:
        ValueError: If tenant_id is empty

    TTL: Computed from token's expires_at minus safety margin
    Value Type: TokenRecord with access_token, expires_at, token_type

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> graph_token_key(ns, "tenant123")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:graph_token'
    """
    return f"{ns.tenant(tenant_id)}:graph_token"


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def user_prefix(ns: "CacheNamespace", tenant_id: str, user_id: str) -> str:
    """Build prefix for invalidating all cache entries for a user.

    Used for bulk invalidation when user permissions change (role assignment,
    group membership update, etc.). Matches ALL user-scoped features
    (permissions, roles, etc.).

    Args:
        ns: Cache namespace
        tenant_id: Tenant identifier
        user_id: User identifier

    Returns:
        Prefix ending with colon: `{ns.user(tenant_id, user_id)}:`

    Raises:
        ValueError: If tenant_id or user_id is empty

    Note:
        Prefix must end with ":" for SigningCacheWrapper compatibility.

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> prefix = user_prefix(ns, "tenant123", "user456")
        >>> await cache.invalidate_by_prefix(prefix)
    """
    return f"{ns.user(tenant_id, user_id)}:"


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def tenant_prefix(ns: "CacheNamespace", tenant_id: str) -> str:
    """Build prefix for invalidating all cache entries for a tenant.

    Used for bulk invalidation when tenant-wide changes occur (policy update,
    organization restructure, role mapping changes, etc.). Matches ALL
    tenant-scoped keys including all users' permissions, roles, and graph tokens.

    Args:
        ns: Cache namespace
        tenant_id: Tenant identifier

    Returns:
        Prefix ending with colon: `{ns.tenant(tenant_id)}:`

    Raises:
        ValueError: If tenant_id is empty

    Note:
        Prefix must end with ":" for SigningCacheWrapper compatibility.

    Example:
        >>> ns = CacheNamespace("neo", "prod", "auth-api", "gateway")
        >>> prefix = tenant_prefix(ns, "tenant123")
        >>> await cache.invalidate_by_prefix(prefix)
    """
    return f"{ns.tenant(tenant_id)}:"


__all__ = [
    "graph_token_key",
    "jwks_key",
    "permissions_key",
    "role_enrichment_key",
    "tenant_prefix",
    "user_prefix",
]
