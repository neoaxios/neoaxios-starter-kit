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

"""Azure AD-specific OIDC decoder for Microsoft Entra ID (Azure AD) tokens.

Validates tokens issued by Microsoft Entra ID (formerly Azure Active Directory) with
Azure-specific features including:
- Both user (delegated) tokens and application (app-only/service principal) tokens
- Application role assignments from the "roles" claim
- Tenant validation (single-tenant, multi-tenant with allowed tenants list)
- Token type detection (idtyp claim for app vs user tokens)
- Azure AD v1.0 and v2.0 token format support
- Directory role mappings (wids claim)
- Security group memberships (groups claim)

This decoder extends OIDCDecoder to add Azure AD-specific functionality:
- Auto-construction of issuer and JWKS URIs from tenant_id
- Azure AD-specific claims handling (tid, oid, appid, idtyp, roles, scp, groups, wids)
- Support for both user tokens and app-only tokens (service principals)
- Multi-tenant token validation with O(1) allowed tenants lookup (frozenset)
- Full JWKS signature verification (inherited from OIDCDecoder)

Azure AD Token Structure:
    Azure AD issues tokens from:
    - v1.0: https://sts.windows.net/{tenant_id}/
    - v2.0: https://login.microsoftonline.com/{tenant_id}/v2.0

Azure AD Token Types:
    User (Delegated) Tokens:
    - Issued when a user authenticates via OAuth 2.0 authorization code flow
    - Contains: sub, oid (user object ID), tid, scp (delegated permissions)
    - "idtyp" claim is absent or not "app"

    App-Only (Service Principal) Tokens:
    - Issued via client credentials flow (no user context)
    - Contains: oid (service principal object ID), appid, tid, roles
    - "idtyp" claim = "app"
    - No "sub" claim (use appid as user_id)
    - No "scp" claim (uses "roles" for app permissions)

Azure AD-Specific Claims:
    - tid: Tenant ID (GUID)
    - oid: Object ID (user or service principal GUID)
    - appid/azp: Application (client) ID
    - idtyp: Token type ("app" for app-only tokens)
    - scp: Delegated permission scopes (space-separated, user tokens)
    - roles: Application role assignments (array, both token types)
    - groups: Security group GUIDs (optional, requires "groups" claim in token config)
    - wids: Directory role template IDs (e.g., Global Administrator)
    - email: User email (optional)
    - name: User display name (optional)
    - preferred_username: UPN (optional)
    - ver: Token version (1.0 or 2.0)
    - idp: Identity provider (for B2B guest users)

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import AzureADDecoder

    # Basic configuration (v2.0 endpoint) - ALWAYS use factory function
    decoder = create_azure_decoder(
        tenant_id="00000000-0000-0000-0000-000000000000",
        client_id="11111111-1111-1111-1111-111111111111",
    )

    # Multi-tenant with allowed tenants list (O(1) lookup)
    decoder = create_azure_decoder(
        tenant_id="organizations",
        client_id="11111111-1111-1111-1111-111111111111",
        allowed_tenants=frozenset(["tenant1-guid", "tenant2-guid"]),
        audience="api://my-api",
    )

    # Decode user token
    identity = await decoder.decode(user_token)
    logger.info(
        f"Decoded Azure AD user token",
        user_id=identity.user_id,
        token_type=identity.attributes.get("token_type"),  # "user"
        roles=identity.roles,
    )

    # Decode app-only token (service principal)
    identity = await decoder.decode(app_token)
    logger.info(
        f"Decoded Azure AD app token",
        user_id=identity.user_id,  # = appid
        token_type=identity.attributes.get("token_type"),  # "app"
        service_principal_id=identity.attributes.get("service_principal_id"),
        roles=identity.roles,  # App permissions
    )

Environment Variables:
    Create decoder from environment variables:
    - AZURE_AD_TENANT_ID: Azure AD tenant ID (GUID or "common"/"organizations"/"consumers")
    - AZURE_AD_CLIENT_ID: OAuth 2.0 client ID (application ID)
    - AZURE_AD_CLIENT_SECRET: OAuth 2.0 client secret (optional)
    - AZURE_AD_AUDIENCE: Expected audience claim (optional)
    - AZURE_AD_API_VERSION: API version ("v1.0" or "v2.0", default: "v2.0")
    - AZURE_AD_ALLOWED_TENANTS: Comma-separated list of allowed tenant IDs (optional)
    - AZURE_AD_CLOCK_SKEW: Clock skew tolerance in seconds (optional, default: 30)

    decoder = create_azure_decoder()  # Reads from environment

Reference: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
"""

import asyncio
import os
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional, Set, Union

from pydantic import SecretStr

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_secure_cache.defaults import CACHE_TTL_MEDIUM
from neoaxios_secure_cache import CacheBackend
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_mapper import (
    DIRECTORY_ROLE_MAPPINGS,
)
from neoaxios_fastapi_kit.auth.cache_keys import role_enrichment_key, tenant_prefix
from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_tenant import (
    GUID_PATTERN,
    TenantValidationError,
)

logger = get_telemetry(__name__)


# =============================================================================
# Pre-compiled Regex Patterns (ReDoS Security Hardening)
# =============================================================================

# GUID_PATTERN and TenantValidationError imported from azure_tenant.py

# Azure AD v1.0 issuer pattern for tenant extraction
# Format: https://sts.windows.net/{tenant_id}/
V1_ISSUER_EXTRACT_PATTERN = re.compile(
    r"https://sts\.windows\.net/([^/]+)/?",
    re.IGNORECASE,
)

# Azure AD v2.0 issuer pattern for tenant extraction
# Format: https://login.microsoftonline.com/{tenant_id}/v2.0
V2_ISSUER_EXTRACT_PATTERN = re.compile(
    r"https://login\.microsoftonline\.com/([^/]+)/v2\.0",
    re.IGNORECASE,
)

# Azure AD v1.0 issuer validation pattern
# Format: https://sts.windows.net/{tenant_guid}/
# ReDoS-safe: Bounded quantifier {1,64} prevents catastrophic backtracking
V1_ISSUER_VALIDATION_PATTERN = re.compile(
    r"^https://sts\.windows\.net/[0-9a-fA-F-]{1,64}/?$",
    re.IGNORECASE,
)

# Azure AD v2.0 issuer validation pattern
# Format: https://login.microsoftonline.com/{tenant_guid}/v2.0
# ReDoS-safe: Bounded quantifier {1,64} prevents catastrophic backtracking
V2_ISSUER_VALIDATION_PATTERN = re.compile(
    r"^https://login\.microsoftonline\.com/[0-9a-fA-F-]{1,64}/v2\.0$",
    re.IGNORECASE,
)

# Multi-tenant issuer validation patterns (common, organizations, consumers)
MULTI_TENANT_V1_ISSUER_PATTERN = re.compile(
    r"^https://sts\.windows\.net/(common|organizations|consumers)/?$",
    re.IGNORECASE,
)

MULTI_TENANT_V2_ISSUER_PATTERN = re.compile(
    r"^https://login\.microsoftonline\.com/(common|organizations|consumers)/v2\.0$",
    re.IGNORECASE,
)


# TenantValidationError imported from azure_tenant.py

# =============================================================================
# Role Enrichment Store (Redis-backed)
# =============================================================================


class RoleEnrichmentStore:
    """Redis-backed role enrichment cache with namespace-aware keys.

    Replaces in-memory RoleEnrichmentCache with distributed cache storage.
    Uses CacheBackend protocol for Redis (or other distributed cache) storage,
    enabling role enrichment data to be shared across multiple application instances.

    Key Format:
        {namespace.base()}:roles:{tenant_id}:{user_id}

    Thread Safety:
        All operations are async and thread-safe through the CacheBackend interface.

    Args:
        backend: Cache backend implementation (required - fail fast on misconfiguration)
        namespace: Cache namespace for hierarchical key prefixing (required)
        default_ttl_seconds: Default TTL for cached roles (default: 3600 = 1 hour)

    Usage:
        from neoaxios_secure_cache.backends.redis import RedisCacheBackend
        from neoaxios_secure_cache import CacheNamespace
        from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure import RoleEnrichmentStore

        namespace = CacheNamespace(
            org="neo",
            env="prod",
            service="auth-api",
            app="gateway",
        )
        backend = RedisCacheBackend(url="redis://localhost:6379")
        store = RoleEnrichmentStore(backend=backend, namespace=namespace)

        # Cache roles
        await store.set("tenant123", "user456", frozenset({"admin", "reader"}))

        # Retrieve cached roles
        roles = await store.get("tenant123", "user456")

        # Invalidate when roles change
        count = await store.invalidate_user("tenant123", "user456")
        count = await store.invalidate_tenant("tenant123")
    """

    def __init__(
        self,
        backend: CacheBackend,
        namespace: "CacheNamespace",
        default_ttl_seconds: int = CACHE_TTL_MEDIUM,
    ) -> None:
        """Initialize role enrichment store.

        Args:
            backend: Cache backend (required)
            namespace: Cache namespace (required)
            default_ttl_seconds: Default TTL in seconds (default: 3600 = 1 hour)
        """
        self._backend = backend
        self._namespace = namespace
        self._default_ttl_seconds = default_ttl_seconds

    @auto_trace(logger)
    async def get(self, tenant_id: str, user_id: str) -> Optional[FrozenSet[str]]:
        """Get cached roles for user in tenant.

        Args:
            tenant_id: Azure AD tenant ID
            user_id: User object ID (oid claim)

        Returns:
            FrozenSet of cached roles if valid cache entry exists, None otherwise

        Note:
            Roles are stored as JSON-serializable lists in the cache backend.
            This method converts the list back to frozenset on retrieval.
            Returns None if the cached value has an unexpected type.
        """
        key = role_enrichment_key(self._namespace, tenant_id, user_id)
        result = await self._backend.get(key)

        if result is not None:
            logger.debug(
                f"Role store hit: tenant_id={tenant_id}, user_id={user_id}, "
                f"role_count={len(result)}"
            )
            # Ensure we return a frozenset
            if isinstance(result, frozenset):
                return result
            if isinstance(result, (list, set)):
                return frozenset(result)
            logger.warning(
                f"Unexpected cached value type: {type(result)}, expected frozenset"
            )
            return None

        logger.debug(f"Role store miss: tenant_id={tenant_id}, user_id={user_id}")
        return None

    @auto_trace(logger)
    async def set(
        self,
        tenant_id: str,
        user_id: str,
        roles: FrozenSet[str],
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Cache roles for user in tenant.

        Args:
            tenant_id: Azure AD tenant ID
            user_id: User object ID (oid claim)
            roles: FrozenSet of roles to cache
            ttl_seconds: TTL in seconds (uses default if not specified)

        Note:
            Roles are converted to a list before storage for JSON serialization
            compatibility with cache backends (Redis, etc.). The get() method
            converts the list back to frozenset on retrieval.
        """
        key = role_enrichment_key(self._namespace, tenant_id, user_id)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds

        # Store as list for JSON serialization compatibility
        await self._backend.set(key, list(roles), ttl_seconds=ttl)

        logger.debug(
            f"Role store set: tenant_id={tenant_id}, user_id={user_id}, "
            f"role_count={len(roles)}, ttl={ttl}s"
        )

    @auto_trace(logger)
    async def invalidate_user(self, tenant_id: str, user_id: str) -> int:
        """Invalidate cached roles for specific user.

        Args:
            tenant_id: Azure AD tenant ID
            user_id: User object ID to invalidate

        Returns:
            Number of entries invalidated (0 or 1)
        """
        key = role_enrichment_key(self._namespace, tenant_id, user_id)
        existed = await self._backend.exists(key)
        await self._backend.delete(key)

        count = 1 if existed else 0
        if count > 0:
            logger.info(
                f"Role store invalidated user: tenant_id={tenant_id}, user_id={user_id}"
            )
        return count

    @auto_trace(logger)
    async def invalidate_tenant(self, tenant_id: str) -> int:
        """Invalidate all cached roles for a tenant.

        Uses prefix-based invalidation to remove all role entries for the tenant.

        Args:
            tenant_id: Azure AD tenant ID to invalidate

        Returns:
            Number of entries invalidated
        """
        prefix = tenant_prefix(self._namespace, tenant_id)
        count = await self._backend.invalidate_by_prefix(prefix)

        if count > 0:
            logger.info(
                f"Role store invalidated tenant: tenant_id={tenant_id}, "
                f"entries_removed={count}"
            )

        return count



@dataclass(frozen=True)
class GraphAPIEnrichmentConfig:
    """Configuration for Microsoft Graph API role enrichment.

    Immutable configuration for optional Graph API integration.
    When enabled, roles are enriched with directory roles and app role
    assignments from Microsoft Graph API.

    Attributes:
        enabled: Whether Graph API enrichment is enabled
        client_id: Client ID for Graph API authentication
        client_secret: Client secret for Graph API (SecretStr, supports env: prefix)
        fetch_directory_roles: Fetch directory roles via memberOf endpoint
        fetch_app_roles: Fetch app role assignments
        cache_ttl_seconds: TTL for caching enriched roles (default: 3600 = 1 hour)
        timeout_seconds: HTTP request timeout for Graph API calls
    """
    enabled: bool = False
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None
    fetch_directory_roles: bool = True
    fetch_app_roles: bool = True
    cache_ttl_seconds: int = 3600
    timeout_seconds: int = 10


class AzureADDecoder(OIDCDecoder):
    """Decode and validate Azure AD-issued OIDC tokens.

    Extends OIDCDecoder with Azure AD-specific features:
    - Automatic issuer/JWKS URI construction from tenant_id
    - Support for both user tokens and app-only tokens (service principals)
    - Application role extraction from "roles" claim
    - Delegated permission extraction from "scp" claim
    - Token type detection via "idtyp" claim
    - Multi-tenant support with O(1) allowed tenants lookup (frozenset)
    - Azure AD v1.0 and v2.0 token format support
    - Directory role extraction (wids claim)
    - Security group extraction (groups claim)
    - Full JWKS signature verification (inherited from OIDCDecoder)

    Token Type Detection:
        - User tokens: "idtyp" claim is absent OR idtyp != "app"
        - App tokens: "idtyp" claim = "app"

    Tenant Validation Flow:
        1. Extract tenant ID (tid) from token BEFORE signature verification (for cache routing)
        2. Verify signature and standard claims
        3. Validate tenant ID AFTER signature verification (security)
        - Single-tenant: tid must match configured tenant_id
        - Multi-tenant: tid must be in allowed_tenants set (O(1) lookup)

    Attributes:
        tenant_id: Azure AD tenant ID (GUID) or special values:
                  - "common": Accept tokens from any Azure AD tenant
                  - "organizations": Accept tokens from any org tenant
                  - "consumers": Accept tokens from Microsoft accounts
        client_id: OAuth 2.0 client ID (application ID)
        client_secret: OAuth 2.0 client secret (optional)
        audience: Expected audience claim (optional)
        allowed_tenants: FrozenSet of allowed tenant IDs for multi-tenant apps (O(1) lookup)
        api_version: Azure AD API version ("v1.0" or "v2.0")
        issuer: Auto-constructed from tenant_id and api_version
        jwks_uri: Auto-constructed JWKS endpoint for key retrieval
        clock_skew_seconds: Clock skew tolerance for time-based claims
        key_cache: Optional cache backend for JWKS caching
    """

    # Special tenant IDs for multi-tenant configurations
    MULTI_TENANT_IDS: FrozenSet[str] = frozenset({"common", "organizations", "consumers"})

    # Maximum number of Graph API clients to cache per decoder instance
    # Prevents memory leak in high-cardinality multi-tenant scenarios
    MAX_GRAPH_CLIENTS: int = 100

    @auto_trace(logger)
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: Optional[Union[SecretStr, str]] = None,
        audience: Optional[str] = None,
        allowed_tenants: Optional[FrozenSet[str]] = None,
        api_version: str = "v2.0",
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
        key_cache: Optional[CacheBackend] = None,
        # Role enrichment configuration
        enable_graph_api: bool = False,
        graph_client_id: Optional[str] = None,
        graph_client_secret: Optional[Union[SecretStr, str]] = None,
        graph_cache_ttl_seconds: int = 3600,
        custom_role_mappings: Optional[Dict[str, str]] = None,
        # Redis-backed role store (recommended for production)
        role_store: Optional[RoleEnrichmentStore] = None,
    ):
        """Initialize Azure AD decoder with tenant configuration.

        Args:
            tenant_id: Azure AD tenant ID (GUID) or special multi-tenant value:
                      - GUID: "00000000-0000-0000-0000-000000000000" (single tenant)
                      - "common": Accept tokens from any Azure AD tenant
                      - "organizations": Accept tokens from any org tenant (no personal accounts)
                      - "consumers": Accept tokens from Microsoft personal accounts only
            client_id: OAuth 2.0 client ID (Application ID) from Azure AD app registration.
                      Format: GUID (e.g., "11111111-1111-1111-1111-111111111111")
            client_secret: OAuth 2.0 client secret (optional). Required for
                          confidential clients but not for JWT signature validation.
                          Supports "env:VAR_NAME" format for environment variable lookup.
            audience: Expected audience claim (aud) for validation. If provided,
                     token aud must match. Common values:
                     - "api://{client_id}" (default API identifier)
                     - Your custom API identifier
                     - Graph API: "https://graph.microsoft.com"
            allowed_tenants: FrozenSet of tenant IDs allowed for multi-tenant apps.
                            When provided with multi-tenant tenant_id (common/organizations),
                            validates that token's tid claim is in this set (O(1) lookup).
                            If None with multi-tenant config, all tenants are allowed.
                            Ignored for single-tenant configurations (tid must match tenant_id).
            api_version: Azure AD API version for token format.
                        - "v1.0": Legacy format (sts.windows.net issuer)
                        - "v2.0": Current format (login.microsoftonline.com issuer)
                        Default: "v2.0"
            clock_skew_seconds: Clock skew tolerance in seconds for exp/nbf
                               validation. Default: 30 seconds. Range: 0-300.
            key_cache: Optional cache backend for JWKS key caching.
                      Recommended for production to reduce JWKS endpoint calls.
            enable_graph_api: Enable Microsoft Graph API for role enrichment.
                             When enabled, roles are enriched with Graph API calls
                             for directory roles and app role assignments.
                             Default: False (claim-based roles only)
            graph_client_id: Client ID for Graph API authentication.
                            Defaults to client_id if not specified.
            graph_client_secret: Client secret for Graph API authentication.
                                Supports "env:VAR_NAME" format for environment
                                variable lookup.
            graph_cache_ttl_seconds: TTL for caching Graph API role enrichment
                                    results per user per tenant.
                                    Default: 3600 seconds (1 hour)
            custom_role_mappings: Custom directory role ID to name mappings.
                                 Extends/overrides default DIRECTORY_ROLE_MAPPINGS.
                                 Format: {"guid": "Role Name", ...}
            role_store: Role enrichment store with CacheBackend and CacheNamespace.
                       Required when enable_graph_api=True. Raises ValueError
                       if not provided with Graph API enabled.

        Raises:
            AuthError: If tenant_id format is invalid or required configuration
                      is missing

        Example:
            # Single tenant configuration - use factory function
            decoder = create_azure_ad_decoder(
                tenant_id="00000000-0000-0000-0000-000000000000",
                client_id="11111111-1111-1111-1111-111111111111",
            )

            # Multi-tenant with allowed tenants list (O(1) lookup)
            decoder = create_azure_ad_decoder(
                tenant_id="organizations",
                client_id="11111111-1111-1111-1111-111111111111",
                allowed_tenants=frozenset(["tenant1-guid", "tenant2-guid"]),
                audience="api://my-api",
            )

            # With Graph API role enrichment
            decoder = create_azure_ad_decoder(
                tenant_id="00000000-0000-0000-0000-000000000000",
                client_id="11111111-1111-1111-1111-111111111111",
                enable_graph_api=True,
                graph_client_secret="env:AZURE_GRAPH_CLIENT_SECRET",
            )
        """
        # Validate tenant_id format
        if not self._validate_tenant_id(tenant_id):
            error = AuthError(
                f"Invalid Azure AD tenant_id format: '{tenant_id}'. "
                f"Expected GUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) "
                f"or special value: 'common', 'organizations', 'consumers'"
            )
            logger.log_error(error=error)
            raise error

        # Validate client_id is present and is GUID format
        if not client_id:
            error = AuthError("Azure AD client_id is required")
            logger.log_error(error=error)
            raise error

        if not self._validate_guid_format(client_id):
            error = AuthError(
                f"Invalid Azure AD client_id format: '{client_id}'. "
                f"Expected GUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
            )
            logger.log_error(error=error)
            raise error

        # Validate api_version
        if api_version not in ("v1.0", "v2.0"):
            error = AuthError(
                f"Invalid Azure AD api_version: '{api_version}'. "
                f"Expected 'v1.0' or 'v2.0'"
            )
            logger.log_error(error=error)
            raise error

        # Store Azure AD-specific configuration
        self.tenant_id = tenant_id
        self.api_version = api_version
        self._is_multi_tenant = tenant_id.lower() in self.MULTI_TENANT_IDS
        self._allowed_tenants: FrozenSet[str] = allowed_tenants or frozenset()

        # Build role mappings (defaults + custom)
        self._role_mappings = dict(DIRECTORY_ROLE_MAPPINGS)
        if custom_role_mappings:
            self._role_mappings.update(custom_role_mappings)

        # Initialize Graph API enrichment configuration
        # Convert str → SecretStr at the boundary
        _graph_secret: Optional[SecretStr] = None
        if isinstance(graph_client_secret, SecretStr):
            _graph_secret = graph_client_secret
        elif graph_client_secret is not None:
            _graph_secret = SecretStr(graph_client_secret)

        self._graph_config = GraphAPIEnrichmentConfig(
            enabled=enable_graph_api,
            client_id=graph_client_id or client_id,
            client_secret=_graph_secret,
            cache_ttl_seconds=graph_cache_ttl_seconds,
        )

        # Initialize role enrichment store (required when enable_graph_api=True)
        if enable_graph_api and role_store is None:
            raise ValueError(
                "AzureADDecoder with enable_graph_api=True requires role_store parameter. "
                "Pass a RoleEnrichmentStore instance with CacheBackend and CacheNamespace "
                "for distributed caching."
            )
        self._role_cache: Optional["RoleEnrichmentStore"] = role_store

        # Lazy-initialized Graph API clients (per-tenant) with LRU eviction
        # Uses OrderedDict for O(1) LRU operations (move_to_end + popitem)
        self._graph_clients: OrderedDict[str, Any] = OrderedDict()
        self._graph_clients_lock = asyncio.Lock()
        # Lazy-initialized shared GraphTokenStore (created on first _get_graph_client call)
        self._graph_token_store: Optional[Any] = None

        # Auto-construct issuer URL based on API version
        # v1.0: https://sts.windows.net/{tenant_id}/
        # v2.0: https://login.microsoftonline.com/{tenant_id}/v2.0
        if api_version == "v1.0":
            issuer = f"https://sts.windows.net/{tenant_id}/"
        else:
            issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

        # Auto-construct JWKS URI for public key retrieval
        # Always uses login.microsoftonline.com endpoint regardless of API version
        jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"

        # For multi-tenant apps, we'll validate issuer differently during decode
        # Store the constructed issuer for single-tenant validation
        self._configured_issuer = issuer

        # Call parent OIDCDecoder constructor with constructed URLs
        # This sets up JWKS signature verification automatically
        # Unwrap SecretStr for parent OIDCDecoder which expects Optional[str]
        _parent_secret = (
            client_secret.get_secret_value()
            if isinstance(client_secret, SecretStr)
            else client_secret
        )
        super().__init__(
            issuer=issuer,
            client_id=client_id,
            client_secret=_parent_secret,
            audience=audience or client_id,
            jwks_uri=jwks_uri,
            clock_skew_seconds=clock_skew_seconds,
            key_cache=key_cache,
        )

        # For multi-tenant Azure AD, skip PyJWT's issuer validation
        # because the token's issuer contains the actual tenant ID, not
        # the configured multi-tenant value (common/organizations/consumers).
        # Our _validate_issuer() override will handle the validation.
        if self._is_multi_tenant:
            self._skip_pyjwt_issuer_validation = True

        logger.info(
            f"Initialized AzureADDecoder for tenant={tenant_id}, "
            f"api_version={api_version}, is_multi_tenant={self._is_multi_tenant}, "
            f"allowed_tenants_count={len(self._allowed_tenants)}, "
            f"issuer={self.issuer}, jwks_uri={self.jwks_uri}, "
            f"audience={self.audience}, clock_skew={clock_skew_seconds}s, "
            f"graph_api_enabled={enable_graph_api}"
        )

    # =========================================================================
    # Override Parent Methods
    # =========================================================================

    @auto_trace(logger, include_args=False)  # Security validation - no token data in logs
    def _validate_issuer(self, iss: str, claims: Dict[str, Any]) -> None:
        """Override OIDC issuer validation to handle multi-tenant Azure AD.

        For multi-tenant Azure AD apps (tenant_id = common/organizations/consumers),
        the token's issuer will contain the actual tenant ID, not the configured
        multi-tenant value. This method validates the issuer format instead of
        exact match, and defers tenant validation to _validate_tenant.

        For single-tenant apps, validates exact issuer match.

        Args:
            iss: Issuer claim value from token
            claims: Full claims dictionary

        Raises:
            TokenInvalidError: If issuer format is invalid for Azure AD
        """
        if self._is_multi_tenant:
            # For multi-tenant, validate issuer is a valid Azure AD issuer format
            # The actual tenant validation happens in _validate_tenant
            if self.api_version == "v2.0":
                pattern = MULTI_TENANT_V2_ISSUER_PATTERN
                tenant_pattern = re.compile(
                    r"^https://login\.microsoftonline\.com/[a-zA-Z0-9-]+/v2\.0$",
                    re.IGNORECASE,
                )
            else:
                pattern = MULTI_TENANT_V1_ISSUER_PATTERN
                tenant_pattern = re.compile(
                    r"^https://sts\.windows\.net/[a-zA-Z0-9-]+/?$",
                    re.IGNORECASE,
                )

            # Accept either multi-tenant issuer OR tenant-specific issuer
            if not (pattern.match(iss) or tenant_pattern.match(iss)):
                error = TokenInvalidError(
                    f"Azure AD issuer format invalid for multi-tenant: '{iss}'"
                )
                logger.log_error(error=error)
                raise error

            logger.debug(
                f"Multi-tenant Azure AD issuer accepted: {iss}"
            )
        else:
            # Single-tenant: strict issuer validation
            if iss != self.issuer:
                error = TokenInvalidError(
                    f"Azure AD issuer mismatch: expected '{self.issuer}', got '{iss}'"
                )
                logger.log_error(error=error)
                raise error

    # =========================================================================
    # Core Public Methods
    # =========================================================================

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if Azure AD token is valid without extracting identity.

        Performs same validation as decode() but returns boolean instead
        of raising exceptions. Useful for permission checks where you only
        need to know if token is valid.

        Args:
            token: Azure AD token string

        Returns:
            True if token is valid (signature, expiration, tenant all pass),
            False otherwise

        Example:
            is_valid = await decoder.validate(token)
            if is_valid:
                logger.info("Azure AD token validation successful")
            else:
                logger.warning("Azure AD token validation failed")
        """
        try:
            await self.decode(token)
            return True
        except (TokenInvalidError, TokenExpiredError, TenantValidationError) as e:
            logger.debug(f"Azure AD token validation failed: {str(e)}")
            return False
        except Exception as e:
            logger.log_error(error=e)
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if Azure AD token has been revoked.

        For Azure AD tokens validated by JWKS signature only, revocation
        checking is not supported by default. This method always returns False.

        Azure AD supports token revocation through:
        1. Short-lived tokens (recommended): Use tokens with short exp (5-60 min)
        2. Microsoft Graph API: Check user status and sign-in risk
        3. Azure AD Conditional Access: Continuous access evaluation (CAE)

        For production revocation support:
        - Implement CAE (Continuous Access Evaluation)
        - Use Microsoft Graph API to check user/session status
        - Override this method in a subclass with Graph API integration

        Args:
            token: Azure AD token string

        Returns:
            False (revocation not supported for JWKS-only validation)

        Note:
            Graph API integration for revocation checking is handled by
            a separate component (GraphAPIEnricher) and can be composed
            with this decoder.
        """
        # Azure AD JWKS-only validation does not support revocation checking
        # For revocation support:
        # - Use short-lived tokens (5-60 minutes)
        # - Implement Continuous Access Evaluation (CAE)
        # - Use Microsoft Graph API (separate component)
        return False

    # =========================================================================
    # Azure AD-Specific Tenant Validation (Private)
    # =========================================================================

    @auto_trace(logger)
    def _validate_azure_tenant(self, claims: Dict[str, Any]) -> None:
        """Validate Azure AD tenant ID against allowed tenants.

        Performs tenant validation based on configuration:
        - Single-tenant: tid must match configured tenant_id
        - Multi-tenant with allowed_tenants: tid must be in allowed_tenants set (O(1))
        - Multi-tenant without allowed_tenants: all tenants allowed

        This method is called AFTER signature verification to ensure the tid
        claim has not been tampered with.

        Args:
            claims: Decoded and signature-verified JWT claims

        Raises:
            TenantValidationError: If tenant ID doesn't match allowed tenants
        """
        token_tenant_id = claims.get("tid", "").lower()

        if not token_tenant_id:
            error = TenantValidationError(
                "Azure AD token missing 'tid' (tenant ID) claim"
            )
            logger.log_error(error=error)
            raise error

        # Validate GUID format for tenant ID
        if not self._validate_guid_format(token_tenant_id):
            error = TenantValidationError(
                f"Azure AD tenant ID has invalid format: '{token_tenant_id}'. "
                f"Expected GUID format."
            )
            logger.log_error(error=error)
            raise error

        # Single-tenant mode: tid must match configured tenant_id
        if not self._is_multi_tenant:
            if token_tenant_id != self.tenant_id.lower():
                error = TenantValidationError(
                    f"Azure AD tenant mismatch: expected '{self.tenant_id}', "
                    f"got '{token_tenant_id}'. Token issued by unauthorized tenant."
                )
                logger.log_error(error=error)
                raise error
            logger.debug(
                f"Single-tenant validation passed: tenant_id={token_tenant_id}"
            )
            return

        # Multi-tenant mode with allowed_tenants: tid must be in set (O(1) lookup)
        if self._allowed_tenants:
            # Normalize allowed_tenants for case-insensitive comparison
            normalized_allowed = frozenset(t.lower() for t in self._allowed_tenants)
            if token_tenant_id not in normalized_allowed:
                error = TenantValidationError(
                    f"Azure AD tenant '{token_tenant_id}' not in allowed tenants list. "
                    f"Token issued by unauthorized tenant."
                )
                logger.log_error(error=error)
                raise error
            logger.debug(
                f"Multi-tenant validation passed: tenant_id={token_tenant_id} "
                f"found in allowed_tenants"
            )
            return

        # Multi-tenant mode without allowed_tenants: all tenants allowed
        logger.debug(
            f"Multi-tenant validation passed (all tenants allowed): "
            f"tenant_id={token_tenant_id}"
        )

    # =========================================================================
    # Private Validation Methods
    # =========================================================================

    @auto_trace(logger)
    def _validate_tenant_id(self, tenant_id: str) -> bool:
        """Validate Azure AD tenant_id format.

        Azure AD tenant IDs can be:
        - GUID: "00000000-0000-0000-0000-000000000000" (single tenant)
        - Special values: "common", "organizations", "consumers" (multi-tenant)

        Args:
            tenant_id: Azure AD tenant ID to validate

        Returns:
            True if format is valid, False otherwise
        """
        if not tenant_id:
            logger.warning("Azure AD tenant_id is empty")
            return False

        # Check for special multi-tenant values
        if tenant_id.lower() in self.MULTI_TENANT_IDS:
            logger.debug(f"Tenant ID '{tenant_id}' is a valid multi-tenant identifier")
            return True

        # Check for GUID format
        return self._validate_guid_format(tenant_id)

    @auto_trace(logger)
    def _validate_guid_format(self, value: str) -> bool:
        """Validate GUID format (Azure AD uses GUIDs for IDs).

        Args:
            value: Value to validate as GUID

        Returns:
            True if value matches GUID format, False otherwise
        """
        if not value:
            return False

        # Use pre-compiled GUID pattern for ReDoS security
        if GUID_PATTERN.match(value):
            logger.debug(f"Value '{value}' matches GUID format")
            return True

        logger.debug(f"Value '{value}' does not match GUID format")
        return False

    @auto_trace(logger)
    def _is_app_token(self, claims: Dict[str, Any]) -> bool:
        """Detect if token is an app-only (service principal) token.

        Azure AD app-only tokens have:
        - "idtyp" claim = "app"

        User (delegated) tokens:
        - "idtyp" claim is absent OR idtyp != "app"

        Args:
            claims: Decoded JWT payload claims

        Returns:
            True if token is app-only (service principal), False if user token
        """
        idtyp = claims.get("idtyp", "")
        is_app = idtyp == "app"

        logger.debug(
            f"Token type detection: idtyp='{idtyp}', is_app_token={is_app}"
        )

        return is_app

    @auto_trace(logger)
    def _extract_tenant_from_issuer(self, issuer: str) -> Optional[str]:
        """Extract tenant ID from issuer URL.

        Handles both v1.0 and v2.0 issuer formats:
        - v1.0: https://sts.windows.net/{tenant_id}/
        - v2.0: https://login.microsoftonline.com/{tenant_id}/v2.0

        Args:
            issuer: Issuer URL from token

        Returns:
            Tenant ID extracted from issuer, or None if extraction fails
        """
        if not issuer:
            return None

        # v1.0 format: https://sts.windows.net/{tenant_id}/
        # Use pre-compiled pattern for ReDoS security
        v1_match = V1_ISSUER_EXTRACT_PATTERN.search(issuer)
        if v1_match:
            tenant = v1_match.group(1)
            logger.debug(f"Extracted tenant '{tenant}' from v1.0 issuer")
            return tenant

        # v2.0 format: https://login.microsoftonline.com/{tenant_id}/v2.0
        # Use pre-compiled pattern for ReDoS security
        v2_match = V2_ISSUER_EXTRACT_PATTERN.search(issuer)
        if v2_match:
            tenant = v2_match.group(1)
            logger.debug(f"Extracted tenant '{tenant}' from v2.0 issuer")
            return tenant

        logger.warning(f"Could not extract tenant from issuer: {issuer}")
        return None

    @auto_trace(logger)
    def _extract_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract roles from Azure AD token.

        Roles can come from:
        - "roles" claim (array): Application role assignments
        - Works for both user tokens (assigned roles) and app tokens (app permissions)

        Args:
            claims: Decoded JWT payload claims

        Returns:
            List of role names (empty list if no roles)
        """
        roles_claim = claims.get("roles", [])

        if not roles_claim:
            return []

        if isinstance(roles_claim, list):
            roles = [str(r).strip() for r in roles_claim if r]
            logger.debug(f"Extracted {len(roles)} roles from 'roles' claim")
            return roles

        if isinstance(roles_claim, str):
            # Handle space-separated string (rare but possible)
            roles = [r.strip() for r in roles_claim.split() if r.strip()]
            logger.debug(f"Extracted {len(roles)} roles from string 'roles' claim")
            return roles

        logger.warning(f"Unexpected roles claim type: {type(roles_claim)}")
        return []

    @auto_trace(logger)
    def _extract_wids_roles(self, claims: Dict[str, Any]) -> FrozenSet[str]:
        """Extract and map directory roles from wids claim.

        Azure AD includes directory role assignments in the "wids" claim
        as an array of role template GUIDs. This method maps those GUIDs
        to human-readable role names using DIRECTORY_ROLE_MAPPINGS.

        Role Sources (Priority Order):
        1. Claim-based roles (from "roles" claim, immediate)
        2. Directory roles from wids claim (mapped to names)
        3. Graph API directory roles (if enabled, async)
        4. Graph API app role assignments (if enabled)

        Args:
            claims: Decoded JWT payload claims

        Returns:
            FrozenSet of directory role names (normalized to lowercase)
        """
        wids_claim = claims.get("wids", [])

        if not wids_claim:
            logger.debug(
                "No 'wids' claim found in token",
                tenant_id=claims.get("tid"),
            )
            return frozenset()

        if not isinstance(wids_claim, list):
            logger.warning(
                f"Unexpected 'wids' claim type: {type(wids_claim)}, expected list",
                tenant_id=claims.get("tid"),
            )
            return frozenset()

        roles: Set[str] = set()
        for role_id in wids_claim:
            role_id_str = str(role_id).lower().strip()
            if not role_id_str:
                continue

            # Look up role name in mappings
            role_name = self._role_mappings.get(role_id_str)
            if role_name:
                roles.add(role_name.lower())
            else:
                # Use GUID as-is if no mapping found (prefixed for clarity)
                roles.add(f"directory_role:{role_id_str}")
                logger.debug(
                    f"Unknown directory role ID: {role_id_str}",
                    tenant_id=claims.get("tid"),
                )

        logger.debug(
            f"Extracted {len(roles)} directory roles from 'wids' claim",
            tenant_id=claims.get("tid"),
            role_count=len(roles),
        )

        return frozenset(roles)

    @auto_trace(logger)
    async def _get_graph_client(self, tenant_id: str):
        """Get or create Graph API client for tenant (lazy initialization).

        Clients are cached per-tenant to allow token reuse and
        minimize connection overhead.

        Args:
            tenant_id: Azure AD tenant ID

        Returns:
            GraphAPIClient instance for the tenant, or None if not configured
        """
        if not self._graph_config.enabled:
            return None

        if not self._graph_config.client_secret:
            logger.warning(
                "Graph API enabled but client_secret not configured",
                tenant_id=tenant_id,
            )
            return None

        async with self._graph_clients_lock:
            if tenant_id in self._graph_clients:
                # Move to end for LRU (most recently used)
                self._graph_clients.move_to_end(tenant_id)
                return self._graph_clients[tenant_id]

            # Lazy import to avoid circular dependency
            from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_graph import (
                GraphAPIClient,
                GraphTokenStore,
            )

            # Resolve secret from environment if needed
            client_secret = self._resolve_secret(self._graph_config.client_secret)
            if not client_secret:
                logger.warning(
                    "Graph API client_secret could not be resolved",
                    tenant_id=tenant_id,
                )
                return None

            # Evict oldest (least recently used) clients if at capacity
            while len(self._graph_clients) >= self.MAX_GRAPH_CLIENTS:
                evicted_tenant, evicted_client = self._graph_clients.popitem(last=False)
                logger.debug(
                    f"Evicted LRU GraphAPIClient for tenant: {evicted_tenant}"
                )
                # Close evicted client if it has a close method
                if hasattr(evicted_client, "close"):
                    try:
                        await evicted_client.close()
                    except Exception as e:
                        logger.warning(
                            f"Error closing evicted GraphAPIClient: {e}",
                            tenant_id=evicted_tenant,
                        )

            # Create shared token store on first use from role_cache's
            # backend/namespace. role_cache is guaranteed non-None here:
            # enable_graph_api=True requires role_store (validated in __init__).
            if self._graph_token_store is None:
                self._graph_token_store = GraphTokenStore(
                    backend=self._role_cache._backend,
                    namespace=self._role_cache._namespace,
                )

            self._graph_clients[tenant_id] = GraphAPIClient(
                tenant_id=tenant_id,
                client_id=self._graph_config.client_id or self.client_id,
                client_secret=client_secret,
                timeout_seconds=self._graph_config.timeout_seconds,
                token_store=self._graph_token_store,
            )
            logger.debug(
                f"Created GraphAPIClient for tenant: {tenant_id}"
            )

            return self._graph_clients[tenant_id]

    @auto_trace(logger)
    def _resolve_secret(self, secret: Optional[Union[SecretStr, str]]) -> Optional[str]:
        """Resolve secret from environment variable if prefixed with 'env:'.

        Args:
            secret: SecretStr, plain string, or 'env:VAR_NAME' reference

        Returns:
            Resolved secret value or None if not found
        """
        if secret is None:
            return None
        raw = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
        if not raw:
            return None
        if raw.startswith("env:"):
            env_var = raw[4:]
            return os.getenv(env_var)
        return raw

    @auto_trace(logger)
    async def _enrich_roles_with_graph_api(
        self,
        user_oid: str,
        tenant_id: str,
        existing_roles: FrozenSet[str],
    ) -> FrozenSet[str]:
        """Enrich roles with Graph API directory and app roles.

        Calls Microsoft Graph API to fetch additional role information
        that may not be in the token claims. This includes:
        - Directory role memberships (via /memberOf endpoint)
        - App role assignments (via /appRoleAssignments endpoint)

        Errors are logged but do not fail token validation (graceful degradation).
        If Graph API is unavailable, returns existing roles unchanged.

        NOTE: This graceful degradation is acceptable for ENRICHMENT only because:
        1. Token validation already succeeded (baseline identity established)
        2. Claim-based roles provide fallback authorization data
        3. Enrichment supplements, not replaces, token claims

        CONTRAST: Permission RESOLUTION must fail-closed because incomplete
        permission data creates ambiguous authorization decisions.

        Error Handling (Graceful Degradation):
        - Graph API 401: Log warning, continue with claim-based roles
        - Graph API 403: Log warning, use claim roles (insufficient permissions)
        - Graph API timeout: Log warning, return claim-based roles
        - Graph API 429: Exponential backoff handled by client, don't fail
        - Never raise exception from role enrichment

        Args:
            user_oid: Azure AD object ID (oid claim)
            tenant_id: Azure AD tenant ID (tid claim)
            existing_roles: Roles already extracted from claims

        Returns:
            FrozenSet of all roles (existing + Graph API roles)
        """
        if not self._graph_config.enabled:
            return existing_roles

        # Check cache first
        cached_roles = await self._role_cache.get(tenant_id, user_oid)
        if cached_roles is not None:
            logger.debug(
                "Using cached Graph API roles",
                tenant_id=tenant_id,
                user_id=user_oid,
                cached_role_count=len(cached_roles),
            )
            return existing_roles | cached_roles

        try:
            graph_client = await self._get_graph_client(tenant_id)
            if not graph_client:
                return existing_roles

            graph_roles: Set[str] = set()

            # Fetch directory roles
            if self._graph_config.fetch_directory_roles:
                try:
                    directory_roles = await graph_client.get_directory_roles(user_oid)
                    graph_roles.update(r.lower() for r in directory_roles)
                    logger.debug(
                        f"Fetched {len(directory_roles)} directory roles from Graph API",
                        tenant_id=tenant_id,
                        user_id=user_oid,
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to fetch directory roles from Graph API",
                        tenant_id=tenant_id,
                        user_id=user_oid,
                        error=str(e),
                    )

            # Cache the Graph API roles
            graph_roles_frozen = frozenset(graph_roles)
            await self._role_cache.set(
                tenant_id,
                user_oid,
                graph_roles_frozen,
                self._graph_config.cache_ttl_seconds,
            )

            logger.info(
                "Enriched roles via Graph API",
                tenant_id=tenant_id,
                user_id=user_oid,
                graph_role_count=len(graph_roles),
                total_roles=len(existing_roles | graph_roles_frozen),
            )

            return existing_roles | graph_roles_frozen

        except Exception as e:
            # Graph API errors should never fail token validation
            logger.warning(
                "Graph API role enrichment failed (graceful degradation)",
                tenant_id=tenant_id,
                user_id=user_oid,
                error=str(e),
            )
            return existing_roles

    @auto_trace(logger)
    async def _handle_groups_overage(
        self,
        claims: Dict[str, Any],
        user_oid: str,
        tenant_id: str,
    ) -> List[str]:
        """Handle groups overage scenario via Graph API.

        When a user belongs to too many groups (typically >200), Azure AD
        includes _claim_names/_claim_sources claims instead of the full
        groups list. This method fetches groups from Graph API when
        overage is detected.

        Groups Overage Detection:
        - Token contains "_claim_names" with "groups" key
        - Token contains "_claim_sources" with endpoint URL
        - Groups claim is empty or missing despite user having groups

        Args:
            claims: Decoded JWT payload claims
            user_oid: Azure AD object ID
            tenant_id: Azure AD tenant ID

        Returns:
            List of group IDs (empty if no overage or Graph API disabled)
        """
        # Check for overage indicator
        claim_names = claims.get("_claim_names", {})
        if not isinstance(claim_names, dict) or "groups" not in claim_names:
            return []

        logger.info(
            "Groups overage detected, fetching from Graph API",
            tenant_id=tenant_id,
            user_id=user_oid,
        )

        if not self._graph_config.enabled:
            logger.warning(
                "Groups overage detected but Graph API not enabled. "
                "Groups may be incomplete. Enable Graph API for full group support.",
                tenant_id=tenant_id,
            )
            return []

        try:
            graph_client = await self._get_graph_client(tenant_id)
            if not graph_client:
                return []

            groups = await graph_client.get_user_groups(user_oid)

            logger.info(
                "Fetched groups via Graph API for overage scenario",
                tenant_id=tenant_id,
                user_id=user_oid,
                group_count=len(groups),
            )

            return groups

        except Exception as e:
            logger.warning(
                "Failed to fetch groups for overage scenario",
                tenant_id=tenant_id,
                user_id=user_oid,
                error=str(e),
            )
            return []

    @auto_trace(logger)
    def _extract_permissions_from_scp(self, claims: Dict[str, Any]) -> List[str]:
        """Extract delegated permissions from scp claim.

        User (delegated) tokens contain:
        - "scp" claim: Space-separated delegated permission scopes
        - Example: "User.Read Files.ReadWrite Calendar.Read"

        App-only tokens typically have empty or no "scp" claim.

        Args:
            claims: Decoded JWT payload claims

        Returns:
            List of permission/scope strings (empty list if no scp claim)
        """
        scp_claim = claims.get("scp", "")

        if not scp_claim:
            return []

        if isinstance(scp_claim, str):
            permissions = [s.strip() for s in scp_claim.split() if s.strip()]
            logger.debug(f"Extracted {len(permissions)} permissions from 'scp' claim")
            return permissions

        if isinstance(scp_claim, list):
            permissions = [str(s).strip() for s in scp_claim if s]
            logger.debug(f"Extracted {len(permissions)} permissions from list 'scp' claim")
            return permissions

        logger.warning(f"Unexpected scp claim type: {type(scp_claim)}")
        return []

    @auto_trace(logger)
    def _extract_app_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Extract identity from app-only (service principal) token.

        App-only tokens:
        - user_id = appid (application's client ID)
        - tenant_id = extracted from tid claim or issuer
        - provider_user_id = oid (service principal object ID)
        - roles = from "roles" claim (app permissions)
        - permissions = from "roles" claim (mapped to permissions)
        - attributes["token_type"] = "app"
        - attributes["service_principal_id"] = oid

        Args:
            claims: Decoded JWT payload claims (verified app-only token)

        Returns:
            IdentityContext with service principal identity

        Raises:
            TokenInvalidError: If required claims (oid, appid) are missing
        """
        # For app tokens, oid is the service principal object ID
        oid = claims.get("oid")
        if not oid:
            error = TokenInvalidError(
                "Azure AD app token missing required 'oid' (object ID) claim. "
                "Service principal object ID is required for app-only tokens."
            )
            logger.log_error(error=error)
            raise error

        # appid is the application (client) ID
        # In v2.0 tokens, this may be in 'azp' claim instead
        appid = claims.get("appid") or claims.get("azp")
        if not appid:
            error = TokenInvalidError(
                "Azure AD app token missing required 'appid' or 'azp' claim. "
                "Application client ID is required for app-only tokens."
            )
            logger.log_error(error=error)
            raise error

        # Extract tenant_id from tid claim or issuer
        tenant_id = claims.get("tid")
        if not tenant_id:
            # Try to extract from issuer
            issuer = claims.get("iss", "")
            tenant_id = self._extract_tenant_from_issuer(issuer)
            if not tenant_id:
                tenant_id = self.tenant_id  # Fall back to configured tenant

        # Extract roles (app permissions)
        roles = self._extract_roles(claims)

        # For app tokens, roles are also treated as permissions
        # (they represent granted application permissions)
        permissions = frozenset(roles)

        # Build attributes with Azure AD-specific claims
        attributes: Dict[str, Any] = {
            "token_type": "app",
            "service_principal_id": oid,
            "appid": appid,
        }

        # Add optional claims to attributes
        if "ver" in claims:
            attributes["ver"] = claims["ver"]
        if "iss" in claims:
            attributes["iss"] = claims["iss"]

        # Build identity context
        # For app tokens, user_id is the appid (client ID)
        identity = IdentityContext(
            user_id=appid,
            tenant_id=tenant_id,
            roles=frozenset(roles),
            permissions=permissions,
            attributes=attributes,
            provider="azure",
            issuer=claims.get("iss", self.issuer),
            provider_user_id=oid,  # Service principal object ID
        )

        logger.info(
            f"Extracted Azure AD app identity: appid={appid}, "
            f"tenant_id={tenant_id}, service_principal_id={oid}, "
            f"roles_count={len(roles)}"
        )

        return identity

    @auto_trace(logger)
    def _extract_user_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Extract identity from user (delegated) token.

        User tokens:
        - user_id = sub (subject, user identifier)
        - tenant_id = tid claim
        - provider_user_id = oid (user object ID)
        - roles = from "roles" claim (assigned directory/app roles)
        - permissions = from "scp" claim (delegated permission scopes)
        - attributes["token_type"] = "user"

        Args:
            claims: Decoded JWT payload claims (verified user token)

        Returns:
            IdentityContext with user identity

        Raises:
            TokenInvalidError: If required claims (sub) are missing
        """
        # Extract required user claims
        user_id = claims.get("sub")
        if not user_id:
            # Fall back to oid if sub is not present (some v1.0 tokens)
            user_id = claims.get("oid")
            if not user_id:
                error = TokenInvalidError(
                    "Azure AD user token missing required 'sub' (subject) claim. "
                    "For user tokens, 'sub' or 'oid' must be present."
                )
                logger.log_error(error=error)
                raise error

        # oid is the user's object ID in Azure AD
        oid = claims.get("oid", user_id)

        # Extract tenant_id from tid claim
        tenant_id = claims.get("tid")
        if not tenant_id:
            # Try to extract from issuer
            issuer = claims.get("iss", "")
            tenant_id = self._extract_tenant_from_issuer(issuer)
            if not tenant_id:
                tenant_id = self.tenant_id  # Fall back to configured tenant

        # Extract roles from "roles" claim (app roles)
        app_roles = self._extract_roles(claims)

        # Extract directory roles from "wids" claim (mapped to names)
        wids_roles = self._extract_wids_roles(claims)

        # Combine all immediate roles (claim-based)
        # Normalize app roles to lowercase for consistency
        combined_roles = frozenset(r.lower() for r in app_roles) | wids_roles

        # Extract permissions from scp claim (delegated permissions)
        scp_permissions = self._extract_permissions_from_scp(claims)

        # Extract groups from token (may be incomplete if overage)
        groups_claim = claims.get("groups", [])
        groups = list(groups_claim) if isinstance(groups_claim, list) else []

        # Build attributes with Azure AD-specific claims
        attributes: Dict[str, Any] = {
            "token_type": "user",
        }

        # Store groups in attributes
        if groups:
            attributes["groups"] = groups

        # Store directory role IDs (wids) for reference
        if claims.get("wids"):
            attributes["directory_role_ids"] = claims["wids"]

        # Add optional user profile claims to attributes
        if "email" in claims:
            attributes["email"] = claims["email"]
        if "name" in claims:
            attributes["name"] = claims["name"]
        if "preferred_username" in claims:
            attributes["preferred_username"] = claims["preferred_username"]
        if "given_name" in claims:
            attributes["given_name"] = claims["given_name"]
        if "family_name" in claims:
            attributes["family_name"] = claims["family_name"]
        if "ver" in claims:
            attributes["ver"] = claims["ver"]
        if "appid" in claims or "azp" in claims:
            attributes["appid"] = claims.get("appid") or claims.get("azp")

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=combined_roles,
            permissions=frozenset(scp_permissions),
            attributes=attributes,
            provider="azure",
            issuer=claims.get("iss", self.issuer),
            provider_user_id=oid,
        )

        logger.info(
            f"Extracted Azure AD user identity: user_id={user_id}, "
            f"tenant_id={tenant_id}, oid={oid}, "
            f"app_roles={len(app_roles)}, wids_roles={len(wids_roles)}, "
            f"total_roles={len(combined_roles)}, "
            f"permissions_count={len(scp_permissions)}"
        )

        return identity

    @auto_trace(logger)
    def _extract_oidc_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Override parent to extract Azure AD-specific identity claims.

        Detects token type (user vs app) and delegates to appropriate extractor:
        - App tokens (idtyp="app"): _extract_app_identity()
        - User tokens (idtyp absent/other): _extract_user_identity()

        Args:
            claims: Decoded and validated JWT payload claims

        Returns:
            IdentityContext with Azure AD-specific attributes

        Raises:
            TokenInvalidError: If required claims are missing
        """
        # Detect token type
        is_app = self._is_app_token(claims)

        # Route to appropriate identity extractor
        if is_app:
            return self._extract_app_identity(claims)
        else:
            return self._extract_user_identity(claims)

    @auto_trace(logger)
    def _validate_oidc_claims(self, claims: Dict[str, Any]) -> None:
        """Override parent to validate Azure AD-specific claims.

        Validates required claims based on token type:
        - User tokens: sub (or oid), iss, aud, exp, iat
        - App tokens: oid, appid (or azp), iss, aud, exp, iat

        Also validates:
        - Tenant consistency (if single-tenant configured)
        - Issuer format matches Azure AD patterns

        Args:
            claims: Decoded JWT payload claims

        Raises:
            TokenInvalidError: If required claims are missing or invalid
        """
        # Call parent validation first for standard OIDC claims
        # But we need to be flexible about 'sub' for app tokens
        is_app = self._is_app_token(claims)

        if is_app:
            # App tokens: require oid, appid/azp instead of sub
            required_claims = ["iss", "aud", "exp", "iat"]
            self._validate_required_claims(claims, required_claims)

            # Validate app-specific required claims
            if not claims.get("oid"):
                error = TokenInvalidError(
                    "Azure AD app token missing required 'oid' claim"
                )
                logger.log_error(error=error)
                raise error

            if not (claims.get("appid") or claims.get("azp")):
                error = TokenInvalidError(
                    "Azure AD app token missing required 'appid' or 'azp' claim"
                )
                logger.log_error(error=error)
                raise error
        else:
            # User tokens: require standard OIDC claims
            # sub is required, but some v1.0 tokens may only have oid
            required_claims = ["iss", "aud", "exp", "iat"]
            self._validate_required_claims(claims, required_claims)

            if not (claims.get("sub") or claims.get("oid")):
                error = TokenInvalidError(
                    "Azure AD user token missing required 'sub' or 'oid' claim"
                )
                logger.log_error(error=error)
                raise error

        # Validate issuer format for Azure AD
        issuer = claims.get("iss", "")
        if not self._validate_azure_issuer(issuer):
            error = TokenInvalidError(
                f"Azure AD token has invalid issuer format: '{issuer}'. "
                f"Expected format: 'https://sts.windows.net/{{tenant}}/' (v1.0) or "
                f"'https://login.microsoftonline.com/{{tenant}}/v2.0' (v2.0)"
            )
            logger.log_error(error=error)
            raise error

        # For single-tenant apps, validate tenant matches
        if not self._is_multi_tenant:
            token_tenant = claims.get("tid")
            if token_tenant and token_tenant != self.tenant_id:
                error = TokenInvalidError(
                    f"Azure AD token tenant mismatch. Expected '{self.tenant_id}', "
                    f"got '{token_tenant}'. Token is from wrong tenant."
                )
                logger.log_error(error=error)
                raise error

        logger.debug(
            f"Azure AD claims validation passed: is_app={is_app}, "
            f"issuer={issuer}, tenant={claims.get('tid')}"
        )

    @auto_trace(logger)
    def _validate_azure_issuer(self, issuer: str) -> bool:
        """Validate issuer matches Azure AD patterns.

        Valid Azure AD issuer patterns:
        - v1.0: https://sts.windows.net/{tenant_id}/
        - v2.0: https://login.microsoftonline.com/{tenant_id}/v2.0

        Args:
            issuer: Issuer URL from token

        Returns:
            True if issuer matches Azure AD pattern, False otherwise
        """
        if not issuer:
            return False

        # v1.0 pattern - use pre-compiled pattern for ReDoS security
        if V1_ISSUER_VALIDATION_PATTERN.match(issuer):
            return True

        # v2.0 pattern - use pre-compiled pattern for ReDoS security
        if V2_ISSUER_VALIDATION_PATTERN.match(issuer):
            return True

        # Multi-tenant patterns (common, organizations, consumers)
        # Use pre-compiled patterns for ReDoS security
        if MULTI_TENANT_V1_ISSUER_PATTERN.match(issuer):
            return True

        if MULTI_TENANT_V2_ISSUER_PATTERN.match(issuer):
            return True

        return False

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and validate Azure AD token with optional Graph API enrichment.

        Performs complete Azure AD token validation:
        1. JWT structure validation (3 parts)
        2. JWKS-based signature verification
        3. Standard OIDC claims validation
        4. Azure AD-specific claims extraction (roles, wids, groups, scp)
        5. Optional Graph API role enrichment (async, non-blocking)
        6. Groups overage handling (if applicable)

        Role Sources (Priority Order):
        1. Claim-based roles (from "roles" claim, immediate)
        2. Directory roles from wids claim (mapped to names)
        3. Graph API directory roles (if enabled, async)
        4. Default roles (fallback if extraction fails)

        Graceful Degradation:
        - Graph API errors never fail token validation
        - If Graph API unavailable, claim-based roles are used
        - Groups overage handled when Graph API enabled

        Args:
            token: Azure AD JWT token string

        Returns:
            IdentityContext with user identity, roles (enriched if Graph API enabled),
            permissions, and Azure AD-specific attributes

        Raises:
            TokenInvalidError: Token format invalid, signature fails, etc.
            TokenExpiredError: Token has expired
            TenantValidationError: Token tenant ID doesn't match allowed tenants
        """
        # Step 1: Validate JWT structure (3 parts)
        self._validate_token_structure(token)

        # Step 2: Extract tenant ID from payload BEFORE signature verification
        # This is needed for multi-tenant apps to potentially route to correct JWKS
        # NOTE: Claims are UNTRUSTED until signature is verified
        unverified_claims = self._decode_payload(token)
        unverified_tenant_id = unverified_claims.get("tid")

        if not unverified_tenant_id:
            error = TokenInvalidError(
                "Azure AD token missing required 'tid' (tenant ID) claim"
            )
            logger.log_error(error=error)
            raise error

        # Step 3 & 4: Call parent decode() for signature verification and basic validation.
        # super().decode() calls _fetch_and_verify_signature (JWKS verification)
        # then _validate_oidc_claims and _extract_oidc_identity (both overridden
        # by this class to handle Azure AD-specific claims). The identity returned
        # contains verified claims extracted from the signature-verified payload.
        identity = await super().decode(token)

        # Step 5: Validate Azure AD tenant using verified identity fields.
        # Build a claims dict from the verified identity rather than re-parsing
        # the raw token payload (which would bypass signature verification).
        verified_claims = {
            "tid": identity.tenant_id,
            "oid": identity.provider_user_id or identity.user_id,
            "idtyp": identity.attributes.get("token_type", ""),
        }
        self._validate_azure_tenant(verified_claims)

        # If Graph API enrichment is not enabled, return immediately
        if not self._graph_config.enabled:
            return identity

        # Use verified identity fields for enrichment (not re-extracted claims)
        user_oid = identity.provider_user_id or identity.user_id
        tenant_id = identity.tenant_id

        # Only enrich user tokens (not app tokens)
        if identity.attributes.get("token_type") == "app":
            logger.debug(
                "Skipping Graph API enrichment for app token",
                tenant_id=tenant_id,
            )
            return identity

        # Enrich roles with Graph API (non-blocking, graceful degradation)
        enriched_roles = await self._enrich_roles_with_graph_api(
            user_oid=user_oid,
            tenant_id=tenant_id,
            existing_roles=identity.roles,
        )

        # Handle groups overage using identity attributes.
        # _claim_names/_claim_sources are needed for overage detection but
        # aren't stored in identity.attributes by _extract_user_identity.
        # Re-extract these specific claims from the already-validated token
        # for groups overage detection only. The token signature was verified
        # by super().decode() above — _claim_names is only used to decide
        # whether to call Graph API (not for security decisions).
        overage_claims = self._decode_payload(token)
        updated_attributes = dict(identity.attributes)
        overage_groups = await self._handle_groups_overage(
            claims=overage_claims,
            user_oid=user_oid,
            tenant_id=tenant_id,
        )

        if overage_groups:
            updated_attributes["groups"] = overage_groups

        # Create new identity with enriched roles
        if enriched_roles != identity.roles or overage_groups:
            identity = IdentityContext(
                user_id=identity.user_id,
                tenant_id=identity.tenant_id,
                roles=enriched_roles,
                permissions=identity.permissions,
                attributes=updated_attributes,
                provider=identity.provider,
                issuer=identity.issuer,
                provider_user_id=identity.provider_user_id,
            )

            logger.info(
                f"Azure AD token decoded with Graph API enrichment: "
                f"user_id={identity.user_id}, tenant_id={identity.tenant_id}, "
                f"total_roles={len(identity.roles)}"
            )
        else:
            logger.info(
                f"Azure AD token decoded: user_id={identity.user_id}, "
                f"tenant_id={identity.tenant_id}, roles={len(identity.roles)}"
            )

        return identity

    @auto_trace(logger)
    async def close(self) -> None:
        """Close all Graph API clients and cleanup resources.

        Should be called when the decoder is no longer needed to properly
        close HTTP connections and cleanup resources.

        Safe to call multiple times (idempotent).

        Example:
            decoder = AzureADDecoder(...)
            try:
                identity = await decoder.decode(token)
            finally:
                await decoder.close()
        """
        async with self._graph_clients_lock:
            for tenant_id, client in self._graph_clients.items():
                try:
                    await client.close()
                    logger.debug(f"Closed GraphAPIClient for tenant: {tenant_id}")
                except Exception as e:
                    logger.warning(
                        f"Error closing GraphAPIClient for tenant {tenant_id}: {e}"
                    )
            self._graph_clients.clear()
            logger.info("Closed all Azure AD decoder Graph API clients")

    async def __aenter__(self) -> "AzureADDecoder":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit with cleanup."""
        await self.close()


# =============================================================================
# Factory Function
# =============================================================================


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_azure_decoder(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[Union[SecretStr, str]] = None,
    audience: Optional[str] = None,
    allowed_tenants: Optional[FrozenSet[str]] = None,
    api_version: Optional[str] = None,
    clock_skew_seconds: Optional[int] = None,
    key_cache: Optional[CacheBackend] = None,
    enable_graph_api: Optional[bool] = None,
    graph_client_id: Optional[str] = None,
    graph_client_secret: Optional[Union[SecretStr, str]] = None,
    graph_cache_ttl_seconds: int = 3600,
    custom_role_mappings: Optional[Dict[str, str]] = None,
    role_store: Optional[RoleEnrichmentStore] = None,
) -> AzureADDecoder:
    """Factory function for AzureADDecoder instantiation.

    This is the recommended way to create AzureADDecoder instances.
    Do NOT call the constructor directly.

    Creates an AzureADDecoder instance with configuration from parameters or
    environment variables. Supports both single-tenant and multi-tenant
    configurations with allowed_tenants list for O(1) tenant validation.

    Environment variables (used if parameters not provided):
    - AZURE_AD_TENANT_ID: Azure AD tenant ID (GUID or "common"/"organizations"/"consumers")
    - AZURE_AD_CLIENT_ID: OAuth 2.0 client ID (application ID)
    - AZURE_AD_CLIENT_SECRET: OAuth 2.0 client secret (optional)
    - AZURE_AD_AUDIENCE: Expected audience claim (optional)
    - AZURE_AD_ALLOWED_TENANTS: Comma-separated list of allowed tenant IDs (optional)
    - AZURE_AD_API_VERSION: API version ("v1.0" or "v2.0", default: "v2.0")
    - AZURE_AD_CLOCK_SKEW: Clock skew tolerance in seconds (optional, default: 30)
    - AZURE_AD_ENABLE_GRAPH_API: Enable Graph API enrichment ("true"/"1"/"yes")
    - AZURE_AD_GRAPH_CLIENT_ID: Client ID for Graph API (optional)
    - AZURE_AD_GRAPH_CLIENT_SECRET: Client secret for Graph API (optional)

    Args:
        tenant_id: Azure AD tenant ID (or None to read from AZURE_AD_TENANT_ID)
        client_id: OAuth client ID (or None to read from AZURE_AD_CLIENT_ID)
        client_secret: OAuth client secret (or None to read from AZURE_AD_CLIENT_SECRET)
        audience: Expected audience (or None to read from AZURE_AD_AUDIENCE)
        allowed_tenants: FrozenSet of allowed tenant IDs for multi-tenant apps.
                        Provides O(1) lookup for tenant validation.
                        Or None to read from AZURE_AD_ALLOWED_TENANTS.
        api_version: API version (or None to read from AZURE_AD_API_VERSION, default: "v2.0")
        clock_skew_seconds: Clock skew tolerance (or None for default: 30)
        key_cache: Optional cache backend for JWKS caching
        enable_graph_api: Enable Graph API for role enrichment (or None to read from env)
        graph_client_id: Client ID for Graph API (defaults to client_id)
        graph_client_secret: Client secret for Graph API
        graph_cache_ttl_seconds: TTL for Graph API role cache (default: 3600)
        custom_role_mappings: Custom directory role ID to name mappings
        role_store: Redis-backed role enrichment store for production deployments

    Returns:
        AzureADDecoder instance configured from parameters or environment

    Raises:
        AuthError: If required configuration (tenant_id, client_id) is missing
                  from both parameters and environment

    Example:
        # Create from environment variables
        decoder = create_azure_decoder()

        # Create single-tenant decoder
        decoder = create_azure_decoder(
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="11111111-1111-1111-1111-111111111111",
        )

        # Create multi-tenant with allowed tenants (O(1) lookup)
        decoder = create_azure_decoder(
            tenant_id="organizations",
            client_id="11111111-1111-1111-1111-111111111111",
            allowed_tenants=frozenset(["tenant1-guid", "tenant2-guid"]),
            audience="api://my-api",
        )

        # With Graph API role enrichment
        decoder = create_azure_decoder(
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="11111111-1111-1111-1111-111111111111",
            enable_graph_api=True,
            graph_client_secret="env:AZURE_GRAPH_CLIENT_SECRET",
        )
    """
    # Read from environment if not provided
    tenant_id = tenant_id or os.getenv("AZURE_AD_TENANT_ID")
    client_id = client_id or os.getenv("AZURE_AD_CLIENT_ID")
    if client_secret is None:
        _env_secret = os.getenv("AZURE_AD_CLIENT_SECRET")
        if _env_secret:
            client_secret = SecretStr(_env_secret)
    audience = audience or os.getenv("AZURE_AD_AUDIENCE")
    api_version = api_version or os.getenv("AZURE_AD_API_VERSION") or "v2.0"

    # Parse allowed_tenants from environment (comma-separated)
    if allowed_tenants is None:
        env_allowed_tenants = os.getenv("AZURE_AD_ALLOWED_TENANTS")
        if env_allowed_tenants:
            allowed_tenants = frozenset(
                t.strip().lower()
                for t in env_allowed_tenants.split(",")
                if t.strip()
            )

    # Parse clock_skew_seconds from environment
    if clock_skew_seconds is None:
        env_clock_skew = os.getenv("AZURE_AD_CLOCK_SKEW")
        if env_clock_skew:
            try:
                clock_skew_seconds = int(env_clock_skew)
            except ValueError:
                logger.warning(
                    f"Invalid AZURE_AD_CLOCK_SKEW value: '{env_clock_skew}', "
                    f"using default {DEFAULT_TOKEN_CLOCK_SKEW_SECONDS} seconds"
                )
                clock_skew_seconds = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
        else:
            clock_skew_seconds = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS

    # Parse Graph API configuration from environment
    if enable_graph_api is None:
        env_graph_api = os.getenv("AZURE_AD_ENABLE_GRAPH_API", "").lower()
        enable_graph_api = env_graph_api in ("true", "1", "yes")

    graph_client_id = graph_client_id or os.getenv("AZURE_AD_GRAPH_CLIENT_ID")
    if graph_client_secret is None:
        _env_graph_secret = os.getenv("AZURE_AD_GRAPH_CLIENT_SECRET")
        if _env_graph_secret:
            graph_client_secret = SecretStr(_env_graph_secret)

    # Validate required configuration
    if not tenant_id:
        error = AuthError(
            "Azure AD tenant_id is required. Provide via parameter or "
            "AZURE_AD_TENANT_ID environment variable. "
            "Format: GUID or 'common'/'organizations'/'consumers' for multi-tenant"
        )
        logger.log_error(error=error)
        raise error

    if not client_id:
        error = AuthError(
            "Azure AD client_id is required. Provide via parameter or "
            "AZURE_AD_CLIENT_ID environment variable. "
            "Format: GUID (application ID from Azure AD app registration)"
        )
        logger.log_error(error=error)
        raise error

    logger.info(
        f"Creating AzureADDecoder from factory: tenant={tenant_id}, "
        f"api_version={api_version}, "
        f"audience={audience or 'client_id'}, "
        f"allowed_tenants_count={len(allowed_tenants) if allowed_tenants else 0}, "
        f"clock_skew={clock_skew_seconds}s, "
        f"graph_api_enabled={enable_graph_api}"
    )

    return AzureADDecoder(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        allowed_tenants=allowed_tenants,
        api_version=api_version,
        clock_skew_seconds=clock_skew_seconds,
        key_cache=key_cache,
        enable_graph_api=enable_graph_api or False,
        graph_client_id=graph_client_id,
        graph_client_secret=graph_client_secret,
        graph_cache_ttl_seconds=graph_cache_ttl_seconds,
        custom_role_mappings=custom_role_mappings,
        role_store=role_store,
    )


# Alias: create_azure_ad_decoder delegates to create_azure_decoder
create_azure_ad_decoder = create_azure_decoder
