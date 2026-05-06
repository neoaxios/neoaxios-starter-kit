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

"""Auth framework for FastAPI services.

Provides standardized authentication (AuthN) and authorization (AuthZ) with support for:
- Token decoding and identity verification (authn/)
- Permission resolution and access control (authz/)
- RBAC and ABAC policies
- Multi-tenant isolation
- Audit logging

Module Structure:
    auth/
    ├── authn/          # Authentication - "Who are you?"
    │   ├── decoders/   # Token decoder implementations
    │   └── errors.py   # Token/auth errors
    ├── authz/          # Authorization - "What can you do?"
    │   ├── resolvers/  # Privilege resolution
    │   ├── dependencies.py
    │   ├── policy.py
    │   ├── cache.py
    │   └── errors.py   # Permission/access errors
    ├── context.py      # IdentityContext (shared)
    ├── audit.py        # Audit logging (shared)
    └── config/         # Configuration (shared)

Usage:
    from neoaxios_fastapi_kit.auth import (
        configure_auth,
        get_auth,
        AuthConfig,
        IdentityContext,
        get_identity,
        require_permission,
        require_ownership,
    )

    # Or import from specific modules:
    from neoaxios_fastapi_kit.auth.authn import JWTDecoder, TokenExpiredError
    from neoaxios_fastapi_kit.auth.authz import require_permission, PermissionDeniedError
"""

# =============================================================================
# Configuration Defaults (all overridable)
# =============================================================================

from neoaxios_fastapi_kit.auth.defaults import (
    DEFAULT_ALLOW_IMPERSONATION,
    DEFAULT_AUDIT_ALL_ACCESS,
    DEFAULT_CACHE_NEGATIVE_TTL_SECONDS,
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_IMPERSONATION_ROLES,
    DEFAULT_REQUIRE_TENANT_ISOLATION,
    DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    DEFAULT_TOKEN_HEADER,
    DEFAULT_TOKEN_PREFIX,
)

# =============================================================================
# Shared Components
# =============================================================================

# Core identity context (bridge between authn and authz)
from neoaxios_fastapi_kit.auth.context import IdentityContext

# Protocols (runtime-checkable interfaces)
from neoaxios_fastapi_kit.auth.protocols import (
    PrivilegeResolver,
    OwnershipResolver,
    TokenDecoder,
    PolicyEvaluator,
    AuditLogger as AuditLoggerProtocol,
    TenantQueryFilter as TenantQueryFilterProtocol,
)

# Validators
from neoaxios_fastapi_kit.auth.validators import (
    check_path_traversal,
    validate_permission,
    validate_resource_id,
    validate_role,
    validate_uuid,
)

# Audit logging
from neoaxios_fastapi_kit.auth.audit import (
    AuditBackend,
    AuditEntry,
    AuditLogger,
    InMemoryAuditBackend,
)

# Configuration
from neoaxios_fastapi_kit.auth.config import (
    DecoderConfig,
    AuthMode,
    DevJWTConfig,
    ALLOWED_DEV_ENVIRONMENTS,
)
from neoaxios_fastapi_kit.auth.config.app import (
    AuthConfig,
    configure_auth,
    get_auth,
)

# =============================================================================
# Authentication (AuthN) - "Who are you?"
# =============================================================================

# Token decoders
from neoaxios_fastapi_kit.auth.authn.decoders import (
    AnonymousDecoder,
    BaseDecoder,
    BearerTokenDecoder,
    JWTDecoder,
    OIDCDecoder,
    create_oidc_decoder,
    DevJWTDecoder,
    create_dev_jwt_decoder,
    MultiProviderTokenDecoder,
    DEFAULT_ISSUER_PATTERNS,
)

# AuthN errors (also available from neoaxios_fastapi_kit.auth.errors for backwards compat)
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    TokenExpiredError,
    TokenRevokedError,
    ProviderNotConfiguredError,
    RateLimitExceededError,
    SecurityError,
)

# =============================================================================
# Middleware
# =============================================================================

# Auth middleware for request pipeline
from neoaxios_fastapi_kit.auth.middleware import (
    AuthMiddleware,
    ReadOnlyIdentityWrapper,
    ALLOWED_SKIP_PATHS,
    ALLOWED_SKIP_PREFIXES,
    DEFAULT_SKIP_PATHS,
    DEFAULT_SKIP_PREFIXES,
)

# =============================================================================
# Authorization (AuthZ) - "What can you do?"
# =============================================================================

# Resolvers
from neoaxios_fastapi_kit.auth.authz.resolvers import (
    LocalResolver,
    CompositeResolver,
)
from neoaxios_fastapi_kit.auth.authz.resolvers.composite import (
    all_resolvers_selector,
    provider_based_selector,
)

# FastAPI dependencies
from neoaxios_fastapi_kit.auth.authz.dependencies import (
    get_identity,
    require_collaborator,
    require_ownership,
    require_permission,
    require_policy,
    require_role,
    require_tenant_access,
)

# Policy evaluation
from neoaxios_fastapi_kit.auth.authz.policy import (
    Policy,
    PolicyDecision,
    SimplePolicyEvaluator,
)

# Cache backend
from neoaxios_fastapi_kit.auth.authz.cache import (
    CacheBackend,
    InMemoryCacheBackend,
    RedisCacheBackend,
)

# Cache key builders (namespace-aware)
from neoaxios_fastapi_kit.auth.cache_keys import (
    graph_token_key,
    jwks_key,
    permissions_key,
    role_enrichment_key,
    tenant_prefix,
    user_prefix,
)

# Tenant filters
from neoaxios_fastapi_kit.auth.authz.filters import (
    TenantQueryFilter,
    create_tenant_filter,
)

# AuthZ errors (also available from neoaxios_fastapi_kit.auth.errors for backwards compat)
from neoaxios_fastapi_kit.auth.authz.errors import (
    PermissionDeniedError,
    PolicyDeniedError,
    TenantMismatchError,
    OwnershipRequiredError,
    ResourceNotFoundError,
    ImpersonationNotAllowedError,
    ValidationError,
)

# Base error class
from neoaxios_fastapi_kit.auth.errors import AuthError

# Exception handlers
from neoaxios_fastapi_kit.auth.exception_handlers import register_auth_exception_handlers

# =============================================================================
# Inter-Service HMAC Signing
# =============================================================================

# HMAC-SHA256 signer + verifier shared by every Neo service-to-service call
# that cannot yet rely on mTLS.  Previously duplicated in identity,
# service; consolidated here so a future HMAC-format
# change only needs to update one site.
from neoaxios_fastapi_kit.auth.inter_service import (
    NONCE_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    SignatureExpiredError,
    SignatureInvalidError,
    canonical_message,
    canonical_path_with_sorted_query,
    generate_nonce,
    sign_request,
    verify_request,
    verify_signed_request_or_raise,
)

__all__ = [
    # ==========================================================================
    # Defaults
    # ==========================================================================
    "DEFAULT_ALLOW_IMPERSONATION",
    "DEFAULT_AUDIT_ALL_ACCESS",
    "DEFAULT_CACHE_NEGATIVE_TTL_SECONDS",
    "DEFAULT_CACHE_TTL_SECONDS",
    "DEFAULT_IMPERSONATION_ROLES",
    "DEFAULT_REQUIRE_TENANT_ISOLATION",
    "DEFAULT_TOKEN_CLOCK_SKEW_SECONDS",
    "DEFAULT_TOKEN_HEADER",
    "DEFAULT_TOKEN_PREFIX",
    # ==========================================================================
    # Shared
    # ==========================================================================
    "IdentityContext",
    # Protocols
    "PrivilegeResolver",
    "OwnershipResolver",
    "TokenDecoder",
    "PolicyEvaluator",
    "AuditLoggerProtocol",
    "TenantQueryFilterProtocol",
    # Validators
    "check_path_traversal",
    "validate_permission",
    "validate_resource_id",
    "validate_role",
    "validate_uuid",
    # Audit
    "AuditBackend",
    "AuditEntry",
    "AuditLogger",
    "InMemoryAuditBackend",
    # Configuration
    "AuthConfig",
    "DecoderConfig",
    "AuthMode",
    "DevJWTConfig",
    "ALLOWED_DEV_ENVIRONMENTS",
    "configure_auth",
    "get_auth",
    # ==========================================================================
    # Authentication (AuthN)
    # ==========================================================================
    "AnonymousDecoder",
    "BaseDecoder",
    "BearerTokenDecoder",
    "JWTDecoder",
    "OIDCDecoder",
    "create_oidc_decoder",
    "DevJWTDecoder",
    "create_dev_jwt_decoder",
    "MultiProviderTokenDecoder",
    "DEFAULT_ISSUER_PATTERNS",
    # AuthN Errors
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenRevokedError",
    "ProviderNotConfiguredError",
    "RateLimitExceededError",
    "SecurityError",
    # ==========================================================================
    # Middleware
    # ==========================================================================
    "AuthMiddleware",
    "ReadOnlyIdentityWrapper",
    "ALLOWED_SKIP_PATHS",
    "ALLOWED_SKIP_PREFIXES",
    "DEFAULT_SKIP_PATHS",
    "DEFAULT_SKIP_PREFIXES",
    # ==========================================================================
    # Authorization (AuthZ)
    # ==========================================================================
    # Resolvers
    "LocalResolver",
    "CompositeResolver",
    "all_resolvers_selector",
    "provider_based_selector",
    # Dependencies
    "get_identity",
    "require_collaborator",
    "require_ownership",
    "require_permission",
    "require_policy",
    "require_role",
    "require_tenant_access",
    # Policy
    "Policy",
    "PolicyDecision",
    "SimplePolicyEvaluator",
    # Cache
    "CacheBackend",
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    # Cache key builders (namespace-aware)
    "graph_token_key",
    "jwks_key",
    "permissions_key",
    "role_enrichment_key",
    "tenant_prefix",
    "user_prefix",
    # Filters
    "TenantQueryFilter",
    "create_tenant_filter",
    # AuthZ Errors
    "PermissionDeniedError",
    "PolicyDeniedError",
    "TenantMismatchError",
    "OwnershipRequiredError",
    "ResourceNotFoundError",
    "ImpersonationNotAllowedError",
    "ValidationError",
    # Base Error
    "AuthError",
    # ==========================================================================
    # Exception Handlers
    # ==========================================================================
    "register_auth_exception_handlers",
    # ==========================================================================
    # Inter-Service HMAC Signing
    # ==========================================================================
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "NONCE_HEADER",
    "SignatureInvalidError",
    "SignatureExpiredError",
    "canonical_message",
    "canonical_path_with_sorted_query",
    "generate_nonce",
    "sign_request",
    "verify_request",
    "verify_signed_request_or_raise",
]
