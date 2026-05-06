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

"""FastAPI application configuration for authorization framework.

Provides AuthConfig dataclass and configure_auth/get_auth functions for
setting up the authorization framework on FastAPI applications.

All protocol interfaces are defined here to avoid circular imports.

Reference: docs/auth-framework-design.md Configuration section
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional

from fastapi import FastAPI

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.defaults import (
    DEFAULT_ALLOW_IMPERSONATION,
    DEFAULT_AUDIT_ALL_ACCESS,
    DEFAULT_CACHE_NEGATIVE_TTL_SECONDS,
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_IMPERSONATION_ROLES,
    DEFAULT_REQUIRE_TENANT_ISOLATION,
)

logger = get_telemetry(__name__)


# =============================================================================
# Protocol Imports
# =============================================================================

from ..protocols import (
    TokenDecoder,
    PrivilegeResolver,
    OwnershipResolver,
    AuditLogger,
    PolicyEvaluator,
    TenantQueryFilter,
)
from neoaxios_secure_cache import CacheBackend

# =============================================================================
# Configuration Class
# =============================================================================
# NOTE: Protocol definitions (AuditLogger, PolicyEvaluator, TenantQueryFilter)
# imported from protocols.py to avoid duplication.
# CacheBackend imported from neoaxios_secure_cache (top-level public API).
# =============================================================================


@dataclass
class AuthConfig:
    """Authorization framework configuration.

    Per design spec: Required resolvers must be provided, optional components
    have sensible defaults.

    Reference: docs/auth-framework-design.md Configuration section

    Usage:
        from fastapi import FastAPI
        from neoaxios_fastapi_kit.auth.config.app import configure_auth, AuthConfig

        app = FastAPI()
        config = AuthConfig(
            token_decoder=my_decoder,
            privilege_resolver=my_resolver,
            ownership_resolver=my_ownership,
            cache_ttl_seconds=600,  # Override default
        )
        configure_auth(app, config)
    """

    # Required resolvers
    token_decoder: TokenDecoder
    privilege_resolver: PrivilegeResolver
    ownership_resolver: OwnershipResolver

    # Optional components
    audit_logger: Optional[AuditLogger] = None
    tenant_filter: Optional[TenantQueryFilter] = None
    policy_evaluator: Optional[PolicyEvaluator] = None

    # Caching
    cache_backend: Optional[CacheBackend] = None
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS
    cache_negative_ttl_seconds: int = DEFAULT_CACHE_NEGATIVE_TTL_SECONDS

    # Behavior flags
    require_tenant_isolation: bool = DEFAULT_REQUIRE_TENANT_ISOLATION
    audit_all_access: bool = DEFAULT_AUDIT_ALL_ACCESS
    allow_impersonation: bool = DEFAULT_ALLOW_IMPERSONATION
    impersonation_roles: FrozenSet[str] = DEFAULT_IMPERSONATION_ROLES


# =============================================================================
# Configuration Functions
# =============================================================================


@auto_trace(logger)
def configure_auth(app: FastAPI, config: AuthConfig) -> None:
    """Configure authorization framework on FastAPI app.

    Stores config in app.state.auth_config for use by dependencies.
    Logs configuration summary for telemetry.

    Args:
        app: FastAPI application instance
        config: AuthConfig with all resolvers and settings

    Raises:
        ValueError: If config is invalid

    Usage:
        from fastapi import FastAPI
        from neoaxios_fastapi_kit.auth.config.app import configure_auth, AuthConfig

        app = FastAPI()
        configure_auth(app, AuthConfig(
            token_decoder=JWTDecoder(secret=SECRET),
            privilege_resolver=DatabaseResolver(db),
            ownership_resolver=DatabaseOwnership(db),
        ))

    Reference: docs/auth-framework-design.md Configuration section
    """
    # Validate required components
    if config.token_decoder is None:
        raise ValueError("token_decoder is required")
    if config.privilege_resolver is None:
        raise ValueError("privilege_resolver is required")
    if config.ownership_resolver is None:
        raise ValueError("ownership_resolver is required")

    # Store config in app.state
    app.state.auth_config = config

    # Log configuration summary
    logger.info(
        "Auth framework configured",
        extra={
            "token_decoder": type(config.token_decoder).__name__,
            "privilege_resolver": type(config.privilege_resolver).__name__,
            "ownership_resolver": type(config.ownership_resolver).__name__,
            "audit_logger": (
                type(config.audit_logger).__name__ if config.audit_logger else None
            ),
            "tenant_filter": (
                type(config.tenant_filter).__name__ if config.tenant_filter else None
            ),
            "policy_evaluator": (
                type(config.policy_evaluator).__name__
                if config.policy_evaluator
                else None
            ),
            "cache_backend": (
                type(config.cache_backend).__name__ if config.cache_backend else None
            ),
            "cache_ttl_seconds": config.cache_ttl_seconds,
            "cache_negative_ttl_seconds": config.cache_negative_ttl_seconds,
            "require_tenant_isolation": config.require_tenant_isolation,
            "audit_all_access": config.audit_all_access,
            "allow_impersonation": config.allow_impersonation,
            "impersonation_roles": list(config.impersonation_roles),
        },
    )


@auto_trace(logger)
def get_auth(app: FastAPI) -> AuthConfig:
    """Get authorization configuration from FastAPI app.

    Retrieves the AuthConfig stored in app.state by configure_auth().
    Use this to access auth components in route handlers or other
    application code.

    Args:
        app: FastAPI application instance

    Returns:
        AuthConfig instance

    Raises:
        ValueError: If auth has not been configured on app

    Usage:
        from fastapi import Request
        from neoaxios_fastapi_kit.auth.config.app import get_auth

        @app.get("/info")
        async def get_info(request: Request):
            config = get_auth(request.app)
            return {"cache_ttl": config.cache_ttl_seconds}

    Reference: docs/auth-framework-design.md Configuration section
    """
    if not hasattr(app.state, "auth_config"):
        raise ValueError(
            "Auth not configured. Call configure_auth(app, config) first."
        )

    return app.state.auth_config
