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

"""Authorization (AuthZ) module - "What can you do?"

Provides permission resolution, access control, policies, and authorization infrastructure.

Components:
    - resolvers/: Privilege resolution implementations
    - dependencies.py: FastAPI dependencies for access control
    - policy.py: ABAC policy evaluation
    - cache.py: Permission caching
    - filters.py: Tenant query filters
    - errors.py: Authorization-specific error types

Usage:
    from neoaxios_fastapi_kit.auth.authz import (
        require_permission,
        require_role,
        require_ownership,
        PermissionDeniedError,
        PolicyDeniedError,
    )

Note: Some imports are deferred to avoid circular dependencies.
Import directly from submodules for explicit access:
    from neoaxios_fastapi_kit.auth.authz.resolvers import LocalResolver
    from neoaxios_fastapi_kit.auth.authz.dependencies import require_permission
"""

from typing import TYPE_CHECKING, Callable, List, Type, overload

# Authorization Errors - safe to import at module level
# (errors.py only imports AuthError from parent, no circular deps)
from neoaxios_fastapi_kit.auth.authz.errors import (
    PermissionDeniedError,
    PolicyDeniedError,
    TenantMismatchError,
    OwnershipRequiredError,
    ResourceNotFoundError,
    ImpersonationNotAllowedError,
    ValidationError,
    CacheSecurityError,
    SignatureVerificationError,
    DecryptionError,
    ReplayAttackError,
    CanaryMismatchError,
    KeyValidationError,
    TamperDetectionActiveError,
)

# Type hints for lazy imports (IDE support)
if TYPE_CHECKING:
    from typing import Literal

    from neoaxios_fastapi_kit.auth.authz.resolvers import (
        PrivilegeResolver as _LocalPrivilegeResolver,
        CompositeResolver as _CompositeResolver,
    )
    from neoaxios_fastapi_kit.auth.authz.dependencies import (
        get_identity as _get_identity,
        require_collaborator as _require_collaborator,
        require_ownership as _require_ownership,
        require_permission as _require_permission,
        require_policy as _require_policy,
        require_role as _require_role,
        require_tenant_access as _require_tenant_access,
    )
    from neoaxios_fastapi_kit.auth.authz.policy import (
        Policy as _Policy,
        PolicyDecision as _PolicyDecision,
        SimplePolicyEvaluator as _SimplePolicyEvaluator,
    )
    from neoaxios_fastapi_kit.auth.authz.cache import (
        CacheBackend as _CacheBackend,
        InMemoryCacheBackend as _InMemoryCacheBackend,
        RedisCacheBackend as _RedisCacheBackend,
    )
    from neoaxios_secure_cache import (
        SecureCacheBackend as _SecureCacheBackend,
    )
    from neoaxios_fastapi_kit.auth.authz.filters import (
        TenantQueryFilter as _TenantQueryFilter,
    )


# Type stubs for overloaded __getattr__ (IDE autocomplete support)
@overload
def __getattr__(name: "Literal['LocalPrivilegeResolver']") -> "Type[_LocalPrivilegeResolver]": ...
@overload
def __getattr__(name: "Literal['LocalResolver']") -> "Type[_LocalPrivilegeResolver]": ...
@overload
def __getattr__(name: "Literal['CompositeResolver']") -> "Type[_CompositeResolver]": ...
@overload
def __getattr__(name: "Literal['get_identity']") -> "Callable[..., _get_identity]": ...
@overload
def __getattr__(name: "Literal['require_collaborator']") -> "Callable[..., _require_collaborator]": ...
@overload
def __getattr__(name: "Literal['require_ownership']") -> "Callable[..., _require_ownership]": ...
@overload
def __getattr__(name: "Literal['require_permission']") -> "Callable[..., _require_permission]": ...
@overload
def __getattr__(name: "Literal['require_policy']") -> "Callable[..., _require_policy]": ...
@overload
def __getattr__(name: "Literal['require_role']") -> "Callable[..., _require_role]": ...
@overload
def __getattr__(name: "Literal['require_tenant_access']") -> "Callable[..., _require_tenant_access]": ...
@overload
def __getattr__(name: "Literal['Policy']") -> "Type[_Policy]": ...
@overload
def __getattr__(name: "Literal['PolicyDecision']") -> "Type[_PolicyDecision]": ...
@overload
def __getattr__(name: "Literal['SimplePolicyEvaluator']") -> "Type[_SimplePolicyEvaluator]": ...
@overload
def __getattr__(name: "Literal['CacheBackend']") -> "Type[_CacheBackend]": ...
@overload
def __getattr__(name: "Literal['InMemoryCacheBackend']") -> "Type[_InMemoryCacheBackend]": ...
@overload
def __getattr__(name: "Literal['RedisCacheBackend']") -> "Type[_RedisCacheBackend]": ...
@overload
def __getattr__(name: "Literal['SecureCacheBackend']") -> "Type[_SecureCacheBackend]": ...
@overload
def __getattr__(name: "Literal['TenantQueryFilter']") -> "Type[_TenantQueryFilter]": ...
@overload
def __getattr__(name: "Literal['create_tenant_filter']") -> "Callable[..., _TenantQueryFilter]": ...
@overload
def __getattr__(name: str) -> object: ...


def __getattr__(name: str):
    """Lazy import for components that may have circular dependencies."""
    # Resolvers
    if name in ("LocalPrivilegeResolver", "LocalResolver", "CompositeResolver"):
        from neoaxios_fastapi_kit.auth.authz.resolvers import PrivilegeResolver, CompositeResolver
        if name == "LocalPrivilegeResolver" or name == "LocalResolver":
            return PrivilegeResolver
        return CompositeResolver

    # Dependencies
    if name in ("get_identity", "require_collaborator", "require_ownership",
                "require_permission", "require_policy", "require_role", "require_tenant_access"):
        from neoaxios_fastapi_kit.auth.authz import dependencies
        return getattr(dependencies, name)

    # Policy
    if name in ("Policy", "PolicyDecision", "SimplePolicyEvaluator"):
        from neoaxios_fastapi_kit.auth.authz import policy
        return getattr(policy, name)

    # Cache
    if name in ("CacheBackend", "InMemoryCacheBackend", "RedisCacheBackend"):
        from neoaxios_fastapi_kit.auth.authz import cache
        return getattr(cache, name)

    # Secure Cache
    if name == "SecureCacheBackend":
        from neoaxios_secure_cache import SecureCacheBackend
        return SecureCacheBackend

    # Filters
    if name in ("TenantQueryFilter", "create_tenant_filter"):
        from neoaxios_fastapi_kit.auth.authz import filters
        return getattr(filters, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> List[str]:
    """Return list of module attributes for introspection and IDE support."""
    return __all__


__all__ = [
    # Resolvers (lazy)
    "LocalPrivilegeResolver",
    "LocalResolver",
    "CompositeResolver",
    # Dependencies (lazy)
    "get_identity",
    "require_collaborator",
    "require_ownership",
    "require_permission",
    "require_policy",
    "require_role",
    "require_tenant_access",
    # Policy (lazy)
    "Policy",
    "PolicyDecision",
    "SimplePolicyEvaluator",
    # Cache (lazy)
    "CacheBackend",
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "SecureCacheBackend",
    # Filters (lazy)
    "TenantQueryFilter",
    "create_tenant_filter",
    # Errors (eager - safe)
    "PermissionDeniedError",
    "PolicyDeniedError",
    "TenantMismatchError",
    "OwnershipRequiredError",
    "ResourceNotFoundError",
    "ImpersonationNotAllowedError",
    "ValidationError",
    "CacheSecurityError",
    "SignatureVerificationError",
    "DecryptionError",
    "ReplayAttackError",
    "CanaryMismatchError",
    "KeyValidationError",
    "TamperDetectionActiveError",
]
