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

"""Cache backend implementations for permission caching.

This module provides cache backends for authorization permission caching.
Re-exports implementations from neoaxios-secure-cache package.

Usage:
    from neoaxios_fastapi_kit.auth.authz.cache import (
        InMemoryCacheBackend,
        RedisCacheBackend,
        create_redis_backend,
        AuthCacheHelper,
    )
    from neoaxios_fastapi_kit.auth.cache_keys import permissions_key, user_prefix, tenant_prefix
    from neoaxios_secure_cache import CacheNamespace

    # Create namespace
    ns = CacheNamespace(
        org="neo",
        env="prod",
        service="auth-api",
        app="gateway",
    )

    # Redis cache (required for production)
    cache = create_redis_backend(
        default_ttl_seconds=300,
    )

    # Store permissions using namespace-aware key
    key = permissions_key(ns, tenant_id, user_id)
    await cache.set(key, permissions, ttl_seconds=300)
    permissions = await cache.get(key)

    # Invalidate by prefix using namespace-aware helpers
    helper = AuthCacheHelper(cache=cache, namespace=ns)
    await helper.invalidate_user(tenant_id, user_id)
    await helper.invalidate_tenant(tenant_id)

    Note:
        When using SigningCacheWrapper, invalidate_by_prefix requires prefixes
        to end with ":" and will raise ValueError otherwise.
"""

from typing import TYPE_CHECKING

from neoaxios_logging import auto_trace, get_telemetry

# Re-export directly from neoaxios_secure_cache - no wrapper adapters
from neoaxios_secure_cache import InMemoryCacheBackend
from neoaxios_secure_cache.backends.redis import RedisCacheBackend, create_redis_backend
from neoaxios_secure_cache import CacheBackend

from neoaxios_fastapi_kit.auth.defaults import DEFAULT_CACHE_TTL_SECONDS
from neoaxios_fastapi_kit.auth.cache_keys import (
    user_prefix,
    tenant_prefix,
)

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace

logger = get_telemetry(__name__)


# =============================================================================
# AuthCacheHelper - Domain-Specific Cache Invalidation
# =============================================================================


class AuthCacheHelper:
    """Helper for auth-domain cache invalidation operations.

    Composes namespace-aware key prefix functions with CacheBackend.invalidate_by_prefix
    to provide convenient invalidation methods for user and tenant scopes.

    Args:
        cache: Cache backend implementation (required - fail fast on misconfiguration)
        namespace: Cache namespace for hierarchical key prefixing (required)

    Usage:
        from neoaxios_fastapi_kit.auth.authz.cache import AuthCacheHelper
        from neoaxios_secure_cache.backends.redis import RedisCacheBackend
        from neoaxios_secure_cache import CacheNamespace

        ns = CacheNamespace(
            org="neo",
            env="prod",
            service="auth-api",
            app="gateway",
        )
        backend = RedisCacheBackend()
        helper = AuthCacheHelper(cache=backend, namespace=ns)

        # Invalidate all cached data for a specific user
        count = await helper.invalidate_user("tenant-123", "user-456")

        # Invalidate all cached data for an entire tenant
        count = await helper.invalidate_tenant("tenant-123")
    """

    def __init__(self, cache: CacheBackend, namespace: "CacheNamespace") -> None:
        self._cache = cache
        self._namespace = namespace

    @auto_trace(logger)
    async def invalidate_user(self, tenant_id: str, user_id: str) -> int:
        """Invalidate all cached data for a specific user.

        Uses namespace-aware user_prefix from cache_keys module with
        cache.invalidate_by_prefix to remove all cache entries scoped to the user.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Returns:
            Number of cache entries invalidated

        Raises:
            ValueError: If prefix does not end with ":" and SigningCacheWrapper is used
            ConnectionError: If cache backend is unavailable
        """
        prefix = user_prefix(self._namespace, tenant_id, user_id)
        count = await self._cache.invalidate_by_prefix(prefix)
        logger.record_metric("auth_cache.invalidate_user.count", count)
        return count

    @auto_trace(logger)
    async def invalidate_tenant(self, tenant_id: str) -> int:
        """Invalidate all cached data for an entire tenant.

        Uses namespace-aware tenant_prefix from cache_keys module with
        cache.invalidate_by_prefix to remove all cache entries scoped to the tenant.
        This includes all users' permissions, roles, graph tokens, and any other
        tenant-scoped data.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Number of cache entries invalidated

        Raises:
            ValueError: If prefix does not end with ":" and SigningCacheWrapper is used
            ConnectionError: If cache backend is unavailable
        """
        prefix = tenant_prefix(self._namespace, tenant_id)
        count = await self._cache.invalidate_by_prefix(prefix)
        logger.record_metric("auth_cache.invalidate_tenant.count", count)
        return count


__all__ = [
    "AuthCacheHelper",
    "CacheBackend",
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "create_redis_backend",
    "DEFAULT_CACHE_TTL_SECONDS",
]
