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

"""Cache configuration models for auth subsystem.

Provides Pydantic BaseSettings models for configuring cache backends
with validation and environment variable support.

Usage:
    from neoaxios_fastapi_kit.auth.namespace_config import NamespacedCacheConfig
    from neoaxios_secure_cache.backends.redis import create_redis_backend

    # Load from environment variables
    config = NamespacedCacheConfig()

    # Create namespace and backend from config
    namespace = config.to_namespace()
    backend = create_redis_backend(
        default_ttl_seconds=config.default_ttl_seconds,
    )

Environment Variables:
    - NEO_CACHE_ORG: Organization identifier for namespace
    - NEO_CACHE_DIVISION: Division within organization (optional)
    - NEO_CACHE_ENV: Environment (development, staging, production)
    - NEO_CACHE_SERVICE: Service name for namespace
    - NEO_CACHE_APP: Application name for namespace
    - NEO_CACHE_VERSION: Namespace version (default: v1)
    - NEO_CACHE_DEFAULT_TTL: Default TTL in seconds (default: 300)
    - NEO_ENV: Environment name for production detection
"""

import os

from pydantic import Field
from pydantic_settings import BaseSettings
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class NamespacedCacheConfig(BaseSettings):
    """Cache configuration with Pydantic validation.

    Loads cache configuration from environment variables with prefix NEO_CACHE_.

    Attributes:
        org: Organization identifier for namespace
        env: Environment name (development, staging, production)
        service: Service name for namespace
        app: Application name for namespace
        version: Namespace version (default: v1)
        default_ttl_seconds: Default cache TTL in seconds

    Usage:
        # From environment
        config = NamespacedCacheConfig()

        # Explicit values
        config = NamespacedCacheConfig(
            org="neo",
            env="production",
            service="auth-api",
            app="gateway",
        )

        # Create namespace
        namespace = config.to_namespace()
    """

    org: str = Field(
        default="neo",
        description="Organization identifier for namespace",
        min_length=1,
    )

    env: str = Field(
        default="development",
        description="Environment name (development, staging, production)",
    )

    service: str = Field(
        default="neoaxios-fastapi-kit",
        description="Service name for namespace",
        min_length=1,
    )

    app: str = Field(
        default="default",
        description="Application name for namespace",
        min_length=1,
    )

    version: str = Field(
        default="v1",
        description="Namespace version",
    )

    division: str = Field(
        default="",
        description="Division within organization (optional, omitted from prefix when empty)",
    )

    default_ttl_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description="Default cache TTL in seconds",
    )

    model_config = {
        "env_prefix": "NEO_CACHE_",
        "case_sensitive": False,
        "extra": "ignore",
    }

    @auto_trace(logger)
    def to_namespace(self) -> "CacheNamespace":  # noqa: F821 — deferred import in body
        """Create CacheNamespace from configuration.

        Returns:
            CacheNamespace instance with values from this config

        Example:
            config = NamespacedCacheConfig(
                org="neo",
                env="prod",
                service="auth-api",
                app="gateway",
            )
            namespace = config.to_namespace()
            # namespace.base() = "org:neo:env:prod:svc:auth-api:app:gateway:v1"
        """
        from neoaxios_secure_cache import CacheNamespace

        return CacheNamespace(
            org=self.org,
            env=self.env,
            service=self.service,
            app=self.app,
            version=self.version,
            division=self.division,
        )

    @auto_trace(logger)
    def is_production(self) -> bool:
        """Check if configuration indicates production environment.

        Returns:
            True if env is production/prod/prd or NEO_ENV indicates production
        """
        neo_env = os.getenv("NEO_ENV", "").lower()
        return (
            self.env.lower() in ("production", "prod", "prd")
            or neo_env in ("production", "prod", "prd")
        )



__all__ = [
    "NamespacedCacheConfig",
]
