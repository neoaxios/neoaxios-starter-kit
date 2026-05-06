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

"""Configuration schemas for secure_cache.

Defines Pydantic schemas for secure_cache configuration using secure_config's
SecureSchema base class for secret field protection and immutability.

All secret fields (master_key) use SecretStr for:
- Automatic masking in logs/repr
- Explicit .get_secret_value() for access
- Support for env:/file:// resolution

Example:
    ```python
    from neoaxios_secure_cache.config import SecureCacheConfig

    # Load from dict (for testing)
    config = SecureCacheConfig(
        tenant_id="tenant-123",
        master_key="env:CACHE_MASTER_KEY",
        default_ttl_seconds=300,
    )

    # Access secret
    key_ref = config.master_key.get_secret_value()  # "env:CACHE_MASTER_KEY"
    ```
"""

from typing import Optional

from pydantic import field_validator
from neoaxios_secure_config import Field, SecretStr, SecureSchema

from ..defaults import (
    CACHE_TTL_SHORT,
    REDIS_POOL_SIZE_CACHE,
    REDIS_POOL_WAIT_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
)


class RedisCacheConfig(SecureSchema):
    """Redis backend configuration.

    Attributes:
        url: Redis connection URL (redis:// or rediss://).
             Uses SecretStr because URLs may contain passwords
             (e.g., rediss://user:password@host:6379).
        pool_size: Connection pool size (1-10000)
        socket_timeout: Socket timeout in seconds (0.1-60.0)
        pool_wait_timeout: How long to wait for a free connection from
            BlockingConnectionPool (0.0-300.0 seconds). Independent from
            socket_timeout which controls network I/O per command.
    """

    url: SecretStr = Field(description="Redis connection URL (redis:// or rediss://)")
    pool_size: int = Field(default=REDIS_POOL_SIZE_CACHE, ge=1, le=10000, description="Connection pool size")
    socket_timeout: float = Field(
        default=REDIS_SOCKET_TIMEOUT, ge=0.1, le=60.0, description="Socket timeout in seconds"
    )
    pool_wait_timeout: float = Field(
        default=REDIS_POOL_WAIT_TIMEOUT, ge=0.0, le=300.0, description="Pool connection wait timeout in seconds"
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: SecretStr) -> SecretStr:
        """Validate Redis URL format."""
        url_value = v.get_secret_value()
        if not url_value.startswith(("redis://", "rediss://")):
            raise ValueError("Redis URL must start with redis:// or rediss://")
        return v


class SecurityConfig(SecureSchema):
    """Security-related configuration.

    Attributes:
        validate_production_key_source: If True, reject keys from environment variables
        enable_memory_protection: If True, call prctl(PR_SET_DUMPABLE, 0) on Linux
    """

    validate_production_key_source: bool = Field(
        default=True,
        description="Reject master keys sourced from environment variables",
    )
    enable_memory_protection: bool = Field(
        default=True,
        description="Disable core dumps to prevent key leakage (Linux only)",
    )


class OptionalFeaturesConfig(SecureSchema):
    """Optional feature configuration.

    Attributes:
        enable_canary: Enable canary monitoring (requires Redis)
        enable_sequence_tracking: Enable replay protection via sequence numbers (requires Redis)
        enable_metrics: Enable Prometheus metrics
    """

    enable_canary: bool = Field(
        default=False,
        description="Enable canary monitoring (requires Redis backend)",
    )
    enable_sequence_tracking: bool = Field(
        default=False,
        description="Enable replay protection via sequence numbers (requires Redis backend)",
    )
    enable_metrics: bool = Field(
        default=False,
        description="Enable Prometheus metrics",
    )


class SecureCacheConfig(SecureSchema):
    """Main secure cache configuration.

    Inherits from SecureSchema for:
    - Frozen (immutable) models
    - to_safe_dict() for safe logging
    - SecretStr automatic masking

    The master_key field supports env:/file:// resolution:
    - "env:CACHE_MASTER_KEY" - Read from environment variable
    - "file:///run/secrets/cache-key" - Read from file
    - Direct hex-encoded 32-byte value

    Attributes:
        tenant_id: Tenant identifier for multi-tenancy isolation
        master_key: 32-byte master key (env: or file:// reference, or hex-encoded)
        default_ttl_seconds: Default cache TTL in seconds (1-86400)
        redis: Redis backend configuration (None = use in-memory backend)
            If redis is configured, create_secure_cache does not fall back to
            the in-memory backend.
        security: Security-related configuration
        features: Optional feature configuration

    Example JSON config:
        ```json
        {
            "tenant_id": "tenant-123",
            "master_key": "env:CACHE_MASTER_KEY",
            "default_ttl_seconds": 300,
            "redis": {
                "url": "rediss://redis.internal:6379",
                "pool_size": 500,
                "socket_timeout": 5.0,
                "pool_wait_timeout": 20.0
            },
            "security": {
                "validate_production_key_source": true,
                "enable_memory_protection": true
            },
            "features": {
                "enable_canary": true,
                "enable_sequence_tracking": true,
                "enable_metrics": true
            }
        }
        ```
    """

    # Required fields
    tenant_id: str = Field(description="Tenant identifier for multi-tenancy isolation")
    master_key: SecretStr = Field(
        description="32-byte master key (env: or file:// reference, or hex-encoded)",
        json_schema_extra={"refreshable": True},  # Supports key rotation
    )

    # Optional with defaults
    default_ttl_seconds: int = Field(
        default=CACHE_TTL_SHORT,
        ge=1,
        le=86400,
        description="Default cache TTL in seconds",
        json_schema_extra={"refreshable": True},
    )

    # Nested configs
    redis: Optional[RedisCacheConfig] = Field(
        default=None,
        description="Redis backend configuration (None = use in-memory backend)",
        json_schema_extra={"refreshable": True},
    )
    security: SecurityConfig = Field(
        default_factory=SecurityConfig,
        description="Security-related configuration",
    )
    features: OptionalFeaturesConfig = Field(
        default_factory=OptionalFeaturesConfig,
        description="Optional feature configuration",
        json_schema_extra={"refreshable": True},
    )

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant_id is non-empty."""
        if not v or not v.strip():
            raise ValueError("tenant_id cannot be empty")
        return v.strip()

    @field_validator("master_key")
    @classmethod
    def validate_master_key_format(cls, v: SecretStr) -> SecretStr:
        """Validate master_key format.

        Accepts:
        - env:VAR_NAME - Environment variable reference
        - file:///path - File path reference
        - Hex-encoded 32-byte value (64 hex characters)
        """
        value = v.get_secret_value()

        # References are validated at resolution time
        if value.startswith("env:") or value.startswith("file://"):
            return v

        # Direct value must be hex-encoded 32 bytes
        try:
            key_bytes = bytes.fromhex(value)
            if len(key_bytes) != 32:
                raise ValueError(
                    f"Master key must be exactly 32 bytes, got {len(key_bytes)}"
                )
        except ValueError as e:
            if "non-hexadecimal" in str(e).lower():
                raise ValueError(
                    "Master key must be env:, file://, or hex-encoded 32 bytes"
                ) from e
            raise

        return v
