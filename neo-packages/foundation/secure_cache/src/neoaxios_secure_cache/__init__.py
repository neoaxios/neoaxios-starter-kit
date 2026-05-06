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

"""neoaxios-secure-cache: Secure caching infrastructure with defense-in-depth security.

This package provides cache backends (in-memory, Redis) with comprehensive
security features including HMAC signing, AES-256-GCM encryption, per-tenant
key derivation, and integrity monitoring.

Public API:
    Configuration:
        - SecureCacheConfig: Main configuration schema
        - register_cache_config: Register configuration from JSON file
        - get_cache_config: Get registered configuration

    Protocols:
        - CacheBackend: Protocol all backends/wrappers must implement
        - SecureCacheBackend: Secure cache protocol with encryption
        - KeyManager: Key management protocol
        - CryptoProvider: Cryptographic operations protocol

    Backends:
        - InMemoryCacheBackend (Deprecated): Thread-safe in-memory cache
        - RedisCacheBackend: Redis-backed distributed cache

    Security Wrappers:
        - SigningCacheWrapper: HMAC-SHA256 integrity verification
        - EncryptingCacheWrapper: AES-256-GCM encryption with per-tenant keys
        - CanaryMonitor: Background integrity checking
        - TamperDetectionState: Tamper detection state tracking

    Key Management:
        - KeyDerivation: HKDF-based key derivation
        - TenantKeyCache: LRU cache for per-tenant derived keys
        - SequenceTracker: Replay protection via sequence numbers

    Sensitive Permission Detection:
        - is_sensitive_permission: Check if permission should bypass cache
        - register_sensitive_pattern: Register additional sensitive patterns

    Factories (single instantiation points):
        - create_secure_cache: Main factory for fully-configured cache
        - create_redis_backend: Factory for Redis backend
        - create_signing_wrapper: Factory for signing wrapper
        - create_encrypting_wrapper: Factory for encryption wrapper

    Redis Client Factory:
        - RedisClientConfig: Configuration dataclass for Redis client creation
        - create_async_redis_client: Factory for async Redis clients

    Gateway Protocol and Accessors:
        - Gateway: Abstract protocol for connection gateways
        - RedisGateway: Redis implementation of Gateway protocol
        - initialize_gateway: Initialize module-level gateway
        - get_gateway: Get the initialized gateway
        - is_gateway_initialized: Check if gateway is initialized
        - reset_gateway: Reset gateway (testing only)
        - register_gateway_type: Register a config->gateway mapping

Usage:
    from neoaxios_secure_cache import create_secure_cache
    from neoaxios_secure_cache.config import register_cache_config, get_cache_config

    # Register configuration from JSON file
    register_cache_config("/etc/myapp/cache.json")

    # Get configuration and create cache
    config = get_cache_config()
    cache = create_secure_cache(config)

    await cache.set("key", {"data": "value"}, ttl_seconds=300)
    value = await cache.get("key")

Config file example (/etc/myapp/cache.json):
    {
        "tenant_id": "tenant-123",
        "master_key": "env:CACHE_MASTER_KEY",
        "default_ttl_seconds": 300,
        "redis": {
            "url": "rediss://redis.internal:6379",
            "pool_size": 500
        },
        "features": {
            "enable_canary": true,
            "enable_metrics": true
        }
    }

    Note: pool_size here is the RedisCacheConfig schema default (500) for config
    files. The RedisClientConfig gateway default is 10 — the gateway divides the
    total pool budget by worker count.
"""

# Configuration
from neoaxios_secure_cache.config import (
    SecureCacheConfig,
    RedisCacheConfig,
    SecurityConfig,
    OptionalFeaturesConfig,
    register_cache_config,
    get_cache_config,
    get_cache_config_or_none,
    reload_cache_config,
    rollback_cache_config,
    has_cache_config_rollback,
)

# Protocols
from neoaxios_secure_cache.protocols import (
    CacheBackend,
    SecureCacheBackend,
    KeyManager,
    CryptoProvider,
)

# Backends
from neoaxios_secure_cache.backends.memory import InMemoryCacheBackend
from neoaxios_secure_cache.backends.redis import RedisCacheBackend, create_redis_backend

# Security Wrappers
from neoaxios_secure_cache.security.signing import SigningCacheWrapper, create_signing_wrapper
from neoaxios_secure_cache.security.encryption import EncryptingCacheWrapper, create_encrypting_wrapper
from neoaxios_secure_cache.security.keys import (
    TenantKeyCache,
    create_tenant_key_cache,
    derive_kek,
    derive_signing_key,
    derive_tenant_key,
)
from neoaxios_secure_cache.security.sequence import SequenceTracker, create_sequence_tracker
from neoaxios_secure_cache.security.sensitive import is_sensitive_permission, register_sensitive_pattern
from neoaxios_secure_cache.security.canary import CanaryMonitor, create_canary_monitor
from neoaxios_secure_cache.security.tamper_detection import TamperDetectionState, create_tamper_detection_state

# Factories
from neoaxios_secure_cache.factories import create_secure_cache

# Health
from neoaxios_secure_cache.health import get_cache_health

# Namespace
from neoaxios_secure_cache.namespace import CacheNamespace, KeyTier

# Redis Client Factory
from neoaxios_secure_cache.redis.client import (
    RedisClientConfig,
    create_async_redis_client,
)

# Gateway Protocol and Accessors
from neoaxios_secure_cache.gateway import (
    Gateway,
    initialize_gateway,
    get_gateway,
    is_gateway_initialized,
    reset_gateway,
    register_gateway_type,
)

# Redis Gateway Implementation
from neoaxios_secure_cache.redis import RedisGateway

# Serialization
from neoaxios_secure_cache.serialization import (
    Serializer,
    JsonSerializer,
    MsgpackSerializer,
    SmartSerializer,
)

# Key Registry
from neoaxios_secure_cache.key_registry import (
    CacheKeySchema,
    CacheKeyRegistry,
    load_cache_key_registry,
    get_cache_key_schema,
    list_cache_keys,
    list_cache_keys_by_component,
)

__all__ = [
    # Configuration
    "SecureCacheConfig",
    "RedisCacheConfig",
    "SecurityConfig",
    "OptionalFeaturesConfig",
    "register_cache_config",
    "get_cache_config",
    "get_cache_config_or_none",
    "reload_cache_config",
    "rollback_cache_config",
    "has_cache_config_rollback",
    # Protocols
    "CacheBackend",
    "SecureCacheBackend",
    "KeyManager",
    "CryptoProvider",
    # Backends
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "create_redis_backend",
    # Security Wrappers
    "SigningCacheWrapper",
    "create_signing_wrapper",
    "EncryptingCacheWrapper",
    "create_encrypting_wrapper",
    "TenantKeyCache",
    "create_tenant_key_cache",
    "derive_signing_key",
    "derive_kek",
    "derive_tenant_key",
    "SequenceTracker",
    "create_sequence_tracker",
    "is_sensitive_permission",
    "register_sensitive_pattern",
    "CanaryMonitor",
    "create_canary_monitor",
    "TamperDetectionState",
    "create_tamper_detection_state",
    # Factories
    "create_secure_cache",
    # Health
    "get_cache_health",
    # Namespace
    "CacheNamespace",
    "KeyTier",
    # Redis Client Factory
    "RedisClientConfig",
    "create_async_redis_client",
    # Gateway
    "Gateway",
    "RedisGateway",
    "initialize_gateway",
    "get_gateway",
    "is_gateway_initialized",
    "reset_gateway",
    "register_gateway_type",
    # Serialization
    "Serializer",
    "JsonSerializer",
    "MsgpackSerializer",
    "SmartSerializer",
    # Key Registry
    "CacheKeySchema",
    "CacheKeyRegistry",
    "load_cache_key_registry",
    "get_cache_key_schema",
    "list_cache_keys",
    "list_cache_keys_by_component",
]

__version__ = "0.2.1"
