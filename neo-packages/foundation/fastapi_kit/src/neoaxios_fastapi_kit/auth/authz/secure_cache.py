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

"""Secure cache backend with HMAC-SHA256 signature verification.

This module provides secure cache functionality for permission caching.
Re-exports implementations from neoaxios-secure-cache package.

Usage:
    from neoaxios_fastapi_kit.auth.authz.secure_cache import (
        SecureCacheConfig,
        create_secure_cache,
        register_cache_config,
        get_cache_config,
    )

    # Register configuration from JSON file
    register_cache_config("/etc/myapp/cache.json")

    # Create cache from registered config
    config = get_cache_config()
    cache = create_secure_cache(config)

    await cache.set("key", value, ttl_seconds=300)
    value = await cache.get("key")

Config file example (/etc/myapp/cache.json):
    {
        "tenant_id": "my-app",
        "master_key": "env:CACHE_MASTER_KEY",
        "default_ttl_seconds": 300,
        "redis": {
            "url": "rediss://redis.internal:6379"
        }
    }
"""

from neoaxios_logging import get_telemetry

# Re-export directly from neoaxios_secure_cache - no wrapper adapters
from neoaxios_secure_cache import (
    # Configuration
    SecureCacheConfig,
    RedisCacheConfig,
    SecurityConfig,
    OptionalFeaturesConfig,
    register_cache_config,
    get_cache_config,
    get_cache_config_or_none,
    reload_cache_config,
    rollback_cache_config,
    # Security components
    SigningCacheWrapper,
    create_signing_wrapper,
    EncryptingCacheWrapper,
    create_encrypting_wrapper,
    derive_signing_key,
    derive_kek,
    # Factory
    create_secure_cache,
)

# Re-export for API completeness. SignatureVerificationError is NOT raised by
# SigningCacheWrapper - by design, signature failures return None (cache miss)
# and log a security event. This design:
# 1. Mitigates timing attacks (exceptions leak timing info; combined with
#    secrets.compare_digest() and TamperDetectionState jitter for constant-time behavior)
# 2. Enables graceful degradation via TamperDetectionState rather than exception propagation
# See errors.py docstring for the full security response protocol.
from neoaxios_fastapi_kit.auth.authz.errors import SignatureVerificationError

logger = get_telemetry(__name__)


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
    # Signing
    "SigningCacheWrapper",
    "create_signing_wrapper",
    # Encryption
    "EncryptingCacheWrapper",
    "create_encrypting_wrapper",
    # Key derivation
    "derive_signing_key",
    "derive_kek",
    # Factory
    "create_secure_cache",
    # Errors
    "SignatureVerificationError",
]
