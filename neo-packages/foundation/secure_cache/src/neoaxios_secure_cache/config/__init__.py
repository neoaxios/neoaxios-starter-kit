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

"""secure_cache configuration module.

Provides configuration schema, loaders, and registry integration for secure_cache
using the secure_config framework.

Example:
    ```python
    from neoaxios_secure_cache.config import register_cache_config, get_cache_config

    # Register configuration from JSON file
    register_cache_config("/etc/myapp/cache.json")

    # Access configuration anywhere
    config = get_cache_config()

    # Create cache from config
    from neoaxios_secure_cache import create_secure_cache
    cache = create_secure_cache(config)
    ```

Config file example (`/etc/myapp/cache.json`):
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

from neoaxios_secure_cache.config.loaders import (
    COMPONENT_NAME,
    get_cache_config,
    get_cache_config_or_none,
    has_cache_config_rollback,
    register_cache_config,
    reload_cache_config,
    rollback_cache_config,
)
from neoaxios_secure_cache.config.schemas import (
    OptionalFeaturesConfig,
    RedisCacheConfig,
    SecureCacheConfig,
    SecurityConfig,
)

__all__ = [
    # Schemas
    "SecureCacheConfig",
    "RedisCacheConfig",
    "SecurityConfig",
    "OptionalFeaturesConfig",
    # Registry API
    "COMPONENT_NAME",
    "register_cache_config",
    "get_cache_config",
    "get_cache_config_or_none",
    "reload_cache_config",
    "rollback_cache_config",
    "has_cache_config_rollback",
]
