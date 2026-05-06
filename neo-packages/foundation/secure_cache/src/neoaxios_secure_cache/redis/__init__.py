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

"""Redis-specific gateway implementation and client factories.

Provides the concrete Redis implementation of the Gateway protocol,
configuration dataclass, and client factory functions.

Self-registers RedisClientConfig -> RedisGateway in the gateway type
registry at import time, enabling automatic dispatch from
``initialize_gateway(RedisClientConfig(...))``.

Usage:
    from neoaxios_secure_cache.redis import RedisGateway, RedisClientConfig
    from neoaxios_secure_cache.gateway import initialize_gateway, get_gateway

    config = RedisClientConfig(url=SecretStr("redis://localhost:6379"))
    initialize_gateway(config)
    gw = get_gateway()
"""

from neoaxios_secure_cache.gateway import register_gateway_type
from neoaxios_secure_cache.redis.client import (
    RedisClientConfig,
    create_async_redis_client,
    get_async_pool_stats,
)
from neoaxios_secure_cache.redis.gateway import RedisGateway
from neoaxios_secure_cache.redis.store_base import RedisStoreBase
from neoaxios_secure_cache.redis.streams import decode_fields, stream_add

__all__ = [
    "RedisGateway",
    "RedisClientConfig",
    "RedisStoreBase",
    "create_async_redis_client",
    "decode_fields",
    "get_async_pool_stats",
    "register_gateway_type",
    "stream_add",
]

# Self-register RedisClientConfig -> RedisGateway at import time
register_gateway_type(RedisClientConfig, RedisGateway)
