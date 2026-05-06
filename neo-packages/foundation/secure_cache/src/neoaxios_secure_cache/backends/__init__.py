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

"""Cache backend implementations.

This module provides concrete implementations of the CacheBackend protocol:
- InMemoryCacheBackend: Thread-safe in-memory cache for development/testing
- RedisCacheBackend: Redis-backed distributed cache for production

All backends implement the CacheBackend protocol with async interfaces.
"""

from neoaxios_secure_cache.backends.memory import InMemoryCacheBackend
from neoaxios_secure_cache.backends.redis import RedisCacheBackend, create_redis_backend

__all__ = [
    "InMemoryCacheBackend",
    "RedisCacheBackend",
    "create_redis_backend",
]
