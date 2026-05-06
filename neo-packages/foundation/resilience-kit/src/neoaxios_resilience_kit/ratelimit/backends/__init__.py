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

"""Rate limiting backend implementations.

Provides storage backends for rate limiting state, including
in-memory (for testing) and Redis (for production) implementations.

Public API:
    InMemoryRateLimitBackend: In-memory rate limiting for testing
    create_memory_ratelimit_backend: Factory function for in-memory backend
    RedisRateLimitBackend: Redis-backed rate limiting with namespace isolation
    create_redis_ratelimit_backend: Factory function with namespace setup
"""

from .memory import InMemoryRateLimitBackend, create_memory_ratelimit_backend
from .redis import RedisRateLimitBackend, create_redis_ratelimit_backend

__all__: list[str] = [
    "InMemoryRateLimitBackend",
    "create_memory_ratelimit_backend",
    "RedisRateLimitBackend",
    "create_redis_ratelimit_backend",
]
