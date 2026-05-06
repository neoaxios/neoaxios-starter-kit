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

"""Shared base class for Redis-backed store implementations.

Consolidates the boilerplate duplicated across Redis store classes:
constructor storing ``_redis`` and ``_namespace``, key construction
via ``_key(suffix)``, lifecycle ``close()``, connectivity
``health_check()``, and idempotent ``_ensure_consumer_group()`` with
BUSYGROUP handling.

Existing stores can migrate to this base incrementally.  New stores
(``RedisMessageQueue``) inherit from it from day one.

"""

from __future__ import annotations

from redis.asyncio import Redis
from redis.exceptions import ResponseError
from neoaxios_secure_cache import CacheNamespace
from neoaxios_secure_cache.serialization import Serializer
from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

logger = get_telemetry(__name__)


class RedisStoreBase:
    """Base class for Redis-backed stores.

    Provides shared constructor, key construction, lifecycle management,
    health checking, and idempotent consumer group creation.

    When a ``serializer`` is provided, subclasses can use
    ``self._serializer.dumps()`` / ``self._serializer.loads()`` instead
    of ``json.dumps()`` / ``json.loads()``.  When ``None`` (the default),
    existing JSON-based serialization in subclasses is unchanged.

    Args:
        redis: Async Redis client instance (obtained via gateway).
        namespace: CacheNamespace for key construction.
        serializer: Optional pluggable serializer.  When provided, stored
            as ``self._serializer`` for subclass use.  When ``None``,
            subclasses retain their existing JSON serialization behavior.
    """

    def __init__(
        self,
        redis: Redis,
        namespace: CacheNamespace,
        serializer: Serializer | None = None,
    ) -> None:
        self._redis = redis
        self._namespace = namespace
        self._serializer = serializer

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def _key(self, suffix: str) -> str:
        """Build a namespaced Redis key.

        Args:
            suffix: Key suffix to append to the namespace prefix.

        Returns:
            Fully-qualified Redis key string.
        """
        return self._namespace.make_key(suffix)

    @auto_trace(logger)
    async def close(self) -> None:
        """Release local Redis reference (gateway owns client lifecycle)."""
        self._redis = None  # type: ignore[assignment]

    @auto_trace(logger)
    async def health_check(self) -> bool:
        """Check Redis connectivity via PING.

        Returns:
            True if Redis is reachable, False otherwise.
        """
        try:
            await self._redis.ping()
            return True
        except Exception as exc:
            logger.warning(
                "redis_store_health_check_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return False

    @auto_trace(logger)
    async def _ensure_consumer_group(
        self, stream_key: str, group_name: str
    ) -> None:
        """Create a consumer group on a stream, idempotently.

        Uses XGROUP CREATE with MKSTREAM to auto-create the stream
        if it does not yet exist.  Silently ignores BUSYGROUP errors
        indicating the group already exists; re-raises all other
        ``ResponseError`` instances.

        Args:
            stream_key: Redis key of the stream.
            group_name: Name of the consumer group to create.

        Raises:
            ResponseError: For non-BUSYGROUP Redis errors.
        """
        try:
            await self._redis.xgroup_create(
                stream_key, group_name, id="0", mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                logger.info(
                    f"Consumer group '{group_name}' already exists on stream '{stream_key}'",
                )
            else:
                raise
