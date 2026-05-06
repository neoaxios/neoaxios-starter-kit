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

"""Central Redis connection gateway implementation.

Owns lifecycle of all Redis clients in the process. Components request
clients by purpose; the gateway creates or reuses as appropriate.

Usage:
    from neoaxios_secure_cache.redis.gateway import RedisGateway
    from neoaxios_secure_cache.redis.client import RedisClientConfig

    gateway = RedisGateway(config)
    client = gateway.get_async_client("cache")

    # At shutdown
    await gateway.close_all()
"""

from __future__ import annotations

import threading

import redis.asyncio as redis_async
from neoaxios_logging import auto_trace, get_telemetry, TraceDisabledReason

from neoaxios_secure_cache.redis.client import (
    RedisClientConfig,
    create_async_redis_client,
    get_async_pool_stats,
)

logger = get_telemetry(__name__)


class RedisGateway:
    """Central registry for Redis connections (async-only).

    Owns lifecycle of all async Redis clients in the process. Components
    request clients by purpose; the gateway creates or reuses as appropriate.

    Clients are cached by (purpose, decode_responses, pool_size,
    socket_timeout, pool_wait_timeout, topology) tuple.
    Thread-safe via threading.Lock.

    Attributes:
        _default_config: Default configuration for new clients.
        _async_clients: Cache of async Redis clients by
            (purpose, decode_responses, pool_size, socket_timeout,
            pool_wait_timeout, topology).
        _lock: Thread-safety lock for client cache access.
    """

    @auto_trace(logger)
    def __init__(self, default_config: RedisClientConfig) -> None:
        """Initialize the gateway with default configuration.

        Args:
            default_config: Default RedisClientConfig for creating new clients.
        """
        self._default_config = default_config
        self._async_clients: dict[tuple[str, bool, int, float, float, str], redis_async.Redis] = {}
        self._lock = threading.Lock()

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _build_config(
        self,
        pool_size: int,
        socket_timeout: float,
        pool_wait_timeout: float,
        decode_responses: bool,
    ) -> RedisClientConfig:
        """Build a RedisClientConfig from gateway defaults plus overrides.

        Centralises the 15-field construction so ``get_async_client``
        uses a single construction site.

        Args:
            pool_size: Connection pool size override.
            socket_timeout: Socket timeout override.
            pool_wait_timeout: Pool wait timeout override.
            decode_responses: Decode responses override.

        Returns:
            Fully populated RedisClientConfig.
        """
        return RedisClientConfig(
            url=self._default_config.url,
            pool_size=pool_size,
            socket_timeout=socket_timeout,
            pool_wait_timeout=pool_wait_timeout,
            decode_responses=decode_responses,
            tls_policy=self._default_config.tls_policy,
            topology=self._default_config.topology,
            sentinel_urls=self._default_config.sentinel_urls,
            sentinel_master_name=self._default_config.sentinel_master_name,
            sentinel_password=self._default_config.sentinel_password,
            password=self._default_config.password,
            username=self._default_config.username,
            cluster_nodes=self._default_config.cluster_nodes,
            cluster_pool_size_per_node=self._default_config.cluster_pool_size_per_node,
            cluster_retry_attempts=self._default_config.cluster_retry_attempts,
        )

    @auto_trace(logger)
    def get_async_client(
        self,
        purpose: str,
        pool_size: int | None = None,
        decode_responses: bool | None = None,
        socket_timeout: float | None = None,
        pool_wait_timeout: float | None = None,
    ) -> redis_async.Redis:
        """Get or create an async Redis client for the given purpose.

        For cluster topology, pool_size is capped to
        ``cluster_pool_size_per_node`` to prevent the N-nodes multiplier
        from creating excessive total connections (e.g. 6 nodes x 5000 = 30K).

        Args:
            purpose: Client purpose (e.g., "cache", "entity", "pubsub").
            pool_size: Override default pool size (only used on first creation).
                Capped to ``cluster_pool_size_per_node`` for cluster topology.
            decode_responses: Override default decode_responses (None uses default).
            socket_timeout: Override default socket timeout. Use 0 for no timeout
                (required for pub/sub connections that block indefinitely).
            pool_wait_timeout: Override default pool wait timeout. Controls how
                long to wait for a free connection from BlockingConnectionPool.

        Returns:
            Async Redis client, cached by (purpose, decode_responses,
            pool_size, socket_timeout, pool_wait_timeout, topology).
        """
        dr = decode_responses if decode_responses is not None else self._default_config.decode_responses
        ps = pool_size if pool_size is not None else self._default_config.pool_size
        st = socket_timeout if socket_timeout is not None else self._default_config.socket_timeout
        pwt = pool_wait_timeout if pool_wait_timeout is not None else self._default_config.pool_wait_timeout

        # Cap pool_size per node for cluster topology to prevent the
        # N-nodes multiplier from creating excessive connections.
        requested_ps = ps
        if self._default_config.topology == "cluster":
            cap = self._default_config.cluster_pool_size_per_node
            if ps > cap:
                ps = cap
                logger.info(
                    "gateway_cluster_pool_size_capped",
                    purpose=purpose,
                    requested_pool_size=requested_ps,
                    capped_pool_size=ps,
                    cluster_pool_size_per_node=cap,
                )

        cache_key = (purpose, dr, ps, st, pwt, self._default_config.topology)

        with self._lock:
            if cache_key in self._async_clients:
                return self._async_clients[cache_key]

            config = self._build_config(ps, st, pwt, dr)

            client = create_async_redis_client(config)
            # tag the client with its purpose so downstream
            # protocols can reject a client from a non-matching pool —
            # preventing pub/sub publishes from landing on a state-pool
            # connection (and vice versa).  ``_neo_purpose`` is absent
            # for clients constructed outside the gateway (pub/sub-pinned
            # standalone clients built directly via
            # :func:`create_async_redis_client` tag themselves at their
            # construction site) and for test mocks; purpose guards MUST
            # accept that case.
            client._neo_purpose = purpose  # type: ignore[attr-defined]
            self._async_clients[cache_key] = client

            logger.info(
                "gateway_async_client_created",
                purpose=purpose,
                decode_responses=dr,
                pool_size=config.pool_size,
                topology=self._default_config.topology,
            )

            return client

    @auto_trace(logger)
    def pool_stats(self) -> dict[str, dict[str, int]]:
        """Collect connection pool stats from all managed async clients.

        Returns:
            Dict keyed by purpose with pool utilization per client.
            Example::

                {
                    "consumer": {"max_connections": 312, "in_use": 5, "available": 10, "created": 15},
                    "entity":   {"max_connections": 312, "in_use": 2, "available": 8, "created": 10},
                }
        """
        stats: dict[str, dict[str, int]] = {}
        with self._lock:
            for cache_key, client in self._async_clients.items():
                purpose = cache_key[0]
                stats[purpose] = get_async_pool_stats(client)
        return stats

    @auto_trace(logger)
    async def close_all(self) -> None:
        """Close all cached async clients.

        Clears the client cache after closing. Safe to call multiple times.
        """
        with self._lock:
            async_clients = list(self._async_clients.values())
            self._async_clients.clear()

        for client in async_clients:
            try:
                if not isinstance(client, redis_async.RedisCluster):
                    await client.connection_pool.disconnect(inuse_connections=True)
                await client.aclose()
            except Exception as e:
                logger.warning("gateway_async_client_close_failed", error=str(e))

        logger.info(
            "gateway_all_clients_closed",
            async_count=len(async_clients),
        )
