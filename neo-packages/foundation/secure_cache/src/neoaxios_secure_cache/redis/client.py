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

"""Centralized Redis client factory with consistent configuration.

All Redis client creation in the codebase MUST go through these factory
functions to ensure consistent pool sizes, timeouts, TLS enforcement,
and decode_responses settings.

Usage:
    from pydantic import SecretStr
    from neoaxios_secure_cache.redis.client import RedisClientConfig, create_async_redis_client

    config = RedisClientConfig(url=SecretStr("redis://localhost:6379"), tls_policy="warn")
    client = create_async_redis_client(config)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

import redis.asyncio as redis_async
from pydantic import SecretStr
from redis.asyncio.cluster import ClusterNode
from redis.backoff import ExponentialBackoff
from redis.retry import Retry
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import (
    REDIS_CLUSTER_POOL_SIZE_PER_NODE,
    REDIS_CLUSTER_RETRY_ATTEMPTS,
    REDIS_DEFAULT_TOPOLOGY,
    REDIS_POOL_SIZE_CLIENT,
    REDIS_POOL_WAIT_TIMEOUT,
    REDIS_SOCKET_TIMEOUT,
)

logger = get_telemetry(__name__)


@dataclass(frozen=True)
class RedisClientConfig:
    """Configuration for Redis client creation.

    Immutable configuration object that validates and stores all parameters
    needed to create a Redis client. Frozen to prevent accidental mutation.

    Attributes:
        url: Redis connection URL (redis:// or rediss://), wrapped in SecretStr
            to prevent credential exposure in logs. Required for
            standalone topology; unused for sentinel/cluster topologies.
        pool_size: Connection pool size.
        socket_timeout: Socket timeout in seconds. 0 means no timeout
            (required for pub/sub connections that block indefinitely).
        pool_wait_timeout: How long (seconds) to wait for a free connection
            from BlockingConnectionPool when all slots are in use. Independent
            from socket_timeout which controls network I/O per command.
        decode_responses: Whether to decode response bytes to strings.
        tls_policy: TLS enforcement level.
            - "require": Reject non-TLS URLs with ValueError.
            - "warn": Log warning for non-TLS URLs.
            - "allow": Accept any URL without warning.
        topology: Redis deployment topology. Determines which factory path
            is used to create the client.
            - "standalone": Single Redis node (default).
            - "sentinel": Redis Sentinel for high-availability.
            - "cluster": Redis Cluster for horizontal sharding.
        sentinel_urls: List of Sentinel node URLs (redis:// or rediss://).
            Required when topology is "sentinel".
        sentinel_master_name: Name of the Sentinel-monitored master.
            Required when topology is "sentinel".
        sentinel_password: Password for Sentinel node authentication, wrapped
            in SecretStr to prevent credential exposure in logs.
        password: Password for the master Redis instance (sentinel topology)
            or cluster nodes (cluster topology), wrapped in SecretStr to
            prevent credential exposure in logs.
        username: Username for Redis ACL authentication on the master
            (sentinel topology) or cluster nodes (cluster topology).
        cluster_nodes: List of cluster node URLs (redis:// or rediss://).
            Required when topology is "cluster".
        cluster_pool_size_per_node: Per-node connection pool size for cluster
            topology. Each cluster node gets its own pool capped at this size.
            Only used when topology is "cluster".
        cluster_retry_attempts: Number of retry attempts with exponential
            backoff for cluster operations on ConnectionError/TimeoutError.
            Only used when topology is "cluster".
    """

    url: SecretStr = SecretStr("")
    pool_size: int = REDIS_POOL_SIZE_CLIENT
    socket_timeout: float = REDIS_SOCKET_TIMEOUT
    pool_wait_timeout: float = REDIS_POOL_WAIT_TIMEOUT
    decode_responses: bool = True
    tls_policy: Literal["require", "warn", "allow"] = "warn"
    topology: Literal["standalone", "sentinel", "cluster"] = REDIS_DEFAULT_TOPOLOGY
    sentinel_urls: list[str] | None = None
    sentinel_master_name: str | None = None
    sentinel_password: SecretStr | None = None
    password: SecretStr | None = None
    username: str | None = None
    cluster_nodes: list[str] | None = None
    cluster_pool_size_per_node: int = REDIS_CLUSTER_POOL_SIZE_PER_NODE
    cluster_retry_attempts: int = REDIS_CLUSTER_RETRY_ATTEMPTS


# notrace: pure computation, called from traced validators
def _validate_pool_settings(config: RedisClientConfig) -> None:
    """Validate pool_size and timeout fields common to all topologies.

    Args:
        config: Configuration to validate.

    Raises:
        ValueError: If pool_size is non-positive or timeouts are negative.
    """
    if config.pool_size <= 0:
        raise ValueError(f"pool_size must be positive (got: {config.pool_size})")

    if config.socket_timeout < 0:
        raise ValueError(f"socket_timeout must be non-negative (got: {config.socket_timeout})")

    if config.pool_wait_timeout < 0:
        raise ValueError(f"pool_wait_timeout must be non-negative (got: {config.pool_wait_timeout})")

    if config.cluster_pool_size_per_node <= 0:
        raise ValueError(
            f"cluster_pool_size_per_node must be positive (got: {config.cluster_pool_size_per_node})"
        )

    if config.cluster_retry_attempts < 0:
        raise ValueError(
            f"cluster_retry_attempts must be non-negative (got: {config.cluster_retry_attempts})"
        )


@auto_trace(logger)
def _validate_config(config: RedisClientConfig) -> None:
    """Validate RedisClientConfig parameters for standalone topology.

    Args:
        config: Configuration to validate.

    Raises:
        ValueError: If any parameter is invalid.
    """
    url_value = config.url.get_secret_value()
    if not url_value or not isinstance(url_value, str):
        raise ValueError("url must be a non-empty string")

    if not url_value.startswith(("redis://", "rediss://")):
        raise ValueError(
            "url must start with 'redis://' or 'rediss://'"
        )

    _validate_pool_settings(config)

    _enforce_tls_policy(url_value, config.tls_policy)


# notrace: pure computation, called from traced validators
def _validate_url_list(urls: list[str], field_name: str) -> None:
    """Validate that all URLs in a list use valid redis schemes.

    Args:
        urls: List of URLs to validate.
        field_name: Field name for error messages (e.g. "sentinel_urls").

    Raises:
        ValueError: If any URL has an invalid scheme.
    """
    valid_schemes = ("redis://", "rediss://")
    for url in urls:
        if not url.startswith(valid_schemes):
            raise ValueError(
                f"{field_name} entry must start with 'redis://' or 'rediss://', "
                f"got: '{url}'"
            )


@auto_trace(logger)
def _validate_topology(config: RedisClientConfig) -> None:
    """Validate topology-specific field invariants on RedisClientConfig.

    Enforces that the fields required by each topology are present and valid
    before any client construction begins (fail-fast).

    For "sentinel": requires non-empty ``sentinel_urls`` list with valid
    ``redis://`` or ``rediss://`` schemes, and non-empty ``sentinel_master_name``.
    For "cluster": requires non-empty ``cluster_nodes`` list with valid schemes.
    For "standalone": defers to ``_validate_config()`` (no additional checks here).

    Args:
        config: Configuration to validate.

    Raises:
        ValueError: If any topology-specific invariant is violated.
    """
    if config.topology == "sentinel":
        _validate_sentinel_topology(config)
    elif config.topology == "cluster":
        _validate_cluster_topology(config)

    # Universal validation: pool_size and timeouts apply to ALL topologies.
    # For standalone, _validate_config() also checks these, but sentinel/cluster
    # skip _validate_config() entirely, so we validate here unconditionally.
    _validate_pool_settings(config)


# notrace: pure computation, called from traced _validate_topology
def _validate_sentinel_topology(config: RedisClientConfig) -> None:
    """Validate sentinel-specific configuration fields.

    Args:
        config: Configuration to validate.

    Raises:
        ValueError: If sentinel_urls or sentinel_master_name are missing/invalid.
    """
    if not config.sentinel_urls:
        raise ValueError(
            "sentinel topology requires sentinel_urls: "
            "provide a non-empty list of sentinel node URLs"
        )
    _validate_url_list(config.sentinel_urls, "sentinel_urls")
    if not config.sentinel_master_name:
        raise ValueError(
            "sentinel topology requires sentinel_master_name: "
            "provide a non-empty string identifying the monitored master"
        )


# notrace: pure computation, called from traced _validate_topology
def _validate_cluster_topology(config: RedisClientConfig) -> None:
    """Validate cluster-specific configuration fields.

    Args:
        config: Configuration to validate.

    Raises:
        ValueError: If cluster_nodes is missing or contains invalid URLs.
    """
    if not config.cluster_nodes:
        raise ValueError(
            "cluster topology requires cluster_nodes: "
            "provide a non-empty list of cluster node URLs"
        )
    _validate_url_list(config.cluster_nodes, "cluster_nodes")


@auto_trace(logger)
def _enforce_tls_policy(url: str, policy: str) -> None:
    """Enforce TLS policy on Redis URL.

    Args:
        url: Redis connection URL.
        policy: TLS policy ("require", "warn", "allow").

    Raises:
        ValueError: If policy is "require" and URL is not rediss://.
    """
    is_tls = url.startswith("rediss://")

    if policy == "require" and not is_tls:
        raise ValueError(
            "TLS required: URL must use rediss:// scheme. "
            "Set tls_policy='warn' or 'allow' for non-TLS connections."
        )

    if policy == "warn" and not is_tls:
        logger.warning(
            "redis_tls_not_enabled",
            message="Redis connection without TLS. Consider rediss:// for production.",
        )


@auto_trace(logger)
def _enforce_tls_policy_on_urls(urls: list[str], policy: str) -> None:
    """Enforce TLS policy on a list of Redis URLs.

    Checks each URL against the TLS policy. For "require", all URLs must use
    rediss://. For "warn", logs a warning if any URL is non-TLS.

    Args:
        urls: List of Redis connection URLs.
        policy: TLS policy ("require", "warn", "allow").

    Raises:
        ValueError: If policy is "require" and any URL is not rediss://.
    """
    for url in urls:
        _enforce_tls_policy(url, policy)


# notrace: pure computation, called from traced factory
def _parse_host_port(url: str) -> tuple[str, int]:
    """Parse a redis:// or rediss:// URL into a (host, port) tuple.

    Args:
        url: Redis URL with redis:// or rediss:// scheme.

    Returns:
        Tuple of (hostname, port).
    """
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    return (host, port)


# notrace: pure computation, called from traced factory
def _parse_credentials_from_url(url: str) -> tuple[str | None, str | None]:
    """Parse username and password from a redis:// or rediss:// URL.

    Args:
        url: Redis URL with redis:// or rediss:// scheme.

    Returns:
        Tuple of (username, password). Either may be None.
    """
    parsed = urlparse(url)
    return (parsed.username, parsed.password)


# notrace: pure computation, called from traced factory
def _any_url_uses_tls(urls: list[str]) -> bool:
    """Check if any URL in the list uses the rediss:// (TLS) scheme.

    Args:
        urls: List of Redis URLs.

    Returns:
        True if at least one URL uses rediss://.
    """
    return any(u.startswith("rediss://") for u in urls)


# notrace: pure computation, called from traced factory
def _cluster_node_from_url(url: str) -> ClusterNode:
    """Parse a redis:// or rediss:// URL into a ClusterNode.

    Args:
        url: Redis URL with redis:// or rediss:// scheme.

    Returns:
        ClusterNode with extracted host and port.
    """
    host, port = _parse_host_port(url)
    return ClusterNode(host=host, port=port)


# notrace: pure computation, called from traced factory
def _resolve_cluster_credentials(config: RedisClientConfig) -> dict[str, str]:
    """Resolve username/password for cluster nodes.

    Uses explicit config fields if set. Falls back to parsing credentials
    from the first cluster node URL.

    Args:
        config: Redis client configuration.

    Returns:
        Dict with "username" and/or "password" keys, or empty dict.
    """
    username = config.username
    password = (
        config.password.get_secret_value() if config.password is not None else None
    )

    # Fall back to credentials embedded in the first cluster URL
    if username is None and password is None and config.cluster_nodes:
        url_user, url_pass = _parse_credentials_from_url(config.cluster_nodes[0])
        username = url_user
        password = url_pass

    creds: dict[str, str] = {}
    if username is not None:
        creds["username"] = username
    if password is not None:
        creds["password"] = password
    return creds


@auto_trace(logger)
def create_async_redis_client(config: RedisClientConfig) -> redis_async.Redis:
    """Create an async Redis client with validated configuration.

    Uses BlockingConnectionPool so that under burst load connections wait
    for a free slot instead of raising ConnectionError("Too many connections").

    Args:
        config: Redis client configuration.

    Returns:
        Configured async Redis client.

    Raises:
        ValueError: If configuration is invalid.
        redis.exceptions.ConnectionError: If pool/client creation fails.
    """
    _validate_topology(config)

    # Enforce TLS policy for ALL topologies before branching.
    if config.topology == "sentinel":
        _enforce_tls_policy_on_urls(config.sentinel_urls, config.tls_policy)  # type: ignore[arg-type]
    elif config.topology == "cluster":
        _enforce_tls_policy_on_urls(config.cluster_nodes, config.tls_policy)  # type: ignore[arg-type]

    if config.topology == "standalone":
        _validate_config(config)

    # redis-py uses None for "no timeout"; 0 means no timeout in our API
    st = None if config.socket_timeout == 0 else config.socket_timeout
    try:
        if config.topology == "sentinel":
            client = _create_async_sentinel_client(config, st)
        elif config.topology == "cluster":
            client = _create_async_cluster_client(config, st)
        else:
            from neoaxios_secure_cache.defaults import REDIS_HEALTH_CHECK_INTERVAL

            pool = redis_async.BlockingConnectionPool.from_url(
                config.url.get_secret_value(),
                max_connections=config.pool_size,
                timeout=config.pool_wait_timeout,
                decode_responses=config.decode_responses,
                socket_timeout=st,
                health_check_interval=REDIS_HEALTH_CHECK_INTERVAL,
            )
            client = redis_async.Redis(connection_pool=pool)
    except Exception as exc:
        logger.log_error(
            Exception(f"Failed to create async Redis client: {exc}"),
        )
        raise

    logger.info(
        "async_redis_client_created",
        pool_size=config.pool_size,
        pool_wait_timeout=config.pool_wait_timeout,
        decode_responses=config.decode_responses,
        tls_policy=config.tls_policy,
        topology=config.topology,
    )

    return client


# notrace: called from traced create_async_redis_client
def _create_async_sentinel_client(
    config: RedisClientConfig, socket_timeout: float | None,
) -> redis_async.Redis:
    """Create an async Redis client via Sentinel discovery.

    Args:
        config: Redis client configuration with sentinel fields.
        socket_timeout: Resolved socket timeout (None means no timeout).

    Returns:
        Async Redis client connected to the sentinel-discovered master.
    """
    sentinel_kwargs: dict[str, str] = {}
    if config.sentinel_password is not None:
        sentinel_kwargs["password"] = (
            config.sentinel_password.get_secret_value()
        )
    sentinel_hosts = [
        _parse_host_port(u) for u in config.sentinel_urls  # type: ignore[union-attr]
    ]
    use_ssl = _any_url_uses_tls(config.sentinel_urls)  # type: ignore[arg-type]
    connection_kwargs: dict[str, object] = {}
    if use_ssl:
        connection_kwargs["ssl"] = True
    sentinel = redis_async.Sentinel(
        sentinel_hosts,
        sentinel_kwargs=sentinel_kwargs,
        socket_timeout=socket_timeout,
        decode_responses=config.decode_responses,
        **connection_kwargs,
    )
    # Forward master Redis password for authentication.
    master_kwargs: dict[str, str] = {}
    if config.password is not None:
        master_kwargs["password"] = config.password.get_secret_value()
    if config.username is not None:
        master_kwargs["username"] = config.username
    return sentinel.master_for(config.sentinel_master_name, **master_kwargs)


# notrace: called from traced create_async_redis_client
def _create_async_cluster_client(
    config: RedisClientConfig, socket_timeout: float | None,
) -> redis_async.RedisCluster:
    """Create an async Redis Cluster client.

    Args:
        config: Redis client configuration with cluster fields.
        socket_timeout: Resolved socket timeout (None means no timeout).

    Returns:
        Async RedisCluster client.
    """
    startup_nodes = [
        _cluster_node_from_url(u) for u in config.cluster_nodes  # type: ignore[union-attr]
    ]
    cluster_ssl = _any_url_uses_tls(config.cluster_nodes)  # type: ignore[arg-type]
    cluster_kwargs: dict[str, object] = {}
    if cluster_ssl:
        cluster_kwargs["ssl"] = True
    # Forward credentials for cluster node authentication.
    creds = _resolve_cluster_credentials(config)
    cluster_kwargs.update(creds)
    # Per-node pool sizing prevents N×pool_size connection explosion
    # (e.g. 6 nodes × 5000 = 30K connections). Each node gets its own pool
    # capped at cluster_pool_size_per_node (default 500).
    # Exponential backoff retry on transient connection errors
    # improves cluster resilience during node failovers and network blips.
    retry = Retry(ExponentialBackoff(), retries=config.cluster_retry_attempts)
    # Include RedisClusterException in retry_on_error so transient failures
    # during cluster topology refresh recover automatically.  redis-py's
    # RedisCluster._split_command_across_slots (used by multi-key commands
    # like DEL/EXISTS/TOUCH/UNLINK) calls initialize() whenever
    # ``_initialize=True``, and ``initialize()`` wraps any node-level
    # ConnectionError from CLUSTER SLOTS into a RedisClusterException.
    # Without this, a single transient startup-node refusal under sustained
    # load takes out every subsequent command that happens to route through
    # the split path — observed in scale/test_async_consumer_pool_throughput
    # (5000-task fan-out momentarily exhausts the Redis TCP accept queue on
    # a single-node cluster, the next DEL's initialize() fails, no retry
    # because RedisClusterException ≠ ConnectionError).
    from redis.exceptions import RedisClusterException
    return redis_async.RedisCluster(
        startup_nodes=startup_nodes,
        max_connections=config.cluster_pool_size_per_node,
        decode_responses=config.decode_responses,
        socket_timeout=socket_timeout,
        retry=retry,
        retry_on_error=[ConnectionError, TimeoutError, RedisClusterException],
        **cluster_kwargs,
    )


# notrace: pure computation, called from traced get_async_pool_stats
def _get_standalone_pool_stats(client: redis_async.Redis) -> dict[str, int]:
    """Extract pool stats from a standalone (non-cluster) Redis client.

    Reads ``BlockingConnectionPool`` internals. Private attributes are
    stable across redis-py 4.x/5.x.

    Args:
        client: Async Redis client with a ``connection_pool`` attribute.

    Returns:
        Dict with ``max_connections``, ``in_use``, ``available``, ``created``.
        Returns zeroes if pool internals are unavailable.
    """
    pool = getattr(client, "connection_pool", None)
    if pool is None:
        return {"max_connections": 0, "in_use": 0, "available": 0, "created": 0}

    max_conn = getattr(pool, "max_connections", 0)
    in_use = len(getattr(pool, "_in_use_connections", set()))
    created = getattr(pool, "_created_connections", 0)

    avail_q = getattr(pool, "_available_connections", None)
    available = avail_q.qsize() if hasattr(avail_q, "qsize") else len(avail_q) if avail_q else 0

    return {
        "max_connections": max_conn,
        "in_use": in_use,
        "available": available,
        "created": created,
    }


# notrace: pure computation, called from traced get_async_pool_stats
def _get_cluster_node_pool_stats(node: ClusterNode) -> dict[str, int]:
    """Extract pool stats from a single ClusterNode.

    ClusterNode manages its own connection pool via ``_connections``
    (all connections) and ``_free`` (idle connections) attributes.

    Args:
        node: A ClusterNode from ``RedisCluster.get_nodes()``.

    Returns:
        Dict with ``max_connections``, ``in_use``, ``available``, ``created``.
        Returns zeroes if node pool internals are unavailable.
    """
    max_conn = getattr(node, "max_connections", 0)
    connections = getattr(node, "_connections", None)
    free = getattr(node, "_free", None)

    if connections is None:
        return {"max_connections": max_conn, "in_use": 0, "available": 0, "created": 0}

    created = len(connections)
    available = len(free) if free is not None else 0
    in_use = created - available

    return {
        "max_connections": max_conn,
        "in_use": in_use,
        "available": available,
        "created": created,
    }


@auto_trace(logger)
def get_async_pool_stats(
    client: redis_async.Redis | redis_async.RedisCluster,
) -> dict:
    """Read connection pool utilization from an async Redis client.

    For standalone/sentinel clients, extracts stats from the underlying
    ``BlockingConnectionPool``. For ``RedisCluster`` clients, iterates
    ``get_nodes()`` to collect per-node pool stats and computes aggregate
    totals.

    Args:
        client: Async Redis client created via ``create_async_redis_client``.

    Returns:
        For non-cluster clients:
            Dict with ``max_connections``, ``in_use``, ``available``, ``created``.
        For cluster clients:
            Dict with aggregate ``max_connections``, ``in_use``, ``available``,
            ``created`` plus a ``nodes`` dict keyed by ``host:port`` with
            per-node breakdown. Returns zeroes if pool internals are unavailable.
    """
    # Detect RedisCluster via isinstance; standalone/sentinel clients
    # do not inherit from RedisCluster and take the fast path.
    if not isinstance(client, redis_async.RedisCluster):
        return _get_standalone_pool_stats(client)

    nodes = client.get_nodes()
    if not nodes:
        return {
            "max_connections": 0,
            "in_use": 0,
            "available": 0,
            "created": 0,
            "nodes": {},
        }

    agg_max = 0
    agg_in_use = 0
    agg_available = 0
    agg_created = 0
    node_stats: dict[str, dict[str, int]] = {}

    for node in nodes:
        node_name = getattr(node, "name", None)
        if node_name is None:
            host = getattr(node, "host", "unknown")
            port = getattr(node, "port", 0)
            node_name = f"{host}:{port}"

        stats = _get_cluster_node_pool_stats(node)
        node_stats[node_name] = stats

        agg_max += stats["max_connections"]
        agg_in_use += stats["in_use"]
        agg_available += stats["available"]
        agg_created += stats["created"]

    return {
        "max_connections": agg_max,
        "in_use": agg_in_use,
        "available": agg_available,
        "created": agg_created,
        "nodes": node_stats,
    }
