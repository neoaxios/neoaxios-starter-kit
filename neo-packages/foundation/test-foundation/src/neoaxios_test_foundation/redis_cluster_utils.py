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

"""Redis Cluster test utilities for cross-package integration tests.

Provides cluster node detection, availability checking, skip markers,
and client creation — extracted from the duplicated pattern in
``neoaxios_fastapi_kit/tests/extended/conftest.py``,
``resilience-kit/tests/conftest.py``, and others.

Functions:
    ``detect_cluster_nodes()`` — parse ``REDIS_CLUSTER_NODES`` env var.
    ``check_cluster_available()`` — TCP-check each cluster node.
    ``make_requires_redis_cluster_marker()`` — pytest skipif marker.
    ``create_cluster_client()`` — async RedisCluster client with health check.
"""

from __future__ import annotations

import os
import socket
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import pytest

from neoaxios_logging import get_telemetry

if TYPE_CHECKING:
    from redis.asyncio.cluster import RedisCluster

logger = get_telemetry(__name__)

# Tell pytest this is not a test module
__test__ = False


def _check_redis_server(url: str) -> bool:
    """Check if a Redis server is reachable via TCP.

    Args:
        url: Redis URL (``redis://host:port`` or ``rediss://host:port``).

    Returns:
        True if server is reachable, False otherwise.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def detect_cluster_nodes() -> list[str]:
    """Parse ``REDIS_CLUSTER_NODES`` env var into a list of node URLs.

    The environment variable is expected to be a comma-separated list of
    Redis URLs (e.g. ``redis://host1:7010,redis://host2:7011``).

    Returns:
        List of stripped, non-empty node URL strings.
        Empty list if the env var is unset or empty.
    """
    raw = os.getenv("REDIS_CLUSTER_NODES", "")
    if not raw:
        return []
    return [n.strip() for n in raw.split(",") if n.strip()]


def check_cluster_available(nodes: list[str]) -> bool:
    """TCP-check each cluster node.

    Args:
        nodes: List of Redis node URLs to check.

    Returns:
        True if all nodes are reachable, False otherwise.
        Returns False if the list is empty.
    """
    if not nodes:
        return False
    return all(_check_redis_server(node) for node in nodes)


def make_requires_redis_cluster_marker() -> pytest.MarkDecorator:
    """Return a ``pytest.mark.skipif`` marker for cluster unavailability.

    Performs detection and availability checking at call time so the
    marker reflects the current environment state.

    Returns:
        A ``pytest.mark.skipif`` decorator that skips tests when Redis
        Cluster is unavailable.
    """
    nodes = detect_cluster_nodes()
    available = check_cluster_available(nodes) if nodes else False
    return pytest.mark.skipif(
        not available,
        reason="Redis Cluster unavailable (REDIS_CLUSTER_NODES not set or nodes unreachable)",
    )


async def create_cluster_client(
    nodes: list[str],
    *,
    decode_responses: bool = False,
) -> "RedisCluster":
    """Create and health-check an async RedisCluster client.

    Parses the first node URL for the startup host/port, creates a
    ``RedisCluster`` client, and verifies connectivity with a ``PING``.

    Args:
        nodes: List of Redis cluster node URLs.
        decode_responses: Whether to decode response bytes to strings.

    Returns:
        A connected ``RedisCluster`` async client.

    Raises:
        pytest.skip: If no nodes are provided or connection fails.
    """
    if not nodes:
        pytest.skip("No Redis Cluster nodes provided")

    from redis.asyncio.cluster import RedisCluster

    parsed = urlparse(nodes[0])
    host = parsed.hostname or "localhost"
    port = parsed.port or 7010

    client = RedisCluster(
        host=host,
        port=port,
        decode_responses=decode_responses,
    )

    try:
        await client.ping()
    except Exception as e:
        pytest.skip(f"Redis Cluster connection failed: {e}")

    return client
