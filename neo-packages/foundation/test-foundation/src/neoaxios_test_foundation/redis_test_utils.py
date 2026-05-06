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

"""Redis test utilities for namespace-scoped key management.

Provides:
    ``make_test_namespace()`` — factory that creates a ``CacheNamespace``
    with a uuid-scoped org for per-test isolation.

    ``cleanup_namespace_keys()`` — a SCAN-based helper that removes or
    expires keys matching a ``CacheNamespace.cleanup_pattern()``.

Together these form the single source of truth for test-key lifecycle
across all packages (replaces the inline ``_expire_namespace_keys()``
and ``integration_namespace`` fixture in neoaxios_fastapi_kit).

Modes:
    ``"unlink"`` — immediate non-blocking deletion via ``UNLINK`` (default).
    ``"expire"`` — set a TTL via ``EXPIRE`` so keys auto-evict.

All operations are batched through a Redis pipeline with a configurable
``batch_size`` to amortise round-trip overhead on large keyspaces.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import CACHE_TTL_SHORT

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace

logger = get_telemetry(__name__)

# Tell pytest this is not a test module
__test__ = False

# Centralized constants for SCAN-based cleanup.
SCAN_BATCH_SIZE: int = 500


@auto_trace(logger)
def make_test_namespace(
    *,
    env: str = "test",
    service: str = "test-svc",
    app: str = "test-app",
    domain: str = "test",
) -> "CacheNamespace":
    """Create a CacheNamespace with a uuid-scoped org for test isolation.

    Each call generates a unique org (``test-{uuid4().hex}``) ensuring
    zero key collisions between parallel test workers.

    Args:
        env: Environment identifier.  Default ``"test"``.
        service: Service name.  Default ``"test-svc"``.
        app: Application name.  Default ``"test-app"``.
        domain: Domain within the app.  Default ``"test"``.

    Returns:
        A ``CacheNamespace`` whose ``org`` is globally unique.
    """
    from neoaxios_secure_cache import CacheNamespace

    return CacheNamespace(
        org=f"test-{uuid4().hex}",
        env=env,
        service=service,
        app=app,
        domain=domain,
    )


@auto_trace(logger)
async def cleanup_namespace_keys(
    client,
    namespace,
    *,
    mode: str = "unlink",
    ttl_seconds: int = CACHE_TTL_SHORT,
    batch_size: int = SCAN_BATCH_SIZE,
) -> int:
    """SCAN for keys matching *namespace* and remove or expire them.

    Uses cursor-based ``SCAN`` with ``COUNT=batch_size`` to iterate the
    keyspace without blocking.  Each batch is executed through a non-
    transactional pipeline for efficiency.

    Args:
        client: An async Redis client (``redis.asyncio.Redis`` or
            compatible) providing ``scan()``, ``pipeline()``.
        namespace: A ``CacheNamespace`` instance whose
            ``cleanup_pattern()`` returns the SCAN match pattern.
        mode: ``"unlink"`` for immediate non-blocking deletion,
            ``"expire"`` to set a TTL.  Raises ``ValueError`` for
            unknown modes.
        ttl_seconds: TTL applied when ``mode="expire"``.  Ignored for
            ``"unlink"`` mode.  Default 300 (5 minutes).
        batch_size: Hint passed as ``COUNT`` to ``SCAN`` and used as
            the pipeline batch boundary.  Default 500.

    Returns:
        Total number of keys processed (UNLINK'd or EXPIRE'd).
        Returns 0 without creating a pipeline when no keys match.

    Raises:
        ValueError: If *mode* is not ``"unlink"`` or ``"expire"``.
    """
    if mode not in ("unlink", "expire"):
        raise ValueError(f"mode must be 'unlink' or 'expire', got {mode!r}")

    pattern = namespace.cleanup_pattern()
    count = 0
    cursor = 0

    while True:
        cursor, keys = await client.scan(cursor, match=pattern, count=batch_size)
        if keys:
            pipe = client.pipeline(transaction=False)
            for key in keys:
                if mode == "unlink":
                    # Uses DELETE instead of UNLINK: ClusterPipeline.unlink
                    # is async while Pipeline.unlink is sync (redis-py
                    # inconsistency). DELETE is sync on both. Functionally
                    # identical in pipeline context.
                    pipe.delete(key)
                else:
                    pipe.expire(key, ttl_seconds)
            await pipe.execute()
            count += len(keys)
        if cursor == 0:
            break

    return count


async def cleanup_with_fallback(client, namespace) -> int:
    """UNLINK namespace keys, falling back to EXPIRE on failure.

    Encapsulates the standard try-UNLINK/except-EXPIRE teardown pattern
    used across package conftest files.

    Args:
        client: Async Redis client.
        namespace: CacheNamespace whose keys to clean up.

    Returns:
        Number of keys processed, or 0 if both modes failed.
    """
    try:
        return await cleanup_namespace_keys(client, namespace, mode="unlink")
    except Exception:
        logger.warning(
            "UNLINK cleanup failed, applying EXPIRE safety net",
            exc_info=True,
        )
        try:
            return await cleanup_namespace_keys(
                client, namespace, mode="expire",
            )
        except Exception:
            logger.warning("EXPIRE safety-net cleanup also failed", exc_info=True)
            return 0
