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

"""Abstract gateway protocol, type registry, and module-level accessors.

Defines the ``Gateway`` protocol that all connection gateway implementations
must structurally satisfy, a type registry that maps configuration classes to
gateway factory callables, and module-level accessor functions for managing
a singleton gateway instance.

New gateway backends register via ``register_gateway_type()``; consumers
call ``initialize_gateway(config)`` which dispatches to the registered
factory.  ``get_gateway()`` returns the active gateway typed as ``Gateway``.

Usage:
    from neoaxios_secure_cache.gateway import initialize_gateway, get_gateway, Gateway

    # At startup (after importing the concrete subpackage to trigger registration)
    import neoaxios_secure_cache.redis  # registers RedisClientConfig -> RedisGateway
    from neoaxios_secure_cache.redis.client import RedisClientConfig
    from pydantic import SecretStr

    config = RedisClientConfig(url=SecretStr("redis://localhost:6379"))
    initialize_gateway(config)

    # In components
    gw: Gateway = get_gateway()
    client = gw.get_async_client("cache")

    # At shutdown
    await gw.close_all()
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Protocol

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

logger = get_telemetry(__name__)


# ── Gateway protocol ────────────────────────────────────────────


class Gateway(Protocol):
    """Protocol defining the lifecycle management interface for connection gateways.

    All gateway implementations must structurally satisfy this protocol by
    providing all three methods with compatible signatures.  The protocol uses
    structural subtyping -- concrete classes do not need to inherit from or
    explicitly reference ``Gateway``.

    Methods:
        get_async_client: Acquire or create an async client for the given purpose.
        pool_stats: Return connection pool statistics for all managed clients.
        close_all: Async shutdown -- close all managed async clients.
    """

    def get_async_client(
        self,
        purpose: str,
        pool_size: int | None = None,
        decode_responses: bool | None = None,
        socket_timeout: float | None = None,
        pool_wait_timeout: float | None = None,
    ) -> Any:
        """Get or create an async client for the given purpose.

        Args:
            purpose: Client purpose identifier (e.g., "cache", "entity", "pubsub").
            pool_size: Override default pool size.
            decode_responses: Override default decode_responses setting.
            socket_timeout: Override default socket timeout.
            pool_wait_timeout: Override default pool wait timeout.

        Returns:
            An async client instance (concrete type depends on the gateway
            implementation).
        """
        ...

    def pool_stats(self) -> dict[str, dict[str, int]]:
        """Collect connection pool statistics from all managed clients.

        Returns:
            Dict keyed by purpose with pool utilisation metrics per client.
        """
        ...

    async def close_all(self) -> None:
        """Close all managed async clients.

        Implementations must clear internal caches after closing.
        Safe to call multiple times.
        """
        ...


# ── Gateway type registry ───────────────────────────────────────

_GATEWAY_REGISTRY: dict[type, Callable] = {}


@auto_trace(logger)
def register_gateway_type(config_type: type, factory: Callable) -> None:
    """Register a gateway factory for a given configuration type.

    After registration, ``initialize_gateway()`` will call *factory* when
    it receives a config object whose ``type()`` matches *config_type*.

    Args:
        config_type: The configuration class to map (e.g., ``RedisClientConfig``).
        factory: A callable that accepts one argument (the config instance)
            and returns a ``Gateway``-compatible object.
    """
    _GATEWAY_REGISTRY[config_type] = factory
    logger.info(
        "gateway_type_registered",
        config_type=config_type.__name__,
    )


# ── Module-level gateway singleton ──────────────────────────────

_gateway: Gateway | None = None
_gateway_lock = threading.Lock()


@auto_trace(logger)
def initialize_gateway(config: Any) -> Gateway:
    """Initialize the module-level gateway by dispatching through the type registry.

    Looks up ``type(config)`` in the gateway type registry and calls the
    registered factory.  Stores the result as the module-level singleton.
    If a gateway already exists it is replaced (the old gateway's clients
    are NOT automatically closed -- call ``close_all()`` first if needed).

    Args:
        config: A configuration object whose type has been registered via
            ``register_gateway_type()``.

    Returns:
        The initialized ``Gateway`` instance.

    Raises:
        ValueError: If ``type(config)`` is not found in the registry.
    """
    global _gateway

    factory = _GATEWAY_REGISTRY.get(type(config))
    if factory is None:
        registered = [t.__name__ for t in _GATEWAY_REGISTRY]
        raise ValueError(
            f"No gateway factory registered for config type "
            f"{type(config).__name__!r}. "
            f"Registered types: {registered}"
        )

    with _gateway_lock:
        _gateway = factory(config)

    logger.info(
        "gateway_initialized",
        config_type=type(config).__name__,
    )
    return _gateway


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def get_gateway() -> Gateway:
    """Get the module-level gateway.

    Returns:
        The initialized ``Gateway`` instance.

    Raises:
        RuntimeError: If ``initialize_gateway()`` has not been called.
    """
    if _gateway is None:
        raise RuntimeError(
            "Gateway not initialized. Call initialize_gateway() first."
        )
    return _gateway


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def is_gateway_initialized() -> bool:
    """Check whether the module-level gateway has been initialized.

    Returns:
        ``True`` if ``initialize_gateway()`` has been called and the gateway
        exists, ``False`` otherwise.
    """
    return _gateway is not None


@auto_trace(logger)
def reset_gateway() -> None:
    """Reset the module-level gateway to ``None``.

    Used in tests to ensure clean state between test runs.
    """
    global _gateway
    with _gateway_lock:
        _gateway = None
