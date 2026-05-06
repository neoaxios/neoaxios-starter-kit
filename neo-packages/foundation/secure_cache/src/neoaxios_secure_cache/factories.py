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

"""Factory functions for cache component creation.

This module provides factory functions for creating cache backends and
security wrappers with validated configurations.

Factories:
- create_secure_cache: Main factory for fully-configured secure cache from config

Usage:
    from neoaxios_secure_cache import create_secure_cache
    from neoaxios_secure_cache.config import register_cache_config, get_cache_config

    # Register configuration from JSON file
    register_cache_config("/etc/myapp/cache.json")

    # Create cache from registered config
    config = get_cache_config()
    cache = create_secure_cache(config)

    # Or create from config directly
    from neoaxios_secure_cache.config import SecureCacheConfig
    config = SecureCacheConfig(
        tenant_id="tenant-123",
        master_key="env:CACHE_MASTER_KEY",
    )
    cache = create_secure_cache(config)

Implementation Notes:
- create_secure_cache is the ONLY public instantiation point
- Takes SecureCacheConfig for all configuration
- Resolves master_key from env:/file:// references
- Derives signing_key and kek from master_key using HKDF
- Wrapper stacking order (Encrypt-then-Sign):
  1. Create base backend (InMemoryBackend or RedisBackend)
  2. Wrap with EncryptingCacheWrapper (encrypt data at rest)
  3. Wrap with SigningCacheWrapper (sign encrypted data)
- Production validation: rejects master_key from env vars (SEC-REQ-07)
- Memory protection: calls prctl(PR_SET_DUMPABLE, 0) on Linux (SEC-REQ-07)
- Optional components attached to returned cache:
  * cache.metrics: SecureCacheMetrics (if features.enable_metrics=True)
  * cache.canary: CanaryMonitor (if features.enable_canary=True, requires redis)
  * cache.sequence_tracker: SequenceTracker (if features.enable_sequence_tracking=True, requires redis)
- CanaryMonitor requires manual start: await cache.canary.start()
"""

import atexit
import base64
import binascii
import ctypes
import dataclasses
import os
import platform
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from neoaxios_secure_config import resolve_value
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.backends.memory import InMemoryCacheBackend
from neoaxios_secure_cache.backends.redis import create_redis_backend
from neoaxios_secure_cache.config.loaders import ALLOWED_SECRET_DIRS
from neoaxios_secure_cache.config.schemas import SecureCacheConfig
from neoaxios_secure_cache.defaults import (
    CANARY_CHECK_INTERVAL_SECONDS,
    CANARY_INLINE_CHECK_PROBABILITY,
    CRYPTO_EXECUTOR_FALLBACK_CPUS,
    CRYPTO_EXECUTOR_MAX_WORKERS,
    CRYPTO_EXECUTOR_MIN_CORES,
    SEQUENCE_TRACKER_LOCAL_CACHE_SIZE,
)
from neoaxios_secure_cache.metrics import create_metrics
from neoaxios_secure_cache.namespace import CacheNamespace
from neoaxios_secure_cache.security.canary import create_canary_monitor
from neoaxios_secure_cache.security.encryption import create_encrypting_wrapper
from neoaxios_secure_cache.security.keys import derive_kek, derive_signing_key, validate_key_material
from neoaxios_secure_cache.security.sequence import create_sequence_tracker
from neoaxios_secure_cache.security.signing import create_signing_wrapper

logger = get_telemetry(__name__)


@auto_trace(logger)
def _enable_memory_protection() -> bool:
    """Disable core dumps to prevent key leakage (Linux only).

    Calls prctl(PR_SET_DUMPABLE, 0) to disable core dumps for this process.
    This prevents sensitive key material from being written to disk in crash dumps.

    Returns:
        True if memory protection was enabled successfully, False otherwise

    Security:
        SEC-REQ-07: Memory protection to prevent key leakage

    Note:
        This function is Linux-specific. On other platforms, it returns False
        without raising an error.
    """
    try:
        # Check if we're on Linux
        if platform.system() != "Linux":  # pragma: no cover
            logger.debug(f"Memory protection not available on {platform.system()}")  # pragma: no cover
            return False  # pragma: no cover

        # prctl constants for Linux
        PR_SET_DUMPABLE = 4

        # Load libc
        try:
            libc = ctypes.CDLL("libc.so.6")
        except OSError:
            # Try alternative libc names
            try:
                libc = ctypes.CDLL("libc.so")
            except OSError as e:
                logger.info(f"Failed to load libc for memory protection: {e}")
                return False

        # Call prctl(PR_SET_DUMPABLE, 0)
        result = libc.prctl(PR_SET_DUMPABLE, 0)

        if result == 0:
            logger.info("Memory protection enabled: core dumps disabled via prctl(PR_SET_DUMPABLE, 0)")
            return True
        else:
            logger.info(f"prctl(PR_SET_DUMPABLE, 0) returned non-zero: {result}")
            return False

    except Exception as e:
        logger.info(f"Failed to enable memory protection: {e}")
        return False


def _key_matches_env_value(  # notrace: pure comparison helper
    master_key: bytes, key_hex: str, env_value: str,
) -> bool:
    """Check if an environment variable value matches the master key.

    Args:
        master_key: Raw master key bytes.
        key_hex: Hex-encoded master key string.
        env_value: Environment variable value to compare.

    Returns:
        True if the env value matches the key (hex or base64), False otherwise.
    """
    if env_value == key_hex:
        return True
    try:
        return base64.b64decode(env_value) == master_key
    except (binascii.Error, ValueError):
        return False


@auto_trace(logger)
def _validate_production_key_source(
    master_key: bytes,
    env: dict[str, str] | None = None,
) -> bool:
    """Validate that master key is not sourced from environment variables in production.

    Args:
        master_key: Master key to validate.
        env: Environment variable mapping (defaults to os.environ for production;
            inject explicitly for testability).

    Returns:
        True if key source is acceptable, False if key appears to come from env var.

    Raises:
        Exception: Re-raises any unexpected error (fail-closed).
    """
    if env is None:
        env = dict(os.environ)

    try:
        key_hex = master_key.hex()

        for env_name, env_value in env.items():
            if not env_value or len(env_value) < 32:
                continue

            if _key_matches_env_value(master_key, key_hex, env_value):
                logger.log_error(
                    Exception(
                        f"Master key appears to come from environment variable '{env_name}'. "
                        f"This is insecure in production. Use a secure secret store instead."
                    )
                )
                return False

        logger.debug("Production key source validation passed")
        return True

    except Exception as e:
        logger.log_error(Exception(f"Error during production key source validation: {e}"))
        raise


@auto_trace(logger)
def _resolve_master_key(config: SecureCacheConfig) -> bytes:
    """Resolve master_key from SecureCacheConfig to bytes.

    Handles:
    - env:VAR_NAME - Read from environment variable
    - file:///path - Read from file
    - Hex-encoded 32-byte value

    Args:
        config: SecureCacheConfig with master_key field

    Returns:
        32-byte master key as bytes

    Raises:
        ValueError: If key cannot be resolved or is invalid
    """
    key_ref = config.master_key.get_secret_value()

    # Resolve env:/file:// references
    if key_ref.startswith("env:") or key_ref.startswith("file://"):
        try:
            resolved = resolve_value(
                key_ref,
                field_name="master_key",
                component="secure_cache",
                allowed_base_dirs=ALLOWED_SECRET_DIRS,
            )
        except Exception as e:
            raise ValueError(
                f"Failed to resolve master_key reference '{key_ref}': {e}"
            ) from e
        if not hasattr(resolved, 'get_secret_value'):
            raise ValueError(
                "resolve_value must return a SecretStr for master_key; "
                "check secure_config resolver configuration"
            )
        key_hex = resolved.get_secret_value()
    else:
        key_hex = key_ref

    # Convert hex to bytes
    try:
        master_key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Master key must be hex-encoded")

    if len(master_key) != 32:
        raise ValueError("Master key must be exactly 32 bytes")

    return master_key


@auto_trace(logger)
def _resolve_redis_url(config: SecureCacheConfig) -> str | None:
    """Resolve and validate the Redis URL from config.

    Args:
        config: SecureCacheConfig with optional redis settings.

    Returns:
        Redis URL string if configured, None for in-memory mode.

    Raises:
        ValueError: If redis config exists but url is empty/blank.
    """
    redis_url = config.redis.url.get_secret_value() if config.redis else None
    if config.redis is not None and (not redis_url or not redis_url.strip()):
        raise ValueError("redis.url must be set when redis backend is selected")
    return redis_url


@auto_trace(logger)
def _create_backend(
    config: SecureCacheConfig,
    redis_url: str | None,
    environment: str,
) -> Any:
    """Create the base cache backend (Redis or in-memory).

    Args:
        config: SecureCacheConfig with backend settings.
        redis_url: Redis URL if configured, None for in-memory.
        environment: Deployment environment name (e.g. "development", "production").
            Passed through to InMemoryCacheBackend for production detection.

    Returns:
        Cache backend implementing CacheBackend protocol.
    """
    if redis_url:
        assert config.redis is not None  # guaranteed by _resolve_redis_url
        backend = create_redis_backend(
            default_ttl_seconds=config.default_ttl_seconds,
            pool_size=config.redis.pool_size,
            socket_timeout=config.redis.socket_timeout,
            pool_wait_timeout=config.redis.pool_wait_timeout,
        )
        logger.info("Created RedisCacheBackend")
        return backend

    backend = InMemoryCacheBackend(
        default_ttl_seconds=config.default_ttl_seconds,
        environment=environment,
    )
    logger.info("Created InMemoryCacheBackend")
    return backend


@auto_trace(logger)
def _create_sequence_tracker_if_enabled(
    config: SecureCacheConfig,
    redis_url: str | None,
    security_ns: CacheNamespace,
) -> Any | None:
    """Create SequenceTracker for replay protection if enabled and Redis available.

    Args:
        config: SecureCacheConfig with feature flags.
        redis_url: Redis URL, required for sequence tracking.
        security_ns: Security-domain namespace for key scoping.

    Returns:
        SequenceTracker instance, or None if not enabled/available.
    """
    if not config.features.enable_sequence_tracking:
        return None

    if not redis_url:
        logger.info("Sequence tracking requires redis - skipping")
        return None

    logger.info("Creating SequenceTracker for replay protection")
    try:
        # All Redis connections via gateway
        from neoaxios_secure_cache.gateway import get_gateway

        sequence_redis_client = get_gateway().get_async_client(
            "sequence", decode_responses=False,
        )
        tracker = create_sequence_tracker(
            redis_client=sequence_redis_client,
            namespace=security_ns,
            local_cache_size=SEQUENCE_TRACKER_LOCAL_CACHE_SIZE,
        )
        logger.info("SequenceTracker created successfully")
        return tracker
    except Exception:
        logger.exception("Failed to create SequenceTracker - skipping")
        return None


@auto_trace(logger)
def _create_canary_if_enabled(
    config: SecureCacheConfig,
    redis_url: str | None,
    backend: Any,
    security_ns: CacheNamespace,
    metrics: Any | None = None,
) -> Any | None:
    """Create CanaryMonitor for integrity verification if enabled.

    Args:
        config: SecureCacheConfig with feature flags.
        redis_url: Redis URL, required for canary monitoring.
        backend: Base cache backend to monitor.
        security_ns: Security-domain namespace for key scoping.
        metrics: SecureCacheMetrics instance for Prometheus gauge emission.

    Returns:
        CanaryMonitor instance, or None if not enabled/available.
    """
    if not config.features.enable_canary:
        return None

    if not redis_url:
        logger.info("Canary monitoring requires redis - skipping")
        return None

    logger.info("Creating CanaryMonitor for integrity verification")
    canary_monitor = create_canary_monitor(
        cache=backend,
        tenant_id=config.tenant_id,
        check_interval_seconds=CANARY_CHECK_INTERVAL_SECONDS,
        inline_check_probability=CANARY_INLINE_CHECK_PROBABILITY,
        namespace=security_ns,
        metrics=metrics,
    )
    logger.info(
        "CanaryMonitor created - call 'await cache.canary.start()' to begin monitoring"
    )
    return canary_monitor


@auto_trace(logger)
def _resolve_and_validate_master_key(config: SecureCacheConfig) -> bytes:
    """Resolve master key from config and validate entropy + production source.

    Args:
        config: SecureCacheConfig with master_key and security settings.

    Returns:
        Validated 32-byte master key.

    Raises:
        ValueError: If key fails resolution, entropy check, or production source check.
    """
    master_key = _resolve_master_key(config)

    if not validate_key_material(master_key):
        raise ValueError(
            "Invalid master key: must be 32 bytes with >= 200 bits entropy. "
            "Use secrets.token_bytes(32).hex() to generate a secure key."
        )

    if config.security.validate_production_key_source:
        logger.info("Validating production key source")
        if not _validate_production_key_source(master_key):
            raise ValueError(
                "Master key appears to come from environment variable. "
                "This is insecure in production. Use a secure secret store instead. "
                "Set security.validate_production_key_source=false to override (NOT RECOMMENDED)."
            )

    return master_key


@auto_trace(logger)
def create_secure_cache(
    config: SecureCacheConfig,
    namespace: CacheNamespace,
    environment: str = "",
) -> Any:
    """Create a fully-configured secure cache with all security layers.

    This is the ONLY public instantiation point for secure cache.
    Creates a cache with proper wrapper stacking in Encrypt-then-Sign order:

    Wrapper stacking order:
    1. Base backend (InMemoryBackend or RedisCacheBackend)
    2. EncryptingCacheWrapper (encrypt data at rest)
    3. SigningCacheWrapper (sign encrypted data)

    This order ensures:
    - Plaintext is never exposed to signing layer
    - Signature covers encrypted ciphertext
    - Tampering detection before decryption

    Args:
        config: SecureCacheConfig with all cache settings
        namespace: CacheNamespace for key scoping; a security-domain
            derivative is created internally for security component keys
        environment: Deployment environment name (e.g. "development", "production").
            Passed explicitly to InMemoryCacheBackend for production detection
            (no os.getenv side-channels).

    Returns:
        Fully-configured secure cache implementing CacheBackend protocol

    Raises:
        ValueError: If master_key fails validation (length, entropy)
        ValueError: If master_key appears to come from env var (when validation enabled)
        ValueError: If tenant_id is invalid
        ValueError: If redis url is invalid format
        ValueError: If namespace is None

    Security Requirements:
        - SEC-REQ-03: HKDF key derivation for signing_key and kek
        - SEC-REQ-07: Memory protection via prctl(PR_SET_DUMPABLE, 0)
        - SEC-REQ-07: Production key source validation

    Example:
        from neoaxios_secure_cache import create_secure_cache
        from neoaxios_secure_cache.config import register_cache_config, get_cache_config
        from neoaxios_secure_cache.namespace import CacheNamespace

        # Register config from JSON file
        register_cache_config("/etc/myapp/cache.json")
        config = get_cache_config()
        ns = CacheNamespace(org="myorg", app="myapp", version="v1")

        # Create cache
        cache = create_secure_cache(config, namespace=ns)

        # Start canary monitoring (if enabled)
        if cache.canary:
            await cache.canary.start()

        # Use the cache
        await cache.set("key", "value", ttl_seconds=300)
        value = await cache.get("key")

        # Stop canary monitoring on shutdown
        if cache.canary:
            await cache.canary.stop()
    """
    logger.info("Creating secure cache", config=config.to_safe_dict())

    if namespace is None:
        raise ValueError("namespace cannot be None")

    security_ns = dataclasses.replace(namespace, domain="security")

    # --- Resolve and validate master key ---
    logger.info("Resolving and validating master key")
    master_key = _resolve_and_validate_master_key(config)

    # --- Memory protection (Linux only) ---
    if config.security.enable_memory_protection:
        logger.info("Enabling memory protection")
        protection_enabled = _enable_memory_protection()
        if protection_enabled:
            logger.info("Memory protection enabled successfully")
        else:
            logger.info("Memory protection not available or failed (continuing without it)")

    # --- Derive keys from master key using HKDF ---
    logger.info("Deriving signing key and KEK from master key")
    signing_key = derive_signing_key(master_key)
    kek = derive_kek(master_key)
    logger.debug("Key derivation completed")

    # --- Create backend and security wrappers ---
    redis_url = _resolve_redis_url(config)
    logger.info(f"Creating base backend (redis={'configured' if redis_url else 'None'})")
    backend = _create_backend(config, redis_url, environment)

    logger.info("Stacking security wrappers (Encrypt-then-Sign)")
    sequence_tracker = _create_sequence_tracker_if_enabled(config, redis_url, security_ns)

    # Shared executor for CPU-bound crypto (AES-GCM encrypt/decrypt, HMAC sign/verify).
    # Only create when enough cores exist for thread parallelism to outweigh dispatch
    # overhead. On small VMs (2-3 cores), inline execution is faster than queuing
    # microsecond AES-GCM/HMAC operations through a thread pool.
    cpu_count = os.cpu_count() or CRYPTO_EXECUTOR_FALLBACK_CPUS
    crypto_executor = None
    if cpu_count >= CRYPTO_EXECUTOR_MIN_CORES:
        crypto_executor = ThreadPoolExecutor(
            max_workers=min(cpu_count, CRYPTO_EXECUTOR_MAX_WORKERS),
            thread_name_prefix="sc-crypto",
        )
        atexit.register(crypto_executor.shutdown, wait=False)

    encrypted_backend = create_encrypting_wrapper(
        backend=backend,
        master_key=kek,
        tenant_id=config.tenant_id,
        sequence_tracker=sequence_tracker,
        executor=crypto_executor,
    )
    logger.debug("Wrapped backend with EncryptingCacheWrapper")

    signed_backend = create_signing_wrapper(
        backend=encrypted_backend,
        signing_key=signing_key,
        namespace=security_ns,
        executor=crypto_executor,
    )
    logger.debug("Wrapped backend with SigningCacheWrapper")

    _attach_optional_components(
        signed_backend, config, redis_url, backend, security_ns, sequence_tracker,
    )

    logger.info(
        "Secure cache created successfully",
        backend="redis" if redis_url else "memory",
        tenant_id=config.tenant_id,
        encryption=True,
        signing=True,
        sequence_tracking=signed_backend.sequence_tracker is not None,
        canary=signed_backend.canary is not None,
        metrics=signed_backend.metrics is not None,
    )

    return signed_backend


@auto_trace(logger)
def _attach_optional_components(
    cache: Any,
    config: SecureCacheConfig,
    redis_url: str | None,
    backend: Any,
    security_ns: CacheNamespace,
    sequence_tracker: Any | None,
) -> None:
    """Attach metrics, canary, and sequence tracker to the signed cache backend.

    Args:
        cache: Signed cache backend to attach components to.
        config: SecureCacheConfig with feature flags.
        redis_url: Redis URL if configured.
        backend: Base cache backend (for canary monitoring).
        security_ns: Security-domain namespace.
        sequence_tracker: SequenceTracker instance if enabled.
    """
    metrics = None
    if config.features.enable_metrics:
        logger.info("Creating Prometheus metrics")
        try:
            metrics = create_metrics()
            logger.info("SecureCacheMetrics created successfully")
        except Exception:
            logger.exception("Failed to create metrics - continuing without metrics")

    canary_monitor = _create_canary_if_enabled(config, redis_url, backend, security_ns, metrics)

    cache.metrics = metrics
    cache.canary = canary_monitor
    cache.sequence_tracker = sequence_tracker
