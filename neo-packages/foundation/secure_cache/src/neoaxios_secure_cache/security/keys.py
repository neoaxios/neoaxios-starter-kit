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

"""Key derivation and management for cache encryption.

This module provides key derivation using HKDF and LRU caching for per-tenant keys.

Components:
- validate_key_material: Validates 32-byte keys with 200-bit entropy minimum
- validate_tenant_id: Validates tenant ID as UTF-8, no null bytes, non-empty
- derive_signing_key: HKDF derivation for HMAC signing
- derive_kek: HKDF derivation for key encryption key
- TenantKeyCache: LRU cache for derived tenant keys (max 1000 entries)
- derive_tenant_key: HKDF derivation with tenant_id in info
- get_or_create_tenant_salt: Atomic Redis salt creation via SET NX

Usage:
    from neoaxios_secure_cache.security.keys import (
        validate_key_material,
        validate_tenant_id,
        derive_signing_key,
        derive_kek,
        TenantKeyCache,
        derive_tenant_key,
        get_or_create_tenant_salt,
    )

    # Validate master key
    if not validate_key_material(master_key_bytes):
        raise ValueError("Invalid key material")

    # Derive keys from master key
    signing_key = derive_signing_key(master_key_bytes)
    kek = derive_kek(master_key_bytes)

    # Derive tenant-specific key
    tenant_key = derive_tenant_key(kek, "tenant-123")

    # Get or create tenant salt atomically (namespace required)
    salt = await get_or_create_tenant_salt(redis_client, "tenant-123", namespace)

Implementation Notes:
- HKDF parameters are LOCKED per SEC-REQ-03:
  * Algorithm: SHA-256
  * Length: 32 bytes
  * Salt: None for all derivations
  * Signing key info: b"secure-cache:v1:sign"
  * KEK info: b"secure-cache:v1:kek"
  * Tenant key info: b"secure-cache:v1:tenant:" + tenant_id.encode('utf-8')
- Tenant salts stored in Redis: tenant:{tenant_id}:salt
- Atomic salt creation via SET NX (SEC-REQ-06)
- Key material validation: length=32 bytes, entropy >= 200 bits
- Zlib compression ratio heuristic for entropy validation
- Tenant ID validation before HKDF (SEC-REQ-08)
"""

import secrets
import zlib
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import TENANT_KEY_CACHE_SIZE
from neoaxios_secure_cache.namespace import CacheNamespace, KeyTier

logger = get_telemetry(__name__)

# LOCKED HKDF PARAMETERS (DO NOT MODIFY - SEC-REQ-03)
HKDF_ALGORITHM = hashes.SHA256()
HKDF_LENGTH = 32
HKDF_SALT = None

# LOCKED INFO STRINGS (DO NOT MODIFY - SEC-REQ-03)
SIGNING_KEY_INFO = b"secure-cache:v1:sign"
KEK_INFO = b"secure-cache:v1:kek"
TENANT_KEY_INFO_PREFIX = b"secure-cache:v1:tenant:"

# Validation thresholds
KEY_LENGTH_BYTES = 32
MIN_ENTROPY_BITS = 200


@auto_trace(logger)
def validate_key_material(key: bytes) -> bool:
    """Validate key material for cryptographic use.

    Validates that key material meets security requirements:
    - Exactly 32 bytes in length
    - Minimum 200 bits of entropy (using zlib compression heuristic)

    Args:
        key: Raw key material to validate

    Returns:
        True if key meets validation requirements, False otherwise

    Examples:
        >>> valid_key = secrets.token_bytes(32)
        >>> validate_key_material(valid_key)
        True
        >>> validate_key_material(b"\\x00" * 32)  # All zeros
        False
        >>> validate_key_material(b"abc")  # Too short
        False
    """
    # Check length
    if not isinstance(key, bytes):
        logger.info("Key validation failed: not bytes type")
        return False

    if len(key) != KEY_LENGTH_BYTES:
        logger.info(
            f"Key validation failed: length={len(key)}, expected={KEY_LENGTH_BYTES}"
        )
        return False

    # Estimate entropy using zlib compression ratio
    # High entropy data compresses poorly
    # If data compresses by more than 50%, it likely has low entropy
    compressed = zlib.compress(key, level=9)
    compression_ratio = len(compressed) / len(key)

    # For 32 bytes with 200 bits entropy:
    # Expected compression ratio > 0.78 (200/256 = 0.78125)
    # We use 0.75 as threshold to account for compression overhead
    min_ratio = MIN_ENTROPY_BITS / (KEY_LENGTH_BYTES * 8)
    threshold = min_ratio - 0.03  # Small margin for compression overhead

    if compression_ratio < threshold:
        logger.info(
            f"Key validation failed: low entropy detected "
            f"(compression_ratio={compression_ratio:.3f}, threshold={threshold:.3f})"
        )
        return False

    logger.debug("Key validation passed")
    return True


@auto_trace(logger)
def validate_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID for use in key derivation.

    Validates that tenant ID meets security requirements:
    - Non-empty string
    - Valid UTF-8 encoding
    - No null bytes (security risk in C libraries)

    Args:
        tenant_id: Tenant identifier to validate

    Returns:
        True if tenant_id meets validation requirements, False otherwise

    Examples:
        >>> validate_tenant_id("tenant-123")
        True
        >>> validate_tenant_id("")
        False
        >>> validate_tenant_id("tenant\\x00malicious")
        False
    """
    # Check type and non-empty
    if not isinstance(tenant_id, str):
        logger.info("Tenant ID validation failed: not string type")
        return False

    if not tenant_id:
        logger.info("Tenant ID validation failed: empty string")
        return False

    # Check for null bytes
    if "\x00" in tenant_id:
        logger.info("Tenant ID validation failed: contains null byte")
        return False

    # Validate UTF-8 encoding
    try:
        tenant_id.encode("utf-8")
    except UnicodeEncodeError as e:  # pragma: no cover
        # Unreachable in Python 3 (all str objects are valid Unicode)
        # Kept for defensive programming and future compatibility
        logger.info(f"Tenant ID validation failed: invalid UTF-8 encoding: {e}")
        return False

    logger.debug(f"Tenant ID validation passed: {tenant_id}")
    return True


def _hkdf_derive(master_key: bytes, info: bytes) -> bytes:
    """Derive a key from master key using HKDF-SHA256 with LOCKED parameters."""
    kdf = HKDF(
        algorithm=HKDF_ALGORITHM,
        length=HKDF_LENGTH,
        salt=HKDF_SALT,
        info=info,
    )
    return kdf.derive(master_key)


@auto_trace(logger)
def derive_signing_key(master_key: bytes) -> bytes:
    """Derive HMAC signing key from master key using HKDF.

    Uses HKDF-SHA256 with LOCKED parameters:
    - Algorithm: SHA-256
    - Length: 32 bytes
    - Salt: None
    - Info: b"secure-cache:v1:sign"

    Args:
        master_key: Master key material (must be 32 bytes with 200+ bit entropy)

    Returns:
        Derived 32-byte signing key

    Raises:
        ValueError: If master_key fails validation

    Examples:
        >>> master_key = secrets.token_bytes(32)
        >>> signing_key = derive_signing_key(master_key)
        >>> len(signing_key)
        32
    """
    if not validate_key_material(master_key):
        raise ValueError("Invalid master key material")

    derived_key = _hkdf_derive(master_key, SIGNING_KEY_INFO)

    logger.debug("Derived signing key from master key")
    return derived_key


@auto_trace(logger)
def derive_kek(master_key: bytes) -> bytes:
    """Derive Key Encryption Key (KEK) from master key using HKDF.

    Uses HKDF-SHA256 with LOCKED parameters:
    - Algorithm: SHA-256
    - Length: 32 bytes
    - Salt: None
    - Info: b"secure-cache:v1:kek"

    Args:
        master_key: Master key material (must be 32 bytes with 200+ bit entropy)

    Returns:
        Derived 32-byte KEK

    Raises:
        ValueError: If master_key fails validation

    Examples:
        >>> master_key = secrets.token_bytes(32)
        >>> kek = derive_kek(master_key)
        >>> len(kek)
        32
    """
    if not validate_key_material(master_key):
        raise ValueError("Invalid master key material")

    derived_key = _hkdf_derive(master_key, KEK_INFO)

    logger.debug("Derived KEK from master key")
    return derived_key


@auto_trace(logger)
def derive_tenant_key(master_key: bytes, tenant_id: str) -> bytes:
    """Derive tenant-specific key using HKDF with tenant_id in info.

    Uses HKDF-SHA256 with LOCKED parameters:
    - Algorithm: SHA-256
    - Length: 32 bytes
    - Salt: None
    - Info: b"secure-cache:v1:tenant:" + tenant_id.encode('utf-8')

    Args:
        master_key: Master key material (must be 32 bytes with 200+ bit entropy)
        tenant_id: Tenant identifier (validated for UTF-8, no null bytes, non-empty)

    Returns:
        Derived 32-byte tenant-specific key

    Raises:
        ValueError: If master_key fails validation
        ValueError: If tenant_id fails validation

    Examples:
        >>> master_key = secrets.token_bytes(32)
        >>> tenant_key = derive_tenant_key(master_key, "tenant-123")
        >>> len(tenant_key)
        32
    """
    if not validate_key_material(master_key):
        raise ValueError("Invalid master key material")

    if not validate_tenant_id(tenant_id):
        raise ValueError("Invalid tenant_id")

    # Construct tenant-specific info string
    tenant_info = TENANT_KEY_INFO_PREFIX + tenant_id.encode("utf-8")

    derived_key = _hkdf_derive(master_key, tenant_info)

    logger.debug(f"Derived tenant key for tenant_id={tenant_id}")
    return derived_key


class TenantKeyCache:
    """LRU cache for derived tenant keys.

    Caches tenant-specific keys to avoid re-deriving on every operation.
    Uses functools.lru_cache with maximum 1000 entries.

    Attributes:
        master_key: Master key for derivation
        max_size: Maximum cache entries (default: 1000)

    Examples:
        >>> master_key = secrets.token_bytes(32)
        >>> cache = TenantKeyCache(master_key, max_size=1000)
        >>> key1 = cache.get_tenant_key("tenant-123")
        >>> key2 = cache.get_tenant_key("tenant-123")  # Cached
        >>> key1 == key2
        True
        >>> cache.clear()
    """

    @auto_trace(logger)
    def __init__(self, master_key: bytes, max_size: int = TENANT_KEY_CACHE_SIZE) -> None:
        """Initialize tenant key cache.

        Args:
            master_key: Master key for derivation (must be 32 bytes with 200+ bit entropy)
            max_size: Maximum cache entries (default: 1000)

        Raises:
            ValueError: If master_key fails validation
            ValueError: If max_size is not positive
        """
        if not validate_key_material(master_key):
            raise ValueError("Invalid master key material")

        if max_size <= 0:
            raise ValueError(f"max_size must be positive (got: {max_size})")

        self._master_key = master_key
        self.max_size = max_size

        # Create LRU-cached derivation function
        @lru_cache(maxsize=max_size)
        def _cached_derive(tenant_id: str) -> bytes:
            return derive_tenant_key(self._master_key, tenant_id)

        self._cached_derive = _cached_derive

        logger.info(f"Initialized TenantKeyCache with max_size={max_size}")

    @auto_trace(logger)
    def get_tenant_key(self, tenant_id: str) -> bytes:
        """Get or derive tenant-specific key.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Derived 32-byte tenant-specific key (cached or newly derived)

        Raises:
            ValueError: If tenant_id fails validation
        """
        if not validate_tenant_id(tenant_id):
            raise ValueError("Invalid tenant_id")

        tenant_key = self._cached_derive(tenant_id)
        logger.debug(f"Retrieved tenant key for tenant_id={tenant_id}")
        return tenant_key

    @auto_trace(logger)
    def clear(self) -> None:
        """Clear all cached tenant keys."""
        self._cached_derive.cache_clear()
        logger.info("Cleared tenant key cache")

    @auto_trace(logger)
    def cache_info(self) -> Any:
        """Get cache statistics.

        Returns:
            Cache info tuple (hits, misses, maxsize, currsize)
        """
        return self._cached_derive.cache_info()


@auto_trace(logger)
async def get_or_create_tenant_salt(
    redis_client: Any,
    tenant_id: str,
    namespace: CacheNamespace,
) -> bytes:
    """Get or atomically create tenant salt in Redis.

    Uses Redis SET NX (set if not exists) for atomic salt creation.
    The key is namespaced via make_key_at().

    Args:
        redis_client: Async Redis client obtained from the gateway
            (``get_gateway().get_async_client("security")``).
        tenant_id: Tenant identifier
        namespace: CacheNamespace with domain="security" for key prefixing

    Returns:
        32-byte tenant salt (existing or newly created)

    Raises:
        ValueError: If tenant_id fails validation or namespace is None
        Exception: If Redis operation fails

    Examples:
        >>> from secure_cache.gateway import get_gateway
        >>> client = get_gateway().get_async_client("security")
        >>> salt1 = await get_or_create_tenant_salt(client, "tenant-123", ns)
        >>> salt2 = await get_or_create_tenant_salt(client, "tenant-123", ns)
        >>> salt1 == salt2  # Same salt
        True
    """
    if not validate_tenant_id(tenant_id):
        raise ValueError("Invalid tenant_id")

    if namespace is None:
        raise ValueError("namespace is required")

    salt_key = namespace.make_key_at(KeyTier.DOMAIN, f"tenant_salt:{tenant_id}")

    try:
        # Try to get existing salt
        existing_salt = await redis_client.get(salt_key)

        if existing_salt is not None:
            # Redis returns string with decode_responses=True, convert to bytes
            if isinstance(existing_salt, str):
                salt_bytes = bytes.fromhex(existing_salt)
            else:
                salt_bytes = existing_salt

            logger.debug(f"Retrieved existing salt for tenant_id={tenant_id}")
            return salt_bytes

        # Generate new salt
        new_salt = secrets.token_bytes(32)
        new_salt_hex = new_salt.hex()

        # Atomic SET NX (set if not exists)
        # Returns True if key was set, False if key already exists
        was_set = await redis_client.set(salt_key, new_salt_hex, nx=True)

        if was_set:
            logger.info(f"Created new salt for tenant_id={tenant_id}")
            return new_salt
        else:
            # Another process created the salt concurrently, retrieve it
            existing_salt = await redis_client.get(salt_key)
            if existing_salt is None:
                # Extremely rare race condition - key expired between SET NX and GET
                raise Exception(
                    f"Salt key {salt_key} disappeared after SET NX failed"
                )

            if isinstance(existing_salt, str):
                salt_bytes = bytes.fromhex(existing_salt)
            else:
                salt_bytes = existing_salt

            logger.debug(
                f"Retrieved salt created by concurrent process for tenant_id={tenant_id}"
            )
            return salt_bytes

    except Exception as e:
        logger.log_error(
            Exception(f"Redis operation failed for tenant salt: {e}")
        )
        raise


@auto_trace(logger)
def create_tenant_key_cache(
    master_key: bytes,
    max_size: int = TENANT_KEY_CACHE_SIZE,
) -> TenantKeyCache:
    """Factory function for TenantKeyCache.

    Creates a TenantKeyCache instance with validated parameters.
    Provided for consistency with other security components.

    Args:
        master_key: Master key for derivation (must be 32 bytes with 200+ bit entropy)
        max_size: Maximum cache entries (default: 1000)

    Returns:
        Configured TenantKeyCache instance

    Raises:
        ValueError: If master_key fails validation
        ValueError: If max_size is not positive

    Example:
        cache = create_tenant_key_cache(
            master_key=secrets.token_bytes(32),
            max_size=1000,
        )
    """
    return TenantKeyCache(
        master_key=master_key,
        max_size=max_size,
    )
