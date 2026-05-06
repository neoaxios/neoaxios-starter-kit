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

"""HMAC-SHA256 signing wrapper for cache integrity.

This module implements SigningCacheWrapper - a decorator that adds HMAC-SHA256
signatures to all cache operations for integrity verification and key obfuscation.

Features:
- HMAC-SHA256 signatures on all cache values
- Timing-safe signature comparison using secrets.compare_digest()
- Cache key obfuscation: HMAC(signing_key, key)[:16].hex()
- Prevents enumeration attacks via Redis SCAN
- Reject and log on signature mismatch

Usage:
    from neoaxios_secure_cache.security.signing import create_signing_wrapper
    from neoaxios_secure_cache.backends.redis import create_redis_backend

    backend = create_redis_backend()
    cache = create_signing_wrapper(backend, signing_key=key_bytes)

    await cache.set("key", "value", ttl_seconds=300)
    value = await cache.get("key")  # Returns None if signature invalid

Implementation Notes:
- Implements CacheBackend protocol
- Delegates to wrapped backend after signature operations
- Uses secrets.compare_digest() for timing-safe comparison
- Obfuscates keys before storage
- Schema version v2 format: {"v": 2, "data": ..., "sig": ...}
- Signature format: HMAC-SHA256(signing_key, obfuscated_key + value_bytes)
- Factory function for 2+ parameter constructors
"""

import asyncio
import hmac
import json
import secrets
from concurrent.futures import Executor
from hashlib import sha256
from typing import Any, Optional

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.namespace import CacheNamespace, KeyTier

logger = get_telemetry(__name__)

# Schema version for signed cache entries
SCHEMA_VERSION = 2

# Legacy prefix index namespace (used when no namespace provided)
_PREFIX_INDEX_NAMESPACE = "__signing_prefix_index__:"


class SigningCacheWrapper:
    """HMAC-SHA256 signing wrapper for cache integrity verification.

    Wraps any CacheBackend to add cryptographic signatures and key obfuscation.
    All cache operations include signature generation/verification using HMAC-SHA256.

    Features:
    - Key obfuscation: HMAC-SHA256(signing_key, key)[:16].hex()
    - Value signing: HMAC-SHA256(signing_key, obfuscated_key + value_bytes)
    - Timing-safe comparison: secrets.compare_digest()
    - Signature mismatch handling: return None, log error (no raise)

    Attributes:
        backend: Wrapped CacheBackend instance
        signing_key: 32-byte signing key for HMAC operations

    Security Requirements:
    - SEC-REQ-01: MUST use secrets.compare_digest() for ALL signature comparisons
    - SEC-REQ-04: Key obfuscation prevents Redis SCAN enumeration

    Example:
        backend = create_redis_backend()
        cache = SigningCacheWrapper(backend, signing_key)
        await cache.set("user:123", {"name": "Alice"}, ttl_seconds=300)
        data = await cache.get("user:123")  # Signature verified
    """

    @auto_trace(logger)
    def __init__(
        self,
        backend: Any,
        signing_key: bytes,
        namespace: CacheNamespace | None = None,
        executor: Optional[Executor] = None,
    ) -> None:
        """Initialize signing wrapper.

        Args:
            backend: CacheBackend instance to wrap
            signing_key: 32-byte key for HMAC signing operations
            namespace: CacheNamespace with domain="security" for prefix index keys
            executor: Optional thread pool executor for offloading CPU-bound
                HMAC operations. When None, HMAC runs inline on the event
                loop (suitable for low-core environments where thread
                dispatch overhead exceeds HMAC execution time).

        Raises:
            ValueError: If signing_key is not 32 bytes
            ValueError: If backend is None

        Note:
            Use create_signing_wrapper() factory function instead of
            direct instantiation.
        """
        if backend is None:
            raise ValueError("backend cannot be None")

        if not isinstance(signing_key, bytes):
            raise ValueError("signing_key must be bytes")

        if len(signing_key) != 32:
            raise ValueError(f"signing_key must be 32 bytes (got {len(signing_key)})")

        self.backend = backend
        self.signing_key = signing_key
        self._namespace = namespace
        self._executor = executor

        logger.info("Initialized SigningCacheWrapper")

    @auto_trace(logger)
    def _obfuscate_key(self, key: str) -> str:
        """Obfuscate cache key using HMAC-SHA256.

        Prevents enumeration attacks via Redis SCAN by obscuring original keys.
        Uses first 16 bytes of HMAC-SHA256(signing_key, key).

        Args:
            key: Original cache key

        Returns:
            Obfuscated key (32 hex characters)

        Security:
            SEC-REQ-04: Key obfuscation prevents Redis SCAN enumeration
        """
        # Note: The obfuscated output is stored directly as the Redis key (registered
        # as perm_cache:{hash} with scope: global in cache-key-registry.yaml).
        # This key CANNOT be namespace-scoped because:
        # 1. Prepending a namespace would defeat anti-enumeration
        # 2. The HMAC input already contains the namespace (implicit isolation)
        # This is an explicit exemption from the namespace-prefix convention
        # used elsewhere in this package.
        key_bytes = key.encode("utf-8")
        mac = hmac.new(self.signing_key, key_bytes, sha256)
        obfuscated = mac.digest()[:16].hex()
        logger.debug(f"Obfuscated key (original length={len(key)})")
        return obfuscated

    @auto_trace(logger)
    def _hash_prefix(self, prefix: str) -> str:
        """Hash a prefix using HMAC-SHA256 for prefix index lookup."""
        prefix_bytes = prefix.encode("utf-8")
        mac = hmac.new(self.signing_key, b"prefix:" + prefix_bytes, sha256)
        return mac.hexdigest()

    @auto_trace(logger)
    def _iter_prefixes(self, key: str) -> list[str]:
        """Generate delimiter-aligned prefixes for a key (ending with ':')."""
        return [key[:i + 1] for i, ch in enumerate(key) if ch == ":"]

    @auto_trace(logger)
    def _prefix_index_key(self, prefix_hash: str, obfuscated_key: str) -> str:
        """Build backend key for prefix index entry."""
        if self._namespace is not None:
            return self._namespace.make_key_at(
                KeyTier.DOMAIN, f"spx:{prefix_hash}:{obfuscated_key}"
            )
        return f"{_PREFIX_INDEX_NAMESPACE}{prefix_hash}:{obfuscated_key}"

    @auto_trace(logger)
    def _sign_value(self, obfuscated_key: str, value_bytes: bytes) -> str:
        """Generate HMAC-SHA256 signature for cache value.

        Signature includes obfuscated key to bind signature to specific cache entry.

        Args:
            obfuscated_key: Obfuscated cache key
            value_bytes: Serialized value to sign

        Returns:
            Hex-encoded HMAC-SHA256 signature (64 hex characters)

        Security:
            Signature format: HMAC-SHA256(signing_key, obfuscated_key + value_bytes)
        """
        message = obfuscated_key.encode("utf-8") + value_bytes
        mac = hmac.new(self.signing_key, message, sha256)
        signature = mac.hexdigest()
        logger.debug(f"Generated signature for value (size={len(value_bytes)} bytes)")
        return signature

    @auto_trace(logger)
    def _verify_signature(
        self, obfuscated_key: str, value_bytes: bytes, expected_sig: str
    ) -> bool:
        """Verify HMAC-SHA256 signature using timing-safe comparison.

        Args:
            obfuscated_key: Obfuscated cache key
            value_bytes: Serialized value that was signed
            expected_sig: Expected signature from cache entry

        Returns:
            True if signature is valid, False otherwise

        Security:
            SEC-REQ-01: Uses secrets.compare_digest() for timing-safe comparison
        """
        actual_sig = self._sign_value(obfuscated_key, value_bytes)

        # SEC-REQ-01: MUST use secrets.compare_digest() for timing-safe comparison
        is_valid = secrets.compare_digest(actual_sig, expected_sig)

        if is_valid:
            logger.debug("Signature verification passed")
        else:
            logger.log_error(
                Exception(
                    f"Signature verification failed for obfuscated_key={obfuscated_key}"
                )
            )

        return is_valid

    @auto_trace(logger)
    async def get(self, key: str) -> Any | None:
        """Retrieve value from cache with signature verification.

        Args:
            key: Original cache key

        Returns:
            Deserialized value if found and signature valid, None otherwise

        Security:
            - Returns None on signature mismatch (doesn't raise exception)
            - Logs signature verification failures
            - Uses timing-safe comparison
        """
        try:
            obfuscated_key = self._obfuscate_key(key)
            signed_entry = await self.backend.get(obfuscated_key)

            if signed_entry is None:
                logger.debug(f"Cache miss for key '{key}'")
                return None

            # Validate schema version
            if not isinstance(signed_entry, dict):
                logger.log_error(
                    Exception(f"Invalid cache entry format for key '{key}': not a dict")
                )
                return None

            schema_version = signed_entry.get("v")
            if schema_version != SCHEMA_VERSION:
                logger.log_error(
                    Exception(
                        f"Invalid schema version for key '{key}': "
                        f"expected {SCHEMA_VERSION}, got {schema_version}"
                    )
                )
                return None

            # Extract data and signature
            data = signed_entry.get("data")
            expected_sig = signed_entry.get("sig")

            if data is None or expected_sig is None:
                logger.log_error(
                    Exception(f"Missing data or signature for key '{key}'")
                )
                return None

            # Serialize data for signature verification
            value_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

            # Verify signature (timing-safe comparison) — offload to executor when available
            if self._executor is not None:
                loop = asyncio.get_running_loop()
                valid = await loop.run_in_executor(
                    self._executor, self._verify_signature,
                    obfuscated_key, value_bytes, expected_sig,
                )
            else:
                valid = self._verify_signature(obfuscated_key, value_bytes, expected_sig)
            if not valid:
                # Signature mismatch - return None, don't raise
                logger.log_error(
                    Exception(f"Signature mismatch for key '{key}' - rejecting entry")
                )
                return None

            logger.debug(f"Cache hit for key '{key}' (signature verified)")
            return data

        except Exception as e:
            logger.log_error(Exception(f"Error retrieving key '{key}': {e}"))
            return None

    @auto_trace(logger)
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value in cache with HMAC-SHA256 signature.

        Also populates the backend prefix index to support prefix-based
        invalidation through obfuscated keys.

        Args:
            key: Original cache key
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time-to-live in seconds

        Raises:
            Exception: If storage fails

        Security:
            - Generates signature: HMAC-SHA256(signing_key, obfuscated_key + value_bytes)
            - Stores schema v2 format: {"v": 2, "data": ..., "sig": ...}
        """
        try:
            obfuscated_key = self._obfuscate_key(key)

            # Serialize value for signing
            value_bytes = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

            # Generate signature — offload HMAC to executor when available
            if self._executor is not None:
                loop = asyncio.get_running_loop()
                signature = await loop.run_in_executor(
                    self._executor, self._sign_value, obfuscated_key, value_bytes,
                )
            else:
                signature = self._sign_value(obfuscated_key, value_bytes)

            # Create signed entry (schema v2)
            signed_entry = {
                "v": SCHEMA_VERSION,
                "data": value,
                "sig": signature,
            }

            # Store in backend
            await self.backend.set(obfuscated_key, signed_entry, ttl_seconds)

            # Persist prefix index entries for cross-process invalidation
            prefixes = self._iter_prefixes(key)
            for prefix in prefixes:
                prefix_hash = self._hash_prefix(prefix)
                index_key = self._prefix_index_key(prefix_hash, obfuscated_key)
                try:
                    await self.backend.set(index_key, 1, ttl_seconds)
                except Exception as e:
                    logger.warning(
                        f"Failed to write prefix index key '{index_key}': {e}"
                    )

            logger.debug(f"Cached key '{key}' with signature (TTL={ttl_seconds}s)")

        except Exception as e:
            logger.log_error(Exception(f"Error storing key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def delete(self, key: str) -> None:
        """Remove key from cache.

        Args:
            key: Original cache key to remove

        Raises:
            Exception: If deletion fails
        """
        try:
            obfuscated_key = self._obfuscate_key(key)
            await self.backend.delete(obfuscated_key)

            # Remove prefix index entries (best effort)
            prefixes = self._iter_prefixes(key)
            for prefix in prefixes:
                prefix_hash = self._hash_prefix(prefix)
                index_key = self._prefix_index_key(prefix_hash, obfuscated_key)
                try:
                    await self.backend.delete(index_key)
                except Exception as e:
                    logger.warning(
                        f"Failed to delete prefix index key '{index_key}': {e}"
                    )

            logger.debug(f"Deleted key '{key}'")
        except Exception as e:
            logger.log_error(Exception(f"Error deleting key '{key}': {e}"))
            raise

    @auto_trace(logger)
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Original cache key to check

        Returns:
            True if key exists, False otherwise

        Warning:
            This method does NOT verify signatures. Use get() to verify integrity.
        """
        try:
            obfuscated_key = self._obfuscate_key(key)
            result = await self.backend.exists(obfuscated_key)
            return result
        except Exception as e:
            logger.log_error(Exception(f"Error checking existence of key '{key}': {e}"))
            return False

    @auto_trace(logger)
    async def mget(self, keys: list[str]) -> list[Any | None]:
        """Retrieve multiple values from cache with signature verification.

        Obfuscates all keys, delegates to the wrapped backend's mget(),
        then verifies signatures on all results. Individual signature
        failures return None at that position without failing the batch.

        Args:
            keys: List of original cache keys

        Returns:
            List aligned with input keys; None for missing or invalid entries

        Security:
            - Each entry is independently verified (one failure does not
              affect other positions)
            - Returns None on signature mismatch per entry (no raise)
            - Uses timing-safe comparison via _verify_signature()
        """
        if not keys:
            return []

        # Obfuscate all keys
        obfuscated_keys = [self._obfuscate_key(key) for key in keys]

        # Batch fetch from backend
        signed_entries = await self.backend.mget(obfuscated_keys)

        # Verify signatures on each result independently
        results: list[Any | None] = []
        for i, signed_entry in enumerate(signed_entries):
            try:
                if signed_entry is None:
                    logger.debug(f"Cache miss for key '{keys[i]}'")
                    results.append(None)
                    continue

                # Validate schema version
                if not isinstance(signed_entry, dict):
                    logger.log_error(
                        Exception(
                            f"Invalid cache entry format for key '{keys[i]}': not a dict"
                        )
                    )
                    results.append(None)
                    continue

                schema_version = signed_entry.get("v")
                if schema_version != SCHEMA_VERSION:
                    logger.log_error(
                        Exception(
                            f"Invalid schema version for key '{keys[i]}': "
                            f"expected {SCHEMA_VERSION}, got {schema_version}"
                        )
                    )
                    results.append(None)
                    continue

                # Extract data and signature
                data = signed_entry.get("data")
                expected_sig = signed_entry.get("sig")

                if data is None or expected_sig is None:
                    logger.log_error(
                        Exception(f"Missing data or signature for key '{keys[i]}'")
                    )
                    results.append(None)
                    continue

                # Serialize data for signature verification
                value_bytes = json.dumps(
                    data, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")

                # Verify signature (timing-safe comparison)
                if not self._verify_signature(
                    obfuscated_keys[i], value_bytes, expected_sig
                ):
                    logger.log_error(
                        Exception(
                            f"Signature mismatch for key '{keys[i]}' - rejecting entry"
                        )
                    )
                    results.append(None)
                    continue

                logger.debug(f"Cache hit for key '{keys[i]}' (signature verified)")
                results.append(data)

            except Exception as e:
                logger.log_error(
                    Exception(f"Error verifying key '{keys[i]}': {e}")
                )
                results.append(None)

        return results

    @auto_trace(logger)
    async def mset(self, items: list[tuple[str, Any, int]]) -> None:
        """Store multiple values in cache with HMAC-SHA256 signatures.

        For each (key, value, ttl_seconds) tuple: obfuscates the key,
        signs the value, builds the schema v2 envelope, then delegates
        all items to the wrapped backend's mset() in a single batch call.
        Prefix index entries are written afterward for each key.

        Args:
            items: List of (key, value, ttl_seconds) tuples to store

        Raises:
            Exception: If backend mset fails

        Security:
            - Each value is signed with HMAC-SHA256(signing_key, obfuscated_key + value_bytes)
            - Stores schema v2 format: {"v": 2, "data": ..., "sig": ...}
        """
        if not items:
            return

        # Build signed items for backend batch call
        signed_items: list[tuple[str, dict, int]] = []
        # Track original keys and their obfuscated counterparts for prefix indexing
        key_pairs: list[tuple[str, str, int]] = []

        for key, value, ttl_seconds in items:
            obfuscated_key = self._obfuscate_key(key)

            # Serialize value for signing
            value_bytes = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

            # Generate signature
            signature = self._sign_value(obfuscated_key, value_bytes)

            # Create signed entry (schema v2)
            signed_entry = {
                "v": SCHEMA_VERSION,
                "data": value,
                "sig": signature,
            }

            signed_items.append((obfuscated_key, signed_entry, ttl_seconds))
            key_pairs.append((key, obfuscated_key, ttl_seconds))

        # Batch store in backend
        await self.backend.mset(signed_items)

        # Persist prefix index entries for cross-process invalidation
        for key, obfuscated_key, ttl_seconds in key_pairs:
            prefixes = self._iter_prefixes(key)
            for prefix in prefixes:
                prefix_hash = self._hash_prefix(prefix)
                index_key = self._prefix_index_key(prefix_hash, obfuscated_key)
                try:
                    await self.backend.set(index_key, 1, ttl_seconds)
                except Exception as e:
                    logger.warning(
                        f"Failed to write prefix index key '{index_key}': {e}"
                    )

        logger.debug(f"Batch cached {len(items)} keys with signatures")

    @auto_trace(logger)
    async def mdelete(self, keys: list[str]) -> int:
        """Remove multiple keys from cache.

        Obfuscates all keys, delegates to the wrapped backend's mdelete(),
        then removes prefix index entries for each key (best effort).

        Args:
            keys: List of original cache keys to remove

        Returns:
            Count of keys successfully deleted by the backend
        """
        if not keys:
            return 0

        # Obfuscate all keys and track pairs for prefix index cleanup
        obfuscated_keys = []
        key_pairs: list[tuple[str, str]] = []
        for key in keys:
            obfuscated_key = self._obfuscate_key(key)
            obfuscated_keys.append(obfuscated_key)
            key_pairs.append((key, obfuscated_key))

        # Batch delete from backend
        deleted_count = await self.backend.mdelete(obfuscated_keys)

        # Remove prefix index entries (best effort)
        for key, obfuscated_key in key_pairs:
            prefixes = self._iter_prefixes(key)
            for prefix in prefixes:
                prefix_hash = self._hash_prefix(prefix)
                index_key = self._prefix_index_key(prefix_hash, obfuscated_key)
                try:
                    await self.backend.delete(index_key)
                except Exception as e:
                    logger.warning(
                        f"Failed to delete prefix index key '{index_key}': {e}"
                    )

        logger.debug(f"Batch deleted {deleted_count} keys")
        return deleted_count

    @auto_trace(logger)
    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries whose original keys match a given prefix.

        Since SigningCacheWrapper obfuscates keys via HMAC, naive prefix matching
        on the backend is impossible. This method uses a hashed-prefix index
        stored in the backend to find matching obfuscated keys across processes.

        Invalidation depends on the backend prefix index. If index entries are
        missing or unavailable, no keys will be removed.

        Args:
            prefix: Original key prefix to match (must end with ":", e.g., "user:123:")

        Returns:
            Number of entries successfully removed

        Raises:
            Exception: If backend deletion fails (no silent swallowing)
            ValueError: If prefix does not end with ":" (delimiter-aligned)
        """
        if not prefix.endswith(":"):
            raise ValueError("prefix must end with ':' for SigningCacheWrapper invalidation")
        prefix_hash = self._hash_prefix(prefix)
        if self._namespace is not None:
            index_prefix = self._namespace.make_key_at(
                KeyTier.DOMAIN, f"spx:{prefix_hash}:"
            )
        else:
            index_prefix = f"{_PREFIX_INDEX_NAMESPACE}{prefix_hash}:"

        # Find all index entries for this prefix
        index_keys = await self.backend.keys_by_prefix(index_prefix)
        if not index_keys:
            logger.record_metric("cache.invalidate_by_prefix.index_miss", 1)
            return 0

        obfuscated_keys = [
            key[len(index_prefix):]
            for key in index_keys
            if key.startswith(index_prefix)
        ]

        deleted_count = 0
        try:
            for obfuscated_key in obfuscated_keys:
                await self.backend.delete(obfuscated_key)
                deleted_count += 1
        except Exception:
            raise

        # Remove index entries after deletes succeed
        for index_key in index_keys:
            await self.backend.delete(index_key)

        logger.record_metric("cache.invalidate_by_prefix.count", deleted_count)
        logger.debug(
            f"Invalidated {deleted_count} keys matching prefix '{prefix}'"
        )
        return deleted_count


@auto_trace(logger)
def create_signing_wrapper(
    backend: Any,
    signing_key: bytes,
    namespace: CacheNamespace | None = None,
    executor: Optional[Executor] = None,
) -> SigningCacheWrapper:
    """Factory function for SigningCacheWrapper.

    Creates a SigningCacheWrapper instance with validated parameters.
    Required for objects with 2+ constructor parameters.

    Args:
        backend: CacheBackend instance to wrap
        signing_key: 32-byte key for HMAC signing operations
        namespace: CacheNamespace with domain="security" for prefix index keys
        executor: Optional thread pool executor for offloading CPU-bound
            HMAC operations. When None, HMAC runs inline on the event loop.

    Returns:
        Configured SigningCacheWrapper instance

    Raises:
        ValueError: If backend is None
        ValueError: If signing_key is not 32 bytes

    Example:
        from neoaxios_secure_cache.security.keys import derive_signing_key
        from neoaxios_secure_cache.backends.redis import create_redis_backend

        master_key = secrets.token_bytes(32)
        signing_key = derive_signing_key(master_key)

        backend = create_redis_backend()
        cache = create_signing_wrapper(backend, signing_key, namespace=security_ns)

        await cache.set("user:123", {"name": "Alice"}, ttl_seconds=300)
        data = await cache.get("user:123")
    """
    # Validate backend
    if backend is None:
        raise ValueError("backend cannot be None")

    # Validate signing_key
    if not isinstance(signing_key, bytes):
        raise ValueError("signing_key must be bytes")

    if len(signing_key) != 32:
        raise ValueError(f"signing_key must be 32 bytes (got {len(signing_key)})")

    return SigningCacheWrapper(
        backend=backend, signing_key=signing_key, namespace=namespace,
        executor=executor,
    )
