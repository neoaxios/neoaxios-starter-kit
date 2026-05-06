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

"""AES-256-GCM encryption wrapper for cache confidentiality.

This module implements EncryptingCacheWrapper - a decorator that adds AES-256-GCM
encryption to all cache operations with per-tenant key derivation.

Features:
- AES-256-GCM authenticated encryption
- Fresh IV per write: secrets.token_bytes(12) generated INSIDE _encrypt()
- Per-tenant key derivation via HKDF
- Authentication tag verification
- Tenant isolation via derive_tenant_key()
- Schema versioning with automatic v1 -> v2 migration

Usage:
    from neoaxios_secure_cache.security.encryption import create_encrypting_wrapper
    from neoaxios_secure_cache.backends.redis import create_redis_backend

    backend = create_redis_backend(
        default_ttl_seconds=300,
    )

    cache = create_encrypting_wrapper(
        backend=backend,
        master_key=master_key_bytes,
        tenant_id="tenant-123",
    )

    await cache.set("key", "value", ttl_seconds=300)
    value = await cache.get("key")  # Returns None if decryption fails

Implementation Notes:
- Implements CacheBackend protocol
- Derives tenant key via HKDF with tenant_id in info parameter (SEC-REQ-03)
- Generates IV inside _encrypt() - never passed as parameter (SEC-REQ-05)
- Schema versioning:
  - v1 format (legacy): {"data": "plaintext_value"} - detected by absence of "v" key
  - v2 format: {"v": 2, "iv": base64, "ct": base64, "tag": base64, "seq": int}
- Fresh IV per write using secrets.token_bytes(12) (SEC-REQ-02)
- Uses cryptography library for AES-256-GCM
"""

import asyncio
import base64
import json
import secrets
from concurrent.futures import Executor
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.security.keys import derive_tenant_key

logger = get_telemetry(__name__)

# Encryption parameters
IV_LENGTH_BYTES = 12  # GCM standard nonce size
KEY_LENGTH_BYTES = 32  # AES-256
SCHEMA_VERSION = 2


class EncryptingCacheWrapper:
    """AES-256-GCM encryption wrapper for cache backends.

    Wraps any CacheBackend implementation to add transparent encryption/decryption
    using AES-256-GCM with per-tenant key derivation. Each write generates a fresh
    IV using secrets.token_bytes(12) inside the _encrypt() method.

    Supports schema versioning:
    - v1 (legacy): Plaintext JSON format {"data": "value"} - read-only
    - v2 (current): Encrypted format {"v": 2, "iv": ..., "ct": ..., "tag": ..., "seq": ...}

    Attributes:
        backend: Wrapped cache backend (implements CacheBackend protocol)
        master_key: Master key for tenant key derivation (32 bytes)
        tenant_id: Tenant identifier for key derivation
        sequence_tracker: Optional SequenceTracker for replay protection

    Example:
        backend = create_redis_backend()
        cache = EncryptingCacheWrapper(
            backend=backend,
            master_key=secrets.token_bytes(32),
            tenant_id="tenant-123",
        )
        await cache.set("key", "value", ttl_seconds=300)
        value = await cache.get("key")
    """

    @auto_trace(logger)
    def __init__(
        self,
        backend: Any,
        master_key: bytes,
        tenant_id: str,
        sequence_tracker: Optional[Any] = None,
        executor: Optional[Executor] = None,
    ) -> None:
        """Initialize encrypting cache wrapper.

        Args:
            backend: Cache backend to wrap (implements CacheBackend protocol)
            master_key: Master key for tenant key derivation (must be 32 bytes)
            tenant_id: Tenant identifier for key derivation
            sequence_tracker: Optional SequenceTracker for replay protection
            executor: Optional thread pool executor for offloading CPU-bound
                crypto operations. When None, crypto runs inline on the
                event loop (suitable for low-core environments where thread
                dispatch overhead exceeds AES-GCM execution time).

        Raises:
            ValueError: If master_key is invalid
            ValueError: If tenant_id is invalid
        """
        # Derive tenant-specific key using HKDF
        # This validates both master_key and tenant_id
        tenant_key = derive_tenant_key(master_key, tenant_id)

        self.backend = backend
        self.master_key = master_key
        self.tenant_id = tenant_id
        self.sequence_tracker = sequence_tracker
        self._tenant_key = tenant_key
        self._aesgcm = AESGCM(tenant_key)
        self._executor = executor

        logger.info(
            f"Initialized EncryptingCacheWrapper for tenant_id={tenant_id} "
            f"with sequence_tracker={sequence_tracker is not None}"
        )

    def _encrypt_core(self, plaintext: str) -> dict:
        """Synchronous encryption core — CPU-bound, safe to run in executor.

        Generates a fresh IV, encrypts plaintext with AES-256-GCM, and returns
        the v2 envelope *without* the sequence number (which requires async I/O).

        CRITICAL: IV is generated INSIDE this method using secrets.token_bytes(12).
        It is NEVER passed as a parameter (SEC-REQ-05).

        Args:
            plaintext: String to encrypt.

        Returns:
            Dictionary with encrypted data (v2 format, no ``seq`` key):
            {
                "v": 2,
                "iv": base64-encoded IV (12 bytes),
                "ct": base64-encoded ciphertext,
                "tag": base64-encoded authentication tag (16 bytes),
            }
        """
        # Generate fresh IV INSIDE encrypt method (SEC-REQ-05)
        iv = secrets.token_bytes(IV_LENGTH_BYTES)

        # Encode plaintext to bytes
        plaintext_bytes = plaintext.encode("utf-8")

        # Encrypt with AESGCM (includes authentication tag in output)
        # ciphertext_and_tag = ciphertext || tag (tag is last 16 bytes)
        ciphertext_and_tag = self._aesgcm.encrypt(iv, plaintext_bytes, None)

        # Split ciphertext and tag
        # GCM tag is always 16 bytes (128 bits) and appended at the end
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        # Build v2 encrypted envelope
        return {
            "v": SCHEMA_VERSION,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
        }

    @auto_trace(logger)
    async def _encrypt(self, plaintext: str, user_id: Optional[str] = None) -> dict:
        """Encrypt plaintext using AES-256-GCM with fresh IV.

        CRITICAL: IV is generated INSIDE this method using secrets.token_bytes(12).
        It is NEVER passed as a parameter (SEC-REQ-05).

        When an executor is provided, offloads the CPU-bound AES-GCM encryption
        to a thread pool. When no executor is provided, runs inline on the event
        loop (AES-GCM is microseconds, so inline avoids thread dispatch overhead).

        Args:
            plaintext: String to encrypt
            user_id: Optional user ID for sequence tracking

        Returns:
            Dictionary with encrypted data (v2 format):
            {
                "v": 2,
                "iv": base64-encoded IV (12 bytes),
                "ct": base64-encoded ciphertext,
                "tag": base64-encoded authentication tag (16 bytes),
                "seq": sequence number (if sequence_tracker provided)
            }

        Note:
            - Fresh IV generated per encryption (SEC-REQ-02)
            - IV generation is atomic and internal to this method
            - Uses AESGCM.encrypt() which includes authentication tag in output
            - Sequence number added if sequence_tracker available
        """
        if self._executor is not None:
            loop = asyncio.get_running_loop()
            encrypted_data = await loop.run_in_executor(
                self._executor, self._encrypt_core, plaintext,
            )
        else:
            encrypted_data = self._encrypt_core(plaintext)

        # Add sequence number if tracker available (requires async I/O)
        if self.sequence_tracker and user_id:
            sequence = await self.sequence_tracker.get_next_sequence(
                tenant_id=self.tenant_id,
                user_id=user_id,
            )
            encrypted_data["seq"] = sequence
            logger.record_metric("cache.v2.write", 1)
            logger.debug(
                f"Encrypted data with sequence={sequence}"
            )
        else:
            logger.record_metric("cache.v2.write", 1)
            logger.debug("Encrypted data")

        return encrypted_data

    @auto_trace(logger)
    def _decrypt(self, encrypted_data: dict) -> Optional[str]:
        """Decrypt encrypted data using AES-256-GCM.

        Args:
            encrypted_data: Dictionary with encrypted data from _encrypt()

        Returns:
            Decrypted plaintext string, or None if decryption fails

        Note:
            Returns None on any decryption failure to maintain timing consistency
            and prevent information leakage.
        """
        try:
            # Validate schema version
            version = encrypted_data.get("v")
            if version != SCHEMA_VERSION:
                logger.info(f"Unsupported schema version: {version}")
                return None

            # Extract and decode components
            iv = base64.b64decode(encrypted_data["iv"])
            ciphertext = base64.b64decode(encrypted_data["ct"])
            tag = base64.b64decode(encrypted_data["tag"])

            # Reconstruct ciphertext_and_tag for AESGCM.decrypt()
            ciphertext_and_tag = ciphertext + tag

            # Decrypt and verify authentication tag
            plaintext_bytes = self._aesgcm.decrypt(iv, ciphertext_and_tag, None)

            # Decode to string
            plaintext = plaintext_bytes.decode("utf-8")

            logger.debug("Successfully decrypted data")
            return plaintext

        except Exception as e:
            # Log error but return None (don't raise) to maintain timing consistency
            logger.log_error(
                Exception(f"Decryption failed: {e}")
            )
            return None

    @auto_trace(logger)
    async def get(self, key: str) -> Optional[Any]:
        """Retrieve and decrypt value from cache with schema versioning.

        Reads v2 (encrypted) format only. Entries missing the ``"v"`` key
        are treated as malformed and return None.

        Args:
            key: Cache key

        Returns:
            Decrypted value if found and valid, None otherwise

        Note:
            Returns None on decryption failures without raising exceptions
            to maintain timing consistency.
        """
        try:
            # Get data from backend
            data = await self.backend.get(key)

            if data is None:
                logger.debug(f"Cache miss for key '{key}'")
                return None

            if "v" not in data:
                logger.info(f"Malformed cache entry for key '{key}': missing version field")
                return None

            # v2 format (encrypted): {"v": 2, "iv": ..., "ct": ..., "tag": ..., "seq": ...}
            # Decrypt value — offload CPU-bound AES-GCM to executor when available
            if self._executor is not None:
                loop = asyncio.get_running_loop()
                decrypted_json = await loop.run_in_executor(
                    self._executor, self._decrypt, data,
                )
            else:
                decrypted_json = self._decrypt(data)

            if decrypted_json is None:
                logger.debug(f"Decryption failed for key '{key}'")
                return None

            # Parse JSON
            value = json.loads(decrypted_json)
            logger.debug(f"Cache hit for key '{key}' (encrypted)")

            return value

        except Exception as e:
            logger.log_error(
                Exception(f"Get operation failed for key '{key}': {e}")
            )
            return None

    @auto_trace(logger)
    async def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int,
        user_id: Optional[str] = None,
    ) -> None:
        """Encrypt and store value in cache using v2 format.

        Always writes in v2 format with encryption and optional sequence number.

        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time-to-live in seconds
            user_id: Optional user ID for sequence tracking

        Raises:
            Exception: If encryption or storage fails

        Note:
            Fresh IV is generated for each write inside _encrypt() method.
            All new writes use v2 format.
        """
        try:
            # Serialize value to JSON
            value_json = json.dumps(value, default=str)

            # Encrypt with fresh IV (generated inside _encrypt)
            # Always produces v2 format
            encrypted_data = await self._encrypt(value_json, user_id=user_id)

            # Store encrypted data in backend
            await self.backend.set(key, encrypted_data, ttl_seconds)

            logger.debug(f"Encrypted and cached key '{key}' with TTL={ttl_seconds}s (v2 format)")

        except Exception as e:
            logger.log_error(
                Exception(f"Set operation failed for key '{key}': {e}")
            )
            raise

    @auto_trace(logger)
    async def delete(self, key: str) -> None:
        """Remove key from cache.

        Args:
            key: Cache key to remove

        Raises:
            Exception: If deletion fails
        """
        try:
            await self.backend.delete(key)
            logger.debug(f"Deleted key '{key}'")
        except Exception as e:
            logger.log_error(
                Exception(f"Delete operation failed for key '{key}': {e}")
            )
            raise

    @auto_trace(logger)
    async def mget(self, keys: list[str]) -> list[Any | None]:
        """Retrieve and decrypt multiple values from cache.

        Delegates to the wrapped backend's mget() for a single round-trip
        retrieval, then decrypts all non-None results using the tenant key
        derived at construction time (one key derivation per wrapper lifetime,
        not per batch).

        Reads v2 (encrypted) format only. Entries missing the ``"v"`` key
        are treated as malformed and return None at that position.
        Decryption failures on individual keys return None at that
        position without failing the entire batch.

        Args:
            keys: List of cache keys to retrieve

        Returns:
            List aligned with input keys; None at position i means keys[i]
            was not found, had invalid format, or failed decryption
        """
        if not keys:
            return []

        # Single round-trip to backend for all keys
        raw_results = await self.backend.mget(keys)

        results: list[Any | None] = []
        for i, data in enumerate(raw_results):
            if data is None:
                results.append(None)
                continue

            try:
                if "v" not in data:
                    logger.info(f"Malformed cache entry for key '{keys[i]}': missing version field")
                    results.append(None)
                else:
                    # v2 format (encrypted)
                    decrypted_json = self._decrypt(data)
                    if decrypted_json is None:
                        logger.debug(f"Decryption failed for key '{keys[i]}'")
                        results.append(None)
                    else:
                        value = json.loads(decrypted_json)
                        results.append(value)
            except Exception as e:
                logger.log_error(
                    Exception(f"mget decryption failed for key '{keys[i]}': {e}")
                )
                results.append(None)

        return results

    @auto_trace(logger)
    async def mset(self, items: list[tuple[str, Any, int]]) -> None:
        """Encrypt and store multiple values in cache using v2 format.

        Encrypts all values using the tenant key derived at construction
        time (one key derivation per wrapper lifetime, not per batch), then
        delegates to the wrapped backend's mset() for batch storage.

        Each value gets a fresh IV generated inside _encrypt() per
        SEC-REQ-02 and SEC-REQ-05.

        Args:
            items: List of (key, value, ttl_seconds) tuples to store

        Raises:
            Exception: If encryption or storage fails
        """
        if not items:
            return

        encrypted_items: list[tuple[str, Any, int]] = []
        for key, value, ttl_seconds in items:
            # Serialize value to JSON
            value_json = json.dumps(value, default=str)

            # Encrypt with fresh IV (generated inside _encrypt)
            encrypted_data = await self._encrypt(value_json)

            encrypted_items.append((key, encrypted_data, ttl_seconds))

        # Single batch call to backend
        await self.backend.mset(encrypted_items)

    @auto_trace(logger)
    async def mdelete(self, keys: list[str]) -> int:
        """Delete multiple keys from cache.

        Delegates directly to the wrapped backend's mdelete() since
        deletion does not require encryption or decryption.

        Args:
            keys: List of cache keys to delete

        Returns:
            Count of keys that were successfully deleted
        """
        if not keys:
            return 0

        return await self.backend.mdelete(keys)

    @auto_trace(logger)
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key to check

        Returns:
            True if key exists, False otherwise

        Warning:
            This method does not decrypt or validate the data.
            Use get() to verify data integrity.
        """
        try:
            return await self.backend.exists(key)
        except Exception as e:
            logger.log_error(
                Exception(f"Exists operation failed for key '{key}': {e}")
            )
            return False

    @auto_trace(logger)
    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries matching a key prefix.

        EncryptingCacheWrapper does not transform keys (encryption applies to
        values only), so the prefix is forwarded directly to the wrapped backend.

        Args:
            prefix: Key prefix to match

        Returns:
            Number of entries removed

        Raises:
            Exception: If backend operation fails
        """
        count = await self.backend.invalidate_by_prefix(prefix)
        logger.record_metric("cache.invalidate_by_prefix.count", count)
        logger.debug(f"Invalidated {count} keys matching prefix '{prefix}'")
        return count

    @auto_trace(logger)
    async def keys_by_prefix(self, prefix: str) -> list[str]:
        """Return all keys matching a key prefix.

        EncryptingCacheWrapper does not transform keys (encryption applies to
        values only), so the prefix is forwarded directly to the wrapped backend.

        Args:
            prefix: Key prefix to match

        Returns:
            List of matching keys

        Raises:
            AttributeError: If wrapped backend does not support keys_by_prefix
            Exception: If backend operation fails
        """
        if not hasattr(self.backend, "keys_by_prefix"):
            raise AttributeError("Wrapped backend does not support keys_by_prefix")
        return await self.backend.keys_by_prefix(prefix)


@auto_trace(logger)
def create_encrypting_wrapper(
    backend: Any,
    master_key: bytes,
    tenant_id: str,
    sequence_tracker: Optional[Any] = None,
    executor: Optional[Executor] = None,
) -> EncryptingCacheWrapper:
    """Factory function for EncryptingCacheWrapper.

    Creates an EncryptingCacheWrapper instance with validated parameters.
    Required for objects with 3+ constructor parameters.

    Args:
        backend: Cache backend to wrap (implements CacheBackend protocol)
        master_key: Master key for tenant key derivation (must be 32 bytes)
        tenant_id: Tenant identifier for key derivation
        sequence_tracker: Optional SequenceTracker for replay protection
        executor: Optional thread pool executor for offloading CPU-bound
            crypto. When None, crypto runs inline on the event loop.

    Returns:
        Configured EncryptingCacheWrapper instance

    Raises:
        ValueError: If master_key is invalid (validated by derive_tenant_key)
        ValueError: If tenant_id is invalid (validated by derive_tenant_key)

    Example:
        from neoaxios_secure_cache.backends.redis import create_redis_backend

        backend = create_redis_backend()
        cache = create_encrypting_wrapper(
            backend=backend,
            master_key=secrets.token_bytes(32),
            tenant_id="tenant-123",
        )
    """
    return EncryptingCacheWrapper(
        backend=backend,
        master_key=master_key,
        tenant_id=tenant_id,
        sequence_tracker=sequence_tracker,
        executor=executor,
    )
