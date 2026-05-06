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

"""Cache backend protocol definitions.

This module defines the CacheBackend protocol that all cache implementations
and security wrappers must implement. The protocol ensures consistent async
interfaces across all cache layers.

Also defines SecureCacheBackend, KeyManager, and CryptoProvider protocols for
secure caching with encryption, key management, and cryptographic operations.

Usage:
    from neoaxios_secure_cache.protocols import CacheBackend

    class MyCacheBackend:
        async def get(self, key: str) -> Optional[Any]: ...
        async def set(self, key: str, value: Any, ttl_seconds: int) -> None: ...
        async def delete(self, key: str) -> None: ...
        async def exists(self, key: str) -> bool: ...
        async def invalidate_by_prefix(self, prefix: str) -> int: ...
        async def keys_by_prefix(self, prefix: str) -> list[str]: ...

    from neoaxios_secure_cache.protocols import SecureCacheBackend, KeyManager, CryptoProvider
"""

from typing import Any, Optional, Protocol, runtime_checkable


class CacheBackend(Protocol):
    """Protocol for cache backend implementations.

    All cache backends and security wrappers must implement this interface
    to support composition via the decorator pattern. Implementations must
    be async-compatible.

    The protocol defines core cache operations with TTL-based expiration.
    Security wrappers (signing, encryption) implement this protocol and
    delegate to wrapped backends.

    Attributes:
        None (protocol defines interface only)

    Example:
        class InMemoryCacheBackend:
            async def get(self, key: str) -> Optional[Any]:
                return self._store.get(key)

            async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
                self._store[key] = CacheEntry(value, time.time() + ttl_seconds)

            async def delete(self, key: str) -> None:
                self._store.pop(key, None)

            async def exists(self, key: str) -> bool:
                return key in self._store
    """

    async def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache.

        Returns None if key is not found, expired, or validation fails
        (signature mismatch, decryption failure, etc.).

        Args:
            key: Cache key (may be obfuscated by signing wrapper)

        Returns:
            Cached value if found and valid, None otherwise

        Note:
            Security wrappers may return None on validation failures
            without raising exceptions, to maintain timing consistency.
        """
        ...

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value in cache with TTL.

        The value is stored with time-to-live expiration. Security wrappers
        may transform the key (obfuscation) and value (encryption/signing)
        before storage.

        Args:
            key: Cache key (will be obfuscated by signing wrapper)
            value: Value to cache (will be encrypted by encryption wrapper)
            ttl_seconds: Time-to-live in seconds (NOT ttl - must be ttl_seconds)

        Raises:
            Exception: If storage fails (connection error, validation error, etc.)

        Note:
            Parameter is ttl_seconds (not ttl) per design specification.
        """
        ...

    async def delete(self, key: str) -> None:
        """Remove key from cache.

        Deletes the key and its associated value. No error if key does not exist.

        Args:
            key: Cache key to remove

        Note:
            Security wrappers apply key obfuscation before deletion.
        """
        ...

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.

        This method checks for key presence without retrieving or validating
        the value. It does NOT verify signatures or decrypt data.

        Args:
            key: Cache key to check

        Returns:
            True if key exists (may be expired or invalid), False otherwise

        Warning:
            This method does not validate cache entry integrity. Use get()
            to verify signatures and encryption.
        """
        ...

    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Invalidate all cache entries whose keys match a given prefix.

        Removes all entries where the original key starts with the specified
        prefix. Security wrappers that obfuscate keys (e.g., SigningCacheWrapper)
        must maintain a backend prefix index to support prefix-based invalidation.
        SigningCacheWrapper requires delimiter-aligned prefixes (ending with ":").

        Args:
            prefix: Key prefix to match (e.g., "user:123:" to invalidate
                all cache entries for user 123)

        Returns:
            Number of entries successfully removed
        """
        ...

    async def keys_by_prefix(self, prefix: str) -> list[str]:
        """Return all keys matching a given prefix.

        Required to support SigningCacheWrapper prefix invalidation in
        distributed environments.

        Args:
            prefix: Key prefix to match

        Returns:
            List of matching keys
        """
        ...

    async def mget(self, keys: list[str]) -> list[Any | None]:
        """Retrieve multiple values by key.

        Returns a list aligned with the input keys; None at position i
        means keys[i] was not found or retrieval failed.

        The default implementation sequentially calls self.get() for each
        key. Subclasses should override with native batch operations for
        better throughput.

        Sequential single-key fallback for backward compatibility with
        existing CacheBackend implementations that do not override batch
        methods.

        Args:
            keys: List of cache keys to retrieve

        Returns:
            List of values aligned with input keys; None for missing keys
        """
        return [await self.get(key) for key in keys]

    async def mset(self, items: list[tuple[str, Any, int]]) -> None:
        """Set multiple key-value pairs with TTL.

        Each tuple is (key, value, ttl_seconds). Values must be
        JSON-serializable. TTL must be > 0.

        The default implementation sequentially calls self.set() for each
        item. Subclasses should override with native batch operations for
        better throughput.

        Sequential single-key fallback for backward compatibility with
        existing CacheBackend implementations that do not override batch
        methods.

        Args:
            items: List of (key, value, ttl_seconds) tuples to store
        """
        for key, value, ttl_seconds in items:
            await self.set(key, value, ttl_seconds)

    async def mdelete(self, keys: list[str]) -> int:
        """Delete multiple keys.

        Returns count of keys that were successfully deleted (i.e., the
        delete call did not raise an exception).

        The default implementation sequentially calls self.delete() for
        each key, counting successful deletions. Since the protocol's
        delete() returns None, success is determined by absence of
        exception.

        Sequential single-key fallback for backward compatibility with
        existing CacheBackend implementations that do not override batch
        methods.

        Args:
            keys: List of cache keys to delete

        Returns:
            Count of keys that were successfully deleted
        """
        count = 0
        for key in keys:
            try:
                await self.delete(key)
                count += 1
            except Exception:
                pass
        return count


@runtime_checkable
class SecureCacheBackend(Protocol):
    """Abstract interface for secure permission caching with encryption.

    Extends the basic CacheBackend with cryptographic protections:
    - AES-256-GCM encryption with per-tenant keys
    - HMAC-SHA256 signature verification (timing-safe)
    - Canary-based integrity monitoring
    - Replay attack protection via sequence numbers
    - Sensitive permission bypass

    See redis-security-design.md Section 13 for locked specifications.

    All methods are async to support network-based cache backends.
    """

    async def get(
        self,
        key: str,
    ) -> Optional[Any]:
        """Get cached value with full cryptographic verification.

        Performs:
        1. Probabilistic canary check (1% of requests)
        2. HMAC signature verification (timing-safe)
        3. AES-GCM decryption with tenant key
        4. Sequence number validation (replay protection)

        Args:
            key: Cache key (already obfuscated via HMAC)

        Returns:
            Decrypted cached value or None if not found/invalid

        Raises:
            Never raises to caller - returns None on any security failure
        """
        ...

    async def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int,
    ) -> None:
        """Set cached value with encryption and signing.

        Performs:
        1. Generate fresh IV (12 bytes, unique per write)
        2. Encrypt with AES-256-GCM using tenant key
        3. Sign envelope with HMAC-SHA256
        4. Store with TTL

        Args:
            key: Cache key (already obfuscated via HMAC)
            value: Value to cache (permissions, roles, metadata)
            ttl_seconds: Time to live in seconds

        Raises:
            TamperDetectionActiveError: If cache integrity violation is active
        """
        ...

    async def delete(
        self,
        key: str,
    ) -> None:
        """Delete cached value and its prefix index entries.

        Args:
            key: Cache key to delete
        """
        ...

    async def invalidate_user(
        self,
        app_id: str,
        tenant_id: str,
        user_id: str,
    ) -> None:
        """Invalidate all cached permissions for user.

        Uses backend prefix index for targeted invalidation
        without SCAN operations.

        Args:
            app_id: Application ID for multi-app isolation. In multi-app deployments
                where multiple applications share a cache backend (e.g., shared Redis),
                app_id ensures cache invalidation only affects the specific application.
                When a user's permissions change in app A, only app A's cache is cleared,
                preventing cross-app pollution.
            tenant_id: Tenant ID
            user_id: User ID to invalidate cache for
        """
        ...

    async def invalidate_tenant(
        self,
        app_id: str,
        tenant_id: str,
    ) -> None:
        """Invalidate all cached permissions for tenant.

        Runs as async background task with max 10k keys limit.

        Args:
            app_id: Application ID for multi-app isolation. In multi-app deployments
                where multiple applications share a cache backend (e.g., shared Redis),
                app_id ensures cache invalidation only affects the specific application.
                When tenant policies change in app A, only app A's cache is cleared,
                preventing cross-app pollution.
            tenant_id: Tenant ID to invalidate cache for
        """
        ...

    def is_sensitive_permission(
        self,
        permission: str,
    ) -> bool:
        """Check if permission should bypass cache entirely.

        Sensitive permissions (admin:*, delete:*, sudo:*, etc.)
        are NEVER cached to prevent TOCTOU attacks.

        Args:
            permission: Permission string to check

        Returns:
            True if permission should bypass cache
        """
        ...

    async def is_healthy(self) -> bool:
        """Check cache health including canary integrity.

        Returns:
            True if cache is operational and canaries valid
        """
        ...



@runtime_checkable
class KeyManager(Protocol):
    """Abstract interface for cryptographic key management.

    Manages key derivation, validation, and rotation for the
    secure cache backend. All keys are derived from a single
    master key using HKDF-SHA256.

    Key derivation info strings use domain-specific prefixes:
    - Signing key: HKDF info=SIGNING_KEY_INFO (e.g., b"secure-cache:v1:sign")
    - KEK: HKDF info=KEK_INFO (e.g., b"secure-cache:v1:kek")
    - Tenant keys: HKDF info=TENANT_KEY_INFO_PREFIX + tenant_id

    See redis-security-design.md Section 13.1 for specifications.
    """

    def validate_master_key(
        self,
        key: bytes,
    ) -> bool:
        """Validate master key material.

        Checks:
        - Length exactly 32 bytes (256 bits)
        - Not all zeros
        - Sufficient entropy (basic check)

        Args:
            key: Master key bytes to validate

        Returns:
            True if key passes validation

        Raises:
            KeyValidationError: If key fails validation
        """
        ...

    def derive_signing_key(self) -> bytes:
        """Derive HMAC signing key from master key.

        Uses: HKDF-SHA256(master, salt=None, info=SIGNING_KEY_INFO)

        Returns:
            32-byte signing key
        """
        ...

    def derive_kek(self) -> bytes:
        """Derive key-encryption-key from master key.

        Uses: HKDF-SHA256(master, salt=None, info=KEK_INFO)

        Returns:
            32-byte KEK for tenant key derivation
        """
        ...

    async def derive_tenant_key(
        self,
        tenant_id: str,
    ) -> bytes:
        """Derive per-tenant encryption key.

        Uses: HKDF-SHA256(KEK, salt=tenant_salt, info=TENANT_KEY_INFO_PREFIX + tenant_id)

        Salt is fetched from Redis (generated on first access).
        Result is cached in LRU cache.

        Args:
            tenant_id: Tenant identifier

        Returns:
            32-byte tenant-specific encryption key
        """
        ...

    async def rotate_master_key(
        self,
        new_master: bytes,
    ) -> None:
        """Begin dual-key rotation process.

        During rotation:
        - New writes use new key
        - Reads try new key first, then old key
        - Old entries naturally expire

        Args:
            new_master: New 32-byte master key

        Raises:
            KeyValidationError: If new key fails validation
        """
        ...


@runtime_checkable
class CryptoProvider(Protocol):
    """Abstract interface for cryptographic operations.

    Provides AES-GCM encryption/decryption and HMAC operations
    with timing-safe comparisons. All methods use the Python
    `cryptography` library.

    See redis-security-design.md Section 13.3 for specifications.
    """

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt plaintext with AES-256-GCM.

        Generates fresh 12-byte IV for each call.

        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key

        Returns:
            Tuple of (ciphertext, iv, tag)
        """
        ...

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        iv: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt ciphertext with AES-256-GCM.

        Args:
            ciphertext: Encrypted data
            key: 32-byte encryption key
            iv: 12-byte initialization vector
            tag: 16-byte authentication tag

        Returns:
            Decrypted plaintext

        Raises:
            DecryptionError: If decryption or authentication fails
        """
        ...

    def sign(
        self,
        data: bytes,
        key: bytes,
    ) -> bytes:
        """Create HMAC-SHA256 signature.

        Args:
            data: Data to sign
            key: 32-byte signing key

        Returns:
            32-byte HMAC signature
        """
        ...

    def verify(
        self,
        data: bytes,
        signature: bytes,
        key: bytes,
    ) -> bool:
        """Verify HMAC-SHA256 signature (timing-safe).

        Uses secrets.compare_digest() for constant-time comparison.

        Args:
            data: Original data
            signature: Signature to verify
            key: 32-byte signing key

        Returns:
            True if signature is valid
        """
        ...

