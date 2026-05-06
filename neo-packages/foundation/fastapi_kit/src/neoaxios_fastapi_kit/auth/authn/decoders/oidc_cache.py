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

"""JWKS caching and key rotation for OIDC token validation.

Implements thread-safe caching of JWKS public keys with TTL-based expiration
and automatic key rotation handling. Designed for high-performance multi-tenant
OIDC deployments where fetching keys from provider JWKS endpoints on every
token validation would be prohibitively expensive.

This cache stores parsed JWKS key sets indexed by issuer and key_id (kid).
When signature verification fails, the cache is automatically invalidated and
fresh keys are fetched from the provider's JWKS endpoint.

Key Features:
- TTL-based expiration (default: 24 hours)
- Thread-safe with asyncio.Lock
- Automatic invalidation on signature failures
- Per-issuer key storage with kid lookup
- Support for multiple key algorithms (RS256, ES256, etc.)
- Support for RSA and ECDSA key types
- Pluggable backend (in-memory or Redis via CacheBackend protocol)

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.oidc_cache import JWKSCache

    # In-memory cache (single-server deployments)
    cache = JWKSCache(backend=InMemoryCacheBackend(default_ttl=86400))

    # Redis cache (distributed deployments)
    cache = JWKSCache(backend=RedisCacheBackend(
        url="redis://localhost:6379",
        default_ttl=86400
    ))

    # Cache JWKS from provider
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "key-1",
                "n": "...",
                "e": "AQAB",
                ...
            }
        ]
    }
    await cache.cache_jwks(issuer="https://accounts.google.com", jwks=jwks)

    # Get specific key
    key = await cache.get_key(issuer="https://accounts.google.com", key_id="key-1")

    # Invalidate on signature failure
    await cache.invalidate(issuer="https://accounts.google.com")

Example (with OIDCDecoder integration):
    # OIDCDecoder uses cache to avoid repeated JWKS fetches
    decoder = OIDCDecoder(
        issuer="https://accounts.google.com",
        audience="my-client-id",
        jwks_cache=cache,
    )

    try:
        identity = await decoder.decode(token)
    except TokenInvalidError:
        # Cache automatically invalidated, next decode will fetch fresh keys
        pass

Performance Characteristics:
- Cache hit: O(1) key lookup, no network call
- Cache miss: O(1) lookup + network call to JWKS endpoint
- Invalidation: O(1) for single issuer
- Memory: O(issuers * keys_per_issuer * key_size)
- Typical key size: ~2KB per RSA-2048 key

Thread Safety:
All public methods use asyncio.Lock to ensure thread-safe access to the
underlying cache backend. Multiple coroutines can safely call cache methods
concurrently.

TTL Strategy:
- Default TTL: 24 hours (recommended by OIDC spec)
- Configurable per cache_jwks() call
- Keys expire independently (per-issuer TTL)
- Expired keys automatically removed on next access
- No background cleanup required (lazy expiration)

Key Rotation Handling:
When OIDC providers rotate keys, the old keys remain valid until their TTL
expires. New tokens will use new kid values. If signature verification fails:
1. Cache is invalidated for the issuer
2. Fresh JWKS is fetched from provider
3. Token validation is retried with new keys

This ensures zero-downtime key rotation without manual intervention.
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import CACHE_TTL_LONG
from neoaxios_secure_cache import CacheBackend
from neoaxios_fastapi_kit.auth.cache_keys import jwks_key

if TYPE_CHECKING:
    from neoaxios_secure_cache import CacheNamespace

logger = get_telemetry(__name__)


@dataclass
class JWKSEntry:
    """Cached JWKS entry with keys indexed by kid.

    Attributes:
        issuer: OIDC issuer URL (e.g., "https://accounts.google.com")
        keys: Dictionary mapping kid -> JWK key dict
        cached_at: Unix timestamp when JWKS was cached
        ttl_seconds: Time-to-live in seconds
        expiry: Unix timestamp when cache entry expires
    """

    issuer: str
    keys: Dict[str, Dict[str, Any]]  # kid -> JWK dict
    cached_at: float
    ttl_seconds: int
    expiry: float


class JWKSCache:
    """Thread-safe JWKS cache with TTL-based expiration and key rotation.

    Caches JWKS key sets from OIDC providers to avoid repeated network calls
    during token validation. Supports multiple issuers, automatic expiration,
    and cache invalidation on signature failures.

    This cache implements the CacheBackend protocol for compatibility with
    existing auth framework components, while providing JWKS-specific methods
    for key lookup and storage.

    Attributes:
        namespace: Cache namespace for hierarchical key prefixing
        backend: Underlying cache backend (Redis required for production)
        default_ttl_seconds: Default TTL for cached JWKS (24 hours)
        _lock: Asyncio lock for thread-safe access

    Design Notes:
        - Thread-safe via asyncio.Lock on all public methods
        - Lazy expiration (no background cleanup tasks)
        - Keys indexed by issuer + kid for O(1) lookup
        - Supports multiple issuers in same cache instance
        - Uses namespace-aware key format from cache_keys module

    Example:
        from neoaxios_secure_cache import CacheNamespace
        from neoaxios_secure_cache.backends.redis import RedisCacheBackend

        ns = CacheNamespace(org="neo", env="prod", service="auth-api", app="gateway")
        backend = RedisCacheBackend(url="redis://localhost:6379")

        cache = JWKSCache(namespace=ns, backend=backend)
        jwks = fetch_jwks_from_provider(issuer)
        await cache.cache_jwks(issuer, jwks, ttl_seconds=86400)
        key = await cache.get_key(issuer, key_id="key-1")
    """

    @auto_trace(logger)
    def __init__(
        self,
        namespace: "CacheNamespace",
        backend: CacheBackend,
        default_ttl_seconds: int = CACHE_TTL_LONG,
    ):
        """Initialize JWKS cache with namespace and backend.

        Args:
            namespace: Cache namespace for hierarchical key prefixing (required)
            backend: Cache backend implementation (required - fail fast on misconfiguration)
            default_ttl_seconds: Default TTL for cached JWKS entries.
                                Default: 86400 (24 hours, per OIDC spec)

        Raises:
            TypeError: If namespace or backend is not provided

        Example:
            from neoaxios_secure_cache import CacheNamespace
            from neoaxios_secure_cache.backends.redis import RedisCacheBackend

            ns = CacheNamespace(
                org="neo",
                env="prod",
                service="auth-api",
                app="gateway",
            )

            cache = JWKSCache(
                namespace=ns,
                backend=RedisCacheBackend(url="redis://localhost:6379"),
                default_ttl_seconds=86400,
            )
        """
        self.namespace = namespace
        self.backend = backend
        self.default_ttl_seconds = default_ttl_seconds
        self._lock = asyncio.Lock()

        logger.info(
            f"Initialized JWKSCache with default_ttl={default_ttl_seconds}s, "
            f"namespace={namespace.base()}, backend={type(backend).__name__}"
        )

    @auto_trace(logger)
    async def get_key(self, issuer: str, key_id: str) -> Optional[Dict[str, Any]]:
        """Get cached public key for issuer and key ID.

        Returns the JWK key dictionary for the specified issuer and kid.
        Returns None if the issuer is not cached, the key_id is not found,
        or the cache entry has expired.

        This method automatically removes expired entries during lookup.

        Args:
            issuer: OIDC issuer URL (e.g., "https://accounts.google.com")
            key_id: Key ID (kid) from JWT header

        Returns:
            JWK key dictionary with kty, n, e, etc., or None if not found/expired

        Example:
            key = await cache.get_key(
                issuer="https://accounts.google.com",
                key_id="abc123"
            )
            if key:
                # Use key for signature verification
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            else:
                # Cache miss - fetch fresh JWKS from provider
                jwks = await fetch_jwks(issuer)
                await cache.cache_jwks(issuer, jwks)
        """
        async with self._lock:
            cache_key = jwks_key(self.namespace, issuer)
            entry_data = await self.backend.get(cache_key)

            if entry_data is None:
                logger.debug(f"Cache miss for issuer '{issuer}' (not in backend)")
                return None

            # Deserialize entry
            entry = self._deserialize_entry(entry_data)

            # Check expiration (backend TTL handles this, but double-check)
            current_time = time.time()
            if current_time > entry.expiry:
                logger.info(f"Cache expired for issuer '{issuer}' (stale in backend)")
                await self.backend.delete(cache_key)
                return None

            # Lookup key by kid
            key = entry.keys.get(key_id)
            if key is None:
                logger.debug(
                    f"Cache miss for key_id '{key_id}' in issuer '{issuer}' "
                    f"(available kids: {list(entry.keys.keys())})"
                )
                return None

            logger.info(
                f"Cache hit for issuer '{issuer}', key_id '{key_id}' "
                f"(expires in {entry.expiry - current_time:.0f}s)"
            )
            return key

    @auto_trace(logger)
    async def cache_jwks(
        self,
        issuer: str,
        jwks: Dict[str, Any],
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Cache JWKS key set for issuer with TTL.

        Stores the entire JWKS key set indexed by issuer. Keys are indexed
        by their kid (key ID) for fast lookup during token validation.

        If the JWKS contains keys without kid claims, those keys are stored
        with a generated key based on their position ("key-0", "key-1", etc.).

        Args:
            issuer: OIDC issuer URL (e.g., "https://accounts.google.com")
            jwks: JWKS dictionary with "keys" array from provider's JWKS endpoint
            ttl_seconds: Time-to-live in seconds. If None, uses default_ttl_seconds.
                        Recommended: 86400 (24 hours per OIDC spec)

        Raises:
            ValueError: If jwks is missing "keys" array or has invalid structure

        Example:
            # Fetch JWKS from provider
            jwks = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "abc123",
                        "use": "sig",
                        "n": "...",
                        "e": "AQAB",
                    },
                    {
                        "kty": "RSA",
                        "kid": "def456",
                        "use": "sig",
                        "n": "...",
                        "e": "AQAB",
                    }
                ]
            }

            # Cache for 24 hours
            await cache.cache_jwks(
                issuer="https://accounts.google.com",
                jwks=jwks,
                ttl_seconds=86400,
            )
        """
        # Validate JWKS structure
        if not isinstance(jwks, dict):
            error = ValueError(f"Invalid JWKS: expected dict, got {type(jwks).__name__}")
            logger.log_error(error=error)
            raise error

        if "keys" not in jwks:
            error = ValueError("Invalid JWKS: missing 'keys' array")
            logger.log_error(error=error)
            raise error

        if not isinstance(jwks["keys"], list):
            error = ValueError(
                f"Invalid JWKS: 'keys' must be array, got {type(jwks['keys']).__name__}"
            )
            logger.log_error(error=error)
            raise error

        # Use default TTL if not specified
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds

        # Build kid -> key mapping
        keys_by_kid: Dict[str, Dict[str, Any]] = {}
        for idx, key in enumerate(jwks["keys"]):
            # Use kid from key, or generate one if missing
            kid = key.get("kid", f"key-{idx}")
            keys_by_kid[kid] = key

        # Create entry
        current_time = time.time()
        entry = JWKSEntry(
            issuer=issuer,
            keys=keys_by_kid,
            cached_at=current_time,
            ttl_seconds=ttl,
            expiry=current_time + ttl,
        )

        async with self._lock:
            cache_key = jwks_key(self.namespace, issuer)
            entry_data = self._serialize_entry(entry)
            await self.backend.set(cache_key, entry_data, ttl)
            logger.info(
                f"Cached JWKS for issuer '{issuer}' with {len(keys_by_kid)} keys, "
                f"ttl={ttl}s, key={cache_key}"
            )

    @auto_trace(logger)
    async def invalidate(self, issuer: str) -> None:
        """Force immediate cache invalidation for issuer.

        Removes all cached keys for the specified issuer. This is typically
        called when:
        - Signature verification fails (possible key rotation)
        - Provider's JWKS endpoint returns 401/403 (credentials revoked)
        - Manual cache flush requested

        After invalidation, the next token validation will fetch fresh keys
        from the provider's JWKS endpoint.

        Args:
            issuer: OIDC issuer URL to invalidate

        Example:
            # Signature verification failed
            try:
                jwt.decode(token, key, algorithms=["RS256"])
            except jwt.InvalidSignatureError:
                # Invalidate cache and retry with fresh keys
                await cache.invalidate(issuer="https://accounts.google.com")
                jwks = await fetch_jwks(issuer)
                await cache.cache_jwks(issuer, jwks)
        """
        async with self._lock:
            cache_key = jwks_key(self.namespace, issuer)
            await self.backend.delete(cache_key)
            logger.info(f"Invalidated JWKS cache for issuer '{issuer}', key={cache_key}")

    @auto_trace(logger)
    async def get_all_keys(self, issuer: str) -> List[Dict[str, Any]]:
        """Get all cached keys for issuer.

        Returns all JWK keys for the issuer, regardless of kid. Returns empty
        list if issuer is not cached or cache entry has expired.

        This method is useful for:
        - Debugging key rotation issues
        - Listing available signing keys
        - Bulk key export

        Args:
            issuer: OIDC issuer URL

        Returns:
            List of JWK key dictionaries, or empty list if not cached/expired

        Example:
            keys = await cache.get_all_keys(issuer="https://accounts.google.com")
            logger.info(f"Provider has {len(keys)} signing keys")
            for key in keys:
                logger.info(f"  kid={key.get('kid')}, kty={key.get('kty')}")
        """
        async with self._lock:
            cache_key = jwks_key(self.namespace, issuer)
            entry_data = await self.backend.get(cache_key)

            if entry_data is None:
                logger.debug(f"No cached keys for issuer '{issuer}' in backend")
                return []

            entry = self._deserialize_entry(entry_data)

            # Check expiration
            current_time = time.time()
            if current_time > entry.expiry:
                logger.info(f"Cache expired for issuer '{issuer}' (stale in backend)")
                await self.backend.delete(cache_key)
                return []

            keys = list(entry.keys.values())
            logger.info(
                f"Retrieved {len(keys)} keys for issuer '{issuer}' from backend"
            )
            return keys

    @auto_trace(logger)
    def _serialize_entry(self, entry: JWKSEntry) -> Dict[str, Any]:
        """Serialize JWKSEntry for backend storage.

        Converts JWKSEntry dataclass to JSON-serializable dictionary.

        Args:
            entry: JWKSEntry to serialize

        Returns:
            Dictionary suitable for JSON serialization

        Example:
            entry_dict = cache._serialize_entry(entry)
            await backend.set(key, entry_dict, ttl)
        """
        return {
            "issuer": entry.issuer,
            "keys": entry.keys,
            "cached_at": entry.cached_at,
            "ttl_seconds": entry.ttl_seconds,
            "expiry": entry.expiry,
        }

    @auto_trace(logger)
    def _deserialize_entry(self, data: Dict[str, Any]) -> JWKSEntry:
        """Deserialize JWKSEntry from backend storage.

        Converts JSON-deserialized dictionary back to JWKSEntry dataclass.

        Args:
            data: Dictionary from backend storage

        Returns:
            JWKSEntry instance

        Raises:
            ValueError: If data is missing required fields

        Example:
            entry_data = await backend.get(key)
            entry = cache._deserialize_entry(entry_data)
        """
        try:
            return JWKSEntry(
                issuer=data["issuer"],
                keys=data["keys"],
                cached_at=data["cached_at"],
                ttl_seconds=data["ttl_seconds"],
                expiry=data["expiry"],
            )
        except KeyError as e:
            error = ValueError(f"Invalid JWKSEntry data: missing field {e}")
            logger.log_error(error=error)
            raise error


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_jwks_cache(
    namespace: "CacheNamespace",
    backend: CacheBackend,
    default_ttl_seconds: int = CACHE_TTL_LONG,
) -> JWKSCache:
    """Factory function for JWKSCache instantiation.

    Creates a JWKSCache instance with validated parameters.

    Args:
        namespace: Cache namespace for hierarchical key prefixing (required)
        backend: Cache backend implementation (required - fail fast on misconfiguration)
        default_ttl_seconds: Default TTL for cached JWKS entries.
                            Default: 86400 (24 hours, per OIDC spec)

    Returns:
        JWKSCache instance configured with validated parameters

    Raises:
        TypeError: If namespace or backend is not provided

    Example:
        from neoaxios_secure_cache import CacheNamespace
        from neoaxios_secure_cache.backends.redis import RedisCacheBackend

        ns = CacheNamespace(
            org="neo",
            env="prod",
            service="auth-api",
            app="gateway",
        )

        cache = create_jwks_cache(
            namespace=ns,
            backend=RedisCacheBackend(url="redis://localhost:6379"),
            default_ttl_seconds=86400,
        )
    """
    return JWKSCache(
        namespace=namespace,
        backend=backend,
        default_ttl_seconds=default_ttl_seconds,
    )
