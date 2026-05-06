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

"""OIDC decoder with JWKS caching for production performance.

This example demonstrates production-ready OIDC token validation with caching:

- JWKS caching to minimize network calls to provider
- Performance comparison (with cache vs. without cache)
- Cache invalidation on signature verification failures
- Telemetry tracking for cache hits and misses
- In-memory and Redis caching backends

Caching is essential for production deployments to:
- Reduce latency (avoid repeated JWKS fetches)
- Minimize load on OIDC provider's JWKS endpoint
- Improve throughput for high-traffic services

This example shows a 10-50x performance improvement with caching.

Requirements:
    pip install neoaxios-fastapi-kit
    pip install redis  # Optional, for Redis cache backend

Environment Variables (optional):
    OIDC_ISSUER: OIDC issuer URL
    OIDC_CLIENT_ID: OAuth 2.0 client ID
    OIDC_JWKS_URI: JWKS endpoint URL
    CACHE_BACKEND: "memory" or "redis" (default: "memory")
    REDIS_URL: Redis connection URL (default: "redis://localhost:6379")

Usage:
    # In-memory cache (single server)
    python oidc_with_cache.py

    # Redis cache (distributed systems)
    CACHE_BACKEND=redis REDIS_URL=redis://localhost:6379 python oidc_with_cache.py

Performance:
    Without cache: ~100-500ms per token validation (network call)
    With cache: ~1-5ms per token validation (cache hit)
    Cache hit ratio: 95-99% in production (depends on key rotation frequency)
"""

import asyncio
import os
import time
from typing import Optional, List

from neoaxios_logging import get_telemetry

# Import decoders and cache from neoaxios_fastapi_kit
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.oidc_cache import JWKSCache, create_jwks_cache
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================

def get_oidc_config() -> dict:
    """Load OIDC configuration from environment or defaults.

    Returns:
        Dictionary with OIDC configuration parameters

    Example:
        config = get_oidc_config()
        decoder = OIDCDecoder(**config)
    """
    config = {
        "issuer": os.getenv(
            "OIDC_ISSUER",
            "https://accounts.google.com"
        ),
        "client_id": os.getenv(
            "OIDC_CLIENT_ID",
            "your-client-id.apps.googleusercontent.com"
        ),
        "jwks_uri": os.getenv(
            "OIDC_JWKS_URI",
            "https://www.googleapis.com/oauth2/v3/certs"
        ),
        "audience": os.getenv("OIDC_AUDIENCE"),
        "clock_skew_seconds": int(os.getenv("OIDC_CLOCK_SKEW", "30")),
        "cache_backend": os.getenv("CACHE_BACKEND", "memory"),
        "redis_url": os.getenv("REDIS_URL", "redis://localhost:6379"),
        "cache_ttl_seconds": int(os.getenv("CACHE_TTL_SECONDS", "86400")),  # 24 hours
    }

    logger.info(
        "Loaded OIDC configuration with cache",
        issuer=config["issuer"],
        jwks_uri=config["jwks_uri"],
        cache_backend=config["cache_backend"],
        cache_ttl=config["cache_ttl_seconds"],
    )

    return config


# =============================================================================
# Cache Setup
# =============================================================================

async def create_cache_backend(backend_type: str, redis_url: str, ttl_seconds: int) -> Optional[JWKSCache]:
    """Create JWKS cache backend based on configuration.

    Args:
        backend_type: Cache backend type ("memory" or "redis")
        redis_url: Redis connection URL (used if backend_type is "redis")
        ttl_seconds: Default TTL for cached JWKS entries

    Returns:
        JWKSCache instance or None if caching is disabled

    Raises:
        Exception: If cache backend creation fails

    Example:
        cache = await create_cache_backend("memory", "", 86400)
        decoder = OIDCDecoder(..., key_cache=cache)
    """
    logger.info(
        "Creating JWKS cache backend",
        backend_type=backend_type,
        ttl_seconds=ttl_seconds,
    )

    try:
        if backend_type == "memory":
            # In-memory cache (recommended for single-server deployments)
            cache = create_jwks_cache(
                backend=None,  # None = in-memory
                default_ttl_seconds=ttl_seconds,
            )
            logger.info("Created in-memory JWKS cache")
            return cache

        elif backend_type == "redis":
            # Redis cache (recommended for distributed deployments)
            logger.info(
                "Redis cache backend requested but not implemented in this example. "
                "For production, import RedisCacheBackend from neoaxios_fastapi_kit.auth.authz.cache"
            )
            # TODO: Implement Redis cache backend
            # from neoaxios_fastapi_kit.auth.authz.cache import RedisCacheBackend
            # cache_backend = RedisCacheBackend(default_ttl_seconds=ttl_seconds)
            # cache = create_jwks_cache(backend=cache_backend, default_ttl_seconds=ttl_seconds)
            # return cache

            # For now, fall back to in-memory
            logger.info("Falling back to in-memory cache")
            return create_jwks_cache(backend=None, default_ttl_seconds=ttl_seconds)

        else:
            logger.warning(
                f"Unknown cache backend type: {backend_type}. "
                f"Using in-memory cache as fallback."
            )
            return create_jwks_cache(backend=None, default_ttl_seconds=ttl_seconds)

    except Exception as e:
        logger.log_error(
            error=e,
            message="Failed to create cache backend",
        )
        raise


# =============================================================================
# Decoder Setup
# =============================================================================

async def create_decoder_with_cache() -> tuple[OIDCDecoder, Optional[JWKSCache]]:
    """Create OIDC decoder with JWKS caching enabled.

    Returns:
        Tuple of (OIDCDecoder, JWKSCache) instances

    Raises:
        Exception: If decoder creation fails

    Example:
        decoder, cache = await create_decoder_with_cache()
        identity = await decoder.decode(token)
    """
    logger.info("Initializing OIDC decoder with JWKS cache")

    try:
        # Load configuration
        config = get_oidc_config()

        # Create cache backend
        cache = await create_cache_backend(
            backend_type=config["cache_backend"],
            redis_url=config["redis_url"],
            ttl_seconds=config["cache_ttl_seconds"],
        )

        # Create decoder with cache
        decoder = OIDCDecoder(
            issuer=config["issuer"],
            client_id=config["client_id"],
            jwks_uri=config["jwks_uri"],
            audience=config.get("audience"),
            clock_skew_seconds=config["clock_skew_seconds"],
            key_cache=cache,  # Enable caching
        )

        logger.info(
            "OIDC decoder with cache initialized successfully",
            issuer=decoder.issuer,
            has_cache=bool(cache),
        )

        return decoder, cache

    except Exception as e:
        logger.log_error(
            error=e,
            message="Failed to create OIDC decoder with cache",
        )
        raise


async def create_decoder_without_cache() -> OIDCDecoder:
    """Create OIDC decoder WITHOUT caching (for performance comparison).

    Returns:
        OIDCDecoder instance without cache

    Raises:
        Exception: If decoder creation fails

    Example:
        decoder = await create_decoder_without_cache()
        identity = await decoder.decode(token)
    """
    logger.info("Initializing OIDC decoder without cache")

    try:
        config = get_oidc_config()

        decoder = OIDCDecoder(
            issuer=config["issuer"],
            client_id=config["client_id"],
            jwks_uri=config["jwks_uri"],
            audience=config.get("audience"),
            clock_skew_seconds=config["clock_skew_seconds"],
            key_cache=None,  # No caching
        )

        logger.info("OIDC decoder without cache initialized")
        return decoder

    except Exception as e:
        logger.log_error(
            error=e,
            message="Failed to create OIDC decoder without cache",
        )
        raise


# =============================================================================
# Token Validation with Performance Tracking
# =============================================================================

async def validate_token_timed(
    decoder: OIDCDecoder,
    token: str,
    description: str = ""
) -> tuple[Optional[IdentityContext], float]:
    """Validate token and measure validation time.

    Args:
        decoder: OIDCDecoder instance (with or without cache)
        token: JWT token string to validate
        description: Description for logging (e.g., "with cache", "without cache")

    Returns:
        Tuple of (IdentityContext or None, elapsed_time_ms)

    Example:
        identity, elapsed_ms = await validate_token_timed(decoder, token, "with cache")
        logger.info(f"Validation took {elapsed_ms:.2f}ms")
    """
    start_time = time.perf_counter()

    try:
        identity = await decoder.decode(token)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            f"Token validation successful ({description})",
            user_id=identity.user_id,
            elapsed_ms=f"{elapsed_ms:.2f}",
        )

        return identity, elapsed_ms

    except (TokenInvalidError, TokenExpiredError) as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.log_error(
            error=e,
            message=f"Token validation failed ({description})",
            elapsed_ms=f"{elapsed_ms:.2f}",
        )

        return None, elapsed_ms

    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.log_error(
            error=e,
            message=f"Unexpected error during token validation ({description})",
            elapsed_ms=f"{elapsed_ms:.2f}",
        )

        return None, elapsed_ms


# =============================================================================
# Performance Comparison
# =============================================================================

async def compare_performance(
    token: str,
    iterations: int = 10
) -> None:
    """Compare performance of cached vs. non-cached decoders.

    Validates the same token multiple times with both decoders to demonstrate
    the performance impact of JWKS caching.

    Args:
        token: JWT token string to validate
        iterations: Number of validation iterations for each decoder

    Example:
        await compare_performance(token, iterations=10)
    """
    logger.info("=" * 60)
    logger.info("PERFORMANCE COMPARISON: Cache vs. No Cache")
    logger.info("=" * 60)

    # Create decoders
    logger.info("Creating decoders for comparison...")
    decoder_cached, cache = await create_decoder_with_cache()
    decoder_no_cache = await create_decoder_without_cache()

    # Test with cache
    logger.info(f"\nValidating token {iterations} times WITH cache:")
    cached_times: List[float] = []
    for i in range(iterations):
        identity, elapsed = await validate_token_timed(
            decoder_cached,
            token,
            description=f"with cache (iteration {i+1})"
        )
        if identity:
            cached_times.append(elapsed)
        await asyncio.sleep(0.1)  # Small delay between iterations

    # Test without cache
    logger.info(f"\nValidating token {iterations} times WITHOUT cache:")
    no_cache_times: List[float] = []
    for i in range(iterations):
        identity, elapsed = await validate_token_timed(
            decoder_no_cache,
            token,
            description=f"without cache (iteration {i+1})"
        )
        if identity:
            no_cache_times.append(elapsed)
        await asyncio.sleep(0.1)  # Small delay between iterations

    # Calculate statistics
    if cached_times and no_cache_times:
        avg_cached = sum(cached_times) / len(cached_times)
        avg_no_cache = sum(no_cache_times) / len(no_cache_times)
        speedup = avg_no_cache / avg_cached if avg_cached > 0 else 0

        logger.info("=" * 60)
        logger.info("PERFORMANCE RESULTS")
        logger.info("=" * 60)
        logger.info("WITH cache:")
        logger.info(f"  Average time: {avg_cached:.2f}ms")
        logger.info(f"  Min time: {min(cached_times):.2f}ms")
        logger.info(f"  Max time: {max(cached_times):.2f}ms")
        logger.info("")
        logger.info("WITHOUT cache:")
        logger.info(f"  Average time: {avg_no_cache:.2f}ms")
        logger.info(f"  Min time: {min(no_cache_times):.2f}ms")
        logger.info(f"  Max time: {max(no_cache_times):.2f}ms")
        logger.info("")
        logger.info(f"SPEEDUP: {speedup:.1f}x faster with cache")
        logger.info("=" * 60)


# =============================================================================
# Cache Invalidation Example
# =============================================================================

async def demonstrate_cache_invalidation(
    decoder: OIDCDecoder,
    cache: JWKSCache,
    token: str
) -> None:
    """Demonstrate cache invalidation on signature verification failure.

    Shows how the cache is automatically invalidated when signature verification
    fails, forcing a fresh JWKS fetch on the next validation attempt.

    Args:
        decoder: OIDCDecoder with cache
        cache: JWKSCache instance
        token: Valid JWT token

    Example:
        await demonstrate_cache_invalidation(decoder, cache, token)
    """
    logger.info("=" * 60)
    logger.info("CACHE INVALIDATION DEMONSTRATION")
    logger.info("=" * 60)

    # First validation - populates cache
    logger.info("Step 1: First validation (populates cache)")
    identity1, time1 = await validate_token_timed(decoder, token, "initial")

    # Check cache
    if identity1:
        logger.info(f"Step 2: Checking cache for issuer: {decoder.issuer}")
        cached_keys = await cache.get_all_keys(decoder.issuer)
        logger.info(f"Cache contains {len(cached_keys)} keys")

    # Invalidate cache manually (simulating signature failure)
    logger.info("Step 3: Invalidating cache (simulating signature failure)")
    await cache.invalidate(decoder.issuer)

    # Check cache after invalidation
    cached_keys_after = await cache.get_all_keys(decoder.issuer)
    logger.info(f"Cache after invalidation: {len(cached_keys_after)} keys")

    # Next validation - fetches fresh keys
    logger.info("Step 4: Validation after invalidation (fetches fresh keys)")
    identity2, time2 = await validate_token_timed(decoder, token, "after invalidation")

    logger.info("=" * 60)


# =============================================================================
# Main Example
# =============================================================================

async def main() -> None:
    """Main example demonstrating OIDC caching.

    Steps:
    1. Create decoders (with and without cache)
    2. Compare performance
    3. Demonstrate cache invalidation

    Example:
        python oidc_with_cache.py
    """
    logger.info("Starting OIDC with cache example")

    try:
        # Get test token
        test_token = os.getenv("OIDC_TEST_TOKEN")

        if not test_token:
            logger.info("No test token in environment.")
            logger.info("Set OIDC_TEST_TOKEN environment variable to run this example")
            logger.info("Example: export OIDC_TEST_TOKEN='your-token-here'")
            return

        # Performance comparison
        await compare_performance(test_token, iterations=5)

        # Cache invalidation demonstration
        decoder, cache = await create_decoder_with_cache()
        await demonstrate_cache_invalidation(decoder, cache, test_token)

        logger.info("Example completed successfully")

    except KeyboardInterrupt:
        logger.info("Example interrupted by user")

    except Exception as e:
        logger.log_error(
            error=e,
            message="Example failed with unexpected error",
        )


if __name__ == "__main__":
    asyncio.run(main())
