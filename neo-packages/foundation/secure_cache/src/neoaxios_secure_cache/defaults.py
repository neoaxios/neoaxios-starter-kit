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

"""Default tuning constants for secure_cache.

Single source of truth for cache TTLs, Redis client pool sizing and
timeouts, HTTP-client connection limits, security-component tuning
(canary intervals, sequence-tracker cache size), and inter-service
HMAC tolerances.

Override these values per-deployment by passing them explicitly to the
relevant factory function or configuration object — they are defaults,
not hard limits.

Usage:
    from neoaxios_secure_cache.defaults import (
        REDIS_SOCKET_TIMEOUT,
        REDIS_POOL_SIZE_CACHE,
        CACHE_TTL_LONG,
    )
"""

# =============================================================================
# Cache TTLs (seconds)
# =============================================================================

CACHE_TTL_SHORT: int = 300
"""Five minutes. Suitable for short-lived per-request caches."""

CACHE_TTL_MEDIUM: int = 3600
"""One hour. Suitable for moderately stable lookups (e.g. metadata)."""

CACHE_TTL_LONG: int = 86400
"""One day. Suitable for slow-changing data (e.g. JWKS, idempotency keys)."""


# =============================================================================
# Redis Client — Connection & Pooling
# =============================================================================

REDIS_DEFAULT_TOPOLOGY: str = "cluster"
"""Default Redis topology when callers do not specify one."""

REDIS_SOCKET_TIMEOUT: float = 5.0
"""Per-command socket timeout in seconds."""

REDIS_POOL_WAIT_TIMEOUT: float = 20.0
"""Maximum time (seconds) a caller waits for a free pool connection
when all slots are in use. Independent from ``REDIS_SOCKET_TIMEOUT``,
which governs network I/O once a connection is acquired."""

REDIS_HEALTH_CHECK_INTERVAL: int = 60
"""Seconds between pool-connection health-check PINGs (redis-py
``health_check_interval``). Prevents stale connections from being
handed back to callers after long idle periods."""

REDIS_POOL_SIZE_CACHE: int = 5000
"""Connection-pool size for cache-tier Redis clients."""

REDIS_POOL_SIZE_CLIENT: int = 5000
"""Connection-pool size for general-purpose Redis clients."""

REDIS_CLUSTER_POOL_SIZE_PER_NODE: int = 500
"""Per-node pool cap when the topology is ``cluster``. Prevents the
N-nodes multiplier from creating excessive total connections."""

REDIS_CLUSTER_RETRY_ATTEMPTS: int = 3
"""Number of exponential-backoff retries on transient cluster errors."""

REDIS_POOL_SIZE_RATELIMIT: int = 50
"""Connection-pool size for the rate-limiting Redis client. Smaller than
the cache-tier pool because rate-limit operations are short-lived."""


# =============================================================================
# Circuit Breaker
# =============================================================================

CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
"""Consecutive failures before the breaker transitions CLOSED → OPEN."""

CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS: int = 60
"""Time the breaker stays OPEN before transitioning to HALF_OPEN."""

CIRCUIT_BREAKER_HALF_OPEN_MAX_CALLS: int = 1
"""Maximum concurrent probe calls allowed in HALF_OPEN state."""

CIRCUIT_BREAKER_STATE_TTL_SECONDS: int = 3600
"""Expiry on the Redis-backed breaker state key. Long enough to cover
typical recovery windows; the entry naturally renews on any state change."""


# =============================================================================
# HTTP Client (httpx)
# =============================================================================

HTTPX_MAX_CONNECTIONS: int = 10
"""Maximum total connections in the httpx connection pool."""

HTTPX_MAX_KEEPALIVE_CONNECTIONS: int = 5
"""Maximum idle keep-alive connections retained in the pool."""

HTTPX_MAX_RETRIES: int = 3
"""Maximum retry attempts for transient HTTP failures."""


# =============================================================================
# Secret Store (Vault TTL cache)
# =============================================================================

SECRET_STORE_CACHE_TTL_SECONDS: int = 300
"""TTL for in-process secret cache entries. Read-through only; never
refreshed on a cache hit. Five minutes balances Vault load against
key-rotation latency."""

SECRET_STORE_HTTP_TIMEOUT_SECONDS: float = 5.0
"""Connect + read timeout for Vault HTTP calls. Keeps a wedged Vault
control plane from holding application threads indefinitely."""


# =============================================================================
# Service Lifecycle
# =============================================================================

DEFAULT_RETRY_SECONDS: int = 60
"""Default ``Retry-After`` value (seconds) for 429/503 responses."""

GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: int = 30
"""Grace period for in-flight work to drain on SIGTERM before forced exit."""


# =============================================================================
# Idempotency
# =============================================================================

IDEMPOTENCY_CACHE_RETRY_DELAY_S: float = 1.0
"""Delay between retries when the idempotency cache is unavailable."""

IDEMPOTENCY_MAX_BODY_SIZE_BYTES: int = 1_048_576  # 1 MiB
"""Maximum request-body size hashed into the idempotency key. Bodies
larger than this skip the body-hash component to avoid extra memory
allocation; FastAPI buffers the full body for JSON parsing regardless,
so the cap only affects the hashing step."""


# =============================================================================
# Inter-Service HMAC Signing
# =============================================================================

INTER_SERVICE_HMAC_TIMESTAMP_TOLERANCE_SECONDS: int = 300
"""Maximum allowed clock skew between signer and verifier on signed
inter-service requests. Five minutes balances NTP drift against the
replay-protection window."""


# =============================================================================
# Cache Security — Canary Monitor
# =============================================================================

CANARY_CHECK_INTERVAL_SECONDS: float = 5.0
"""Background interval at which the canary monitor verifies cache
integrity by reading and comparing canary values."""

CANARY_INLINE_CHECK_PROBABILITY: float = 0.01
"""Probability (0.0–1.0) that an inline cache operation triggers an
opportunistic canary check. 1% gives quick tampering detection without
adding meaningful latency to the hot path."""


# =============================================================================
# Cache Security — Tamper Detection
# =============================================================================

AUTO_RECOVERY_THRESHOLD: int = 10
"""Consecutive successful canary verifications required before tamper
detection automatically clears the alarm."""


# =============================================================================
# Cache Security — Sequence Tracker (replay protection)
# =============================================================================

SEQUENCE_TRACKER_LOCAL_CACHE_SIZE: int = 10_000
"""Per-process LRU size for cached sequence numbers, bounding memory
under high-fan-out replay-protection workloads."""


# =============================================================================
# Cache Security — Tenant Key Cache
# =============================================================================

TENANT_KEY_CACHE_SIZE: int = 1000
"""LRU size for the per-tenant derived-key cache (HKDF outputs)."""


# =============================================================================
# Cache Security — Crypto Executor
# =============================================================================

CRYPTO_EXECUTOR_MIN_CORES: int = 4
"""Minimum CPU cores below which the crypto thread pool is not used
(operations run inline instead)."""

CRYPTO_EXECUTOR_FALLBACK_CPUS: int = 4
"""Fallback worker count when CPU-count detection is unavailable."""

CRYPTO_EXECUTOR_MAX_WORKERS: int = 8
"""Hard cap on crypto-executor worker threads."""


# =============================================================================
# Redis Streams
# =============================================================================

STREAM_MAXLEN: int = 10_000
"""Default ``MAXLEN`` for Redis streams used as bounded queues."""
