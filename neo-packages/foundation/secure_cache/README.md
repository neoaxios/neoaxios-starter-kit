# neoaxios-secure-cache

Caching infrastructure with defense-in-depth security layers. Wraps a backend
(Redis or in-memory) with optional HMAC signing, AES-256-GCM encryption,
canary-based tampering detection, and replay protection — composed in
encrypt-then-sign order so tampering is detected before decryption.

## Install

```bash
pip install neoaxios-secure-cache
```

Requires Python 3.10+. Depends on `neoaxios-logging`, `neoaxios-secure-config`,
`redis>=7.0`, `cryptography>=46.0.7`, `prometheus-client`, and `msgpack`.

## What it provides

| Module | Purpose |
|---|---|
| `secure_cache.factories` | `create_secure_cache` — single instantiation point that assembles the full encrypt-then-sign stack from a `SecureCacheConfig`. |
| `secure_cache.protocols` | `CacheBackend` protocol implemented by every backend and wrapper, plus batch-operation defaults. |
| `secure_cache.backends.redis` | `RedisCacheBackend`, JSON-serialized, atomic SETEX. |
| `secure_cache.backends.memory` | `InMemoryCacheBackend` for development and tests. |
| `secure_cache.namespace` | `CacheNamespace` / `KeyTier` — hierarchical key prefixing (`org → env → svc → app → tier`). |
| `secure_cache.gateway` | Connection-gateway protocol — every Redis client goes through `get_gateway().get_async_client(purpose)` for shared pool ownership. |
| `secure_cache.redis.client` | `RedisClientConfig` and `create_async_redis_client` (standalone / sentinel / cluster). |
| `secure_cache.security.signing` | `SigningCacheWrapper` — HMAC-SHA256 integrity verification with timing-safe compare and key obfuscation. |
| `secure_cache.security.encryption` | `EncryptingCacheWrapper` — AES-256-GCM with per-tenant keys derived via HKDF. |
| `secure_cache.security.keys` | `derive_kek`, `derive_signing_key`, `derive_tenant_key`, `TenantKeyCache` (LRU). |
| `secure_cache.security.canary` | `CanaryMonitor` — background and inline tampering detection (1% inline check probability). |
| `secure_cache.security.sequence` | `SequenceTracker` — replay protection via monotonic sequence numbers. |
| `secure_cache.security.tamper_detection` | `TamperDetectionState` with auto-recovery threshold. |
| `secure_cache.security.sensitive` | `is_sensitive_permission` — pattern-based bypass for sensitive permission checks. |
| `secure_cache.metrics` | Prometheus metrics for cache hits/misses, integrity violations, latency. |
| `secure_cache.health` | `get_cache_health` — depth-aware health check for use with FastAPI's deep-health endpoints. |
| `secure_cache.key_registry` | Discovers and merges per-package `cache-key-registry.yaml` files into a single `CacheKeyRegistry`. |
| `secure_cache.testing.validation` | `ValidatingCacheWrapper` — at test time, raises on undeclared keys to enforce registry discipline. |
| `secure_cache.serialization` | Pluggable `JsonSerializer` / `MsgpackSerializer` / `SmartSerializer`. |
| `secure_cache.defaults` | Tunable defaults for cache TTLs, Redis pool sizing, HTTP-client limits, security tuning. |

## Quickstart

```python
from neoaxios_secure_cache import create_secure_cache, CacheNamespace
from neoaxios_secure_cache.config import SecureCacheConfig

namespace = CacheNamespace(
    org="myorg", env="prod", svc="api", app="gateway", version="v1",
)

config = SecureCacheConfig(
    tenant_id="tenant-123",
    master_key="env:CACHE_MASTER_KEY",
)

cache = create_secure_cache(config, namespace=namespace, environment="production")

await cache.set("user:42:permissions", {"read": True}, ttl_seconds=300)
value = await cache.get("user:42:permissions")
```

## Wrapper composition (encrypt-then-sign)

```
caller
  │
  ▼
SigningCacheWrapper           ← HMAC-SHA256, timing-safe compare
  │
  ▼
EncryptingCacheWrapper        ← AES-256-GCM, per-tenant keys
  │
  ▼
RedisCacheBackend / InMemoryCacheBackend
```

This order ensures plaintext is never exposed to the signing layer, the
signature covers ciphertext, and tampering is detected before decryption.

## Cache-key registry

Packages declare the Redis key families they own in their own
`cache-key-registry.yaml`. The loader discovers all such files in the project
tree and merges them; key names must be globally unique. See
`cache-key-registry.yaml` in this package for the schema and an example.

## Monitoring

`secure_cache.metrics.SecureCacheMetrics` emits Prometheus counters, histograms,
and gauges for cache hits/misses, integrity violations, replay detections,
canary mismatches, and operation latency. Recommended alert thresholds are
documented at the top of `secure_cache/metrics.py`.

A ready-to-import Grafana dashboard for these metrics ships at
[`dashboards/secure-cache-monitoring.json`](dashboards/secure-cache-monitoring.json).
It targets a Prometheus datasource named `Prometheus` and uses a `$tenant`
template variable; adjust the datasource and templating to match your
deployment before importing.

## License

Apache License 2.0. See [LICENSE](LICENSE).
