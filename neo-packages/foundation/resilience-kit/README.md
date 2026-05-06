# neoaxios-resilience-kit

Resilience primitives for distributed Python services: rate limiting, circuit
breakers, and retry helpers. Designed to be wired into FastAPI services that
back onto Redis for shared state.

## What's in the box

### Rate limiting (`neoaxios_resilience_kit.ratelimit`)

- **Algorithms** — `FixedWindowAlgorithm`, `SlidingWindowAlgorithm`,
  `TokenBucketAlgorithm`. All three operate on the same `RateLimitBackend`
  protocol and namespaces their Redis keys with an algorithm discriminator
  prefix (`fw:`, `sw:`, `tb:`) so they can co-exist on a single Redis
  deployment without WRONGTYPE collisions.
- **Backends** — `RedisRateLimitBackend` (production, extends
  `secure_cache.RedisCacheBackend` for connection pooling and TLS) and
  `InMemoryRateLimitBackend` (unit tests only, no cross-worker coordination).
- **Configuration** — `RateLimitConfig` and `EndpointConfig` for per-endpoint
  rate limits with scope dispatch (user / tenant / IP / global). Built on
  `SecureSchema` from `neoaxios-secure-config` for frozen, log-safe configs.
- **Enforcement** — `RateLimitEnforcer` provides the check-record-respond loop
  and raises `RateLimitBackendError` (fail-closed) on backend unavailability.
- **Key building** — `HmacRateLimitKeyBuilder` constructs HMAC-obfuscated keys
  to prevent Redis key enumeration attacks.

### Circuit breaker (`neoaxios_resilience_kit.circuit_breaker`)

- `AsyncCircuitBreakerProtocol` — the public interface.
- `AsyncRedisCircuitBreaker` — async, distributed circuit breaker backed by
  `redis.asyncio` via the `secure_cache` gateway. State (CLOSED, OPEN,
  HALF_OPEN) is shared across workers.
- `create_async_circuit_breaker()` — factory that wires up the backend with a
  `CacheNamespace(domain="circuit")`.
- `CircuitBreakerConfig` — failure threshold, recovery timeout, half-open
  probe count, Redis TTL, and an explicit (default-False) `fail_open` switch.

### Retry (`neoaxios_resilience_kit.retry`)

- `retry_with_timeout()` — async retry helper with exponential backoff and a
  hard deadline. Non-retryable exceptions pass through untouched.
- `RetryBudgetExhausted` — raised when attempts or the deadline budget is
  exhausted; callers handle their own post-budget logic.

## Design choices

- **Fail-closed by default.** Rate-limit and circuit-breaker errors deny the
  request rather than allowing it. Distributed workers depend on Redis for
  shared state; a degraded backend is safer treated as "deny" than "allow."
  `CircuitBreakerConfig.fail_open` exists as an explicit per-deployment
  override but defaults to `False`.
- **Redis Cluster safe.** All backends use `transaction=False` pipelines and
  per-key delete operations; Lua scripts operate on a single key.
- **Namespace isolation.** Both rate limiting and circuit breakers require a
  `CacheNamespace` so multiple services sharing one Redis cluster cannot
  trample each other's state.
- **Atomic operations.** Sliding-window check-and-add and token-bucket
  refill-and-consume run as single Lua scripts to eliminate the
  read-then-write race that would otherwise allow two requests to both pass
  the limit check before either records its consumption.

## Installation

```bash
pip install neoaxios-resilience-kit
```

Or install from the monorepo:

```bash
pip install -e neo-packages/foundation/resilience-kit
```

## Quick start

### Rate limiting

```python
from neoaxios_resilience_kit.ratelimit import (
    create_redis_ratelimit_backend,
    create_fixed_window_algorithm,
    RateLimitEnforcer,
)

backend = create_redis_ratelimit_backend(
    org="neo",
    app="api",
    service="public-api",
    environment="prod",
)
algorithm = create_fixed_window_algorithm()
enforcer = RateLimitEnforcer(backend=backend, algorithm=algorithm)

result = await enforcer.check_and_record(
    key="user:42",
    limit=100,
    window_seconds=60,
)
if not result.allowed:
    raise HTTPException(429, headers={"Retry-After": str(result.retry_after)})
```

### Circuit breaker

```python
from neoaxios_secure_cache import CacheNamespace
from neoaxios_resilience_kit.circuit_breaker import (
    CircuitBreakerConfig,
    create_async_circuit_breaker,
)

breaker = create_async_circuit_breaker(
    config=CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout_seconds=60,
    ),
    namespace=CacheNamespace(
        org="neo", app="api", service="public-api",
        environment="prod", domain="circuit",
    ),
)

async with breaker.guard("payment-gateway"):
    return await call_payment_gateway()
```

### Retry

```python
from neoaxios_resilience_kit.retry import retry_with_timeout, RetryBudgetExhausted

try:
    response = await retry_with_timeout(
        operation=lambda: client.get("/health"),
        max_attempts=5,
        deadline_seconds=30,
        retryable_exceptions=(httpx.TransportError,),
    )
except RetryBudgetExhausted as exc:
    log.warning("upstream unhealthy", attempts=exc.attempts)
    raise
```

## License

Apache 2.0. See [LICENSE](LICENSE).
