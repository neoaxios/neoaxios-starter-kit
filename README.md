# NeoAxios Starter Kit

**Get a production Python webservice up and running, fast.**

Standing up a real webservice means writing the same plumbing every time:
authentication and authorization, rate limiting, request correlation, structured
errors, idempotency, security headers, observability, build and packaging.
This repository publishes the abstractions we built to ship our own services,
so you don't have to write them again.

Drop in `neoaxios-fastapi-kit` and you have a FastAPI app with auth, rate
limiting, idempotency, and consistent error responses on day one. Add
`neoaxios-logging` for structured logs and timeline-based event recording.
Layer in `neoaxios-secure-config` for masked-secret configuration, paired
with `neoaxios-config` for hierarchical YAML settings. Add
`neoaxios-secure-cache` for tamper-evident, encrypted Redis-backed caching,
and `neoaxios-resilience-kit` for rate limiting, circuit breakers, and
retries with deadlines. Use `neoaxios-sse-kit` when you need streaming,
`neoaxios-test-foundation` for shared pytest fixtures and mocks, and
`neoaxios-build-system` to build and cache wheels and Docker images across
a multi-package repo. Each package is independently versioned and
installable on its own — pick the pieces you want, leave the rest.

## Packages

| Package | Description | Version |
|---|---|---|
| [`neoaxios-logging`](neo-packages/logging/) | Structured logging (Logbook) and timeline-based event recording (FlightRecorder), built on `structlog`. | 0.2.1 |
| [`neoaxios-config`](neo-packages/foundation/config/) | Hierarchical YAML configuration loader with deep-merge and environment-variable substitution. | 0.2.1 |
| [`neoaxios-secure-config`](neo-packages/foundation/secure_config/) | Security-hardened configuration loader: file-driven value sources, masked secrets, runtime resource detection. | 0.2.1 |
| [`neoaxios-secure-cache`](neo-packages/foundation/secure_cache/) | Defense-in-depth cache wrappers: HMAC signing, AES-256-GCM encryption, canary tampering detection, replay protection, with Redis and in-memory backends. | 0.2.1 |
| [`neoaxios-secret-store`](neo-packages/foundation/secret_store/) | Vault-backed secret store with read-through TTL caching, AppRole authentication, and explicit fail-closed semantics. | 0.2.1 |
| [`neoaxios-stripe-kit`](neo-packages/foundation/stripe_kit/) | Structured error taxonomy and translator for the Stripe Python SDK — uniform exception handling with retryable/non-retryable distinction preserved. *(Early-stage; expected to grow.)* | 0.0.1 |
| [`neoaxios-resilience-kit`](neo-packages/foundation/resilience-kit/) | Resilience primitives for distributed services: rate limiting (fixed window, sliding window, token bucket), distributed circuit breaker, async retry with deadlines. | 0.2.1 |
| [`neoaxios-test-foundation`](neo-packages/foundation/test-foundation/) | Shared pytest infrastructure: fixtures, mocks (LLM server, SSH server, generic service endpoint), Redis test utilities, namespace management, latency statistics. | 0.2.1 |
| [`neoaxios-fastapi-kit`](neo-packages/foundation/fastapi_kit/) | FastAPI toolkit: authentication, authorization, rate limiting, request correlation, idempotency, security headers, structured errors. | 0.2.2 |
| [`neoaxios-sse-kit`](neo-packages/foundation/sse-kit/) | Server-Sent Events (W3C `text/event-stream`) parsing and serialization. | 0.2.1 |
| [`neoaxios-build-system`](neo-packages/neoaxios-build/) | Dependency-aware parallel build orchestrator with hash-based caching for Python wheels and Docker images. | 0.2.1 |

## Layout

```
neo-packages/
  foundation/
    config/           # neoaxios-config
    fastapi_kit/      # neoaxios-fastapi-kit
    resilience-kit/   # neoaxios-resilience-kit
    secret_store/     # neoaxios-secret-store
    secure_cache/     # neoaxios-secure-cache
    secure_config/    # neoaxios-secure-config
    sse-kit/          # neoaxios-sse-kit
    stripe_kit/       # neoaxios-stripe-kit
    test-foundation/  # neoaxios-test-foundation
  logging/            # neoaxios-logging
  neoaxios-build/     # neoaxios-build-system
```

Each package has its own `pyproject.toml`, `LICENSE`, and `README.md`, and is installable
on its own.

## Requirements

- Python 3.8+ for `neoaxios-logging`, `neoaxios-config`, `neoaxios-fastapi-kit`
- Python 3.10+ for `neoaxios-build-system`, `neoaxios-secure-config`, `neoaxios-secure-cache`, `neoaxios-resilience-kit`
- Python 3.11+ for `neoaxios-sse-kit`, `neoaxios-secret-store`, `neoaxios-stripe-kit`
- Python 3.12+ for `neoaxios-test-foundation`
- See each package's `pyproject.toml` for runtime dependencies

## Installation

Install a specific package directly from its directory:

```bash
pip install neo-packages/logging
pip install neo-packages/foundation/config
pip install neo-packages/foundation/secure_config
pip install neo-packages/foundation/secure_cache
pip install neo-packages/foundation/secret_store
pip install neo-packages/foundation/stripe_kit
pip install neo-packages/foundation/resilience-kit
pip install neo-packages/foundation/test-foundation
pip install neo-packages/foundation/sse-kit
pip install neo-packages/foundation/fastapi_kit
pip install neo-packages/neoaxios-build
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
