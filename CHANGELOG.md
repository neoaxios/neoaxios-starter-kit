# Changelog

All notable changes to the NeoAxios Starter Kit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each package under `neo-packages/` is versioned independently; the version
column in the top-level [README](README.md) is authoritative for the current
release. This file records changes at the kit level — package additions,
removals, and cross-cutting changes that affect the whole repository.

## [Unreleased]

### Changed

- `neoaxios-fastapi-kit` → 0.2.2: rewrote `RequestCorrelationMiddleware`
  and `RetryAfterMiddleware` from `starlette.middleware.base.BaseHTTPMiddleware`
  to raw ASGI middleware (`__call__(scope, receive, send)`). Feature-parity
  with the prior implementation; the rewrite eliminates `BaseHTTPMiddleware`'s
  task-wrap and body-buffer overhead (~120-180 µs/request) and the known
  poor interaction with `StreamingResponse`. Measured on AMD Ryzen 9 7950X3D:
  hello-world kit-wired throughput improves from 8,254 RPS → 30,059 RPS
  (`GET /ping`, 1 worker, +264%); 5,241 RPS → 20,167 RPS (`POST /chat` with
  Pydantic body, 1 worker, +285%). At 16-worker host saturation: 232,800
  RPS (`/ping`) / 185,627 RPS (`/chat`) for kit-wired endpoints, within
  9-10% of the bare FastAPI ceiling. No API changes for consumers —
  `app.add_middleware(RequestCorrelationMiddleware)` and
  `app.add_middleware(RetryAfterMiddleware)` continue to work identically;
  `request.state.correlation_id` populates the same way (now wrapped via
  `starlette.datastructures.State` so FastAPI 0.103+ dict-shaped lifespan
  state is handled correctly).

## [0.2.1] — 2026-05-05

Initial public release of the NeoAxios Starter Kit.

### Added

- `neoaxios-build-system` — dependency-aware parallel build orchestrator with
  hash-based caching for Python wheels and Docker images.
- `neoaxios-logging` — structured logging (Logbook) and timeline-based event
  recording (FlightRecorder), built on `structlog`.
- `neoaxios-config` — hierarchical YAML configuration loader with deep-merge
  and environment-variable substitution.
- `neoaxios-secure-config` — security-hardened configuration loader with
  file-driven value sources, masked secrets, and runtime resource detection.
- `neoaxios-secure-cache` — defense-in-depth cache wrappers with HMAC
  signing, AES-256-GCM encryption, canary tampering detection, and replay
  protection over Redis and in-memory backends.
- `neoaxios-secret-store` — Vault-backed secret store with read-through TTL
  caching, AppRole authentication, and explicit fail-closed semantics.
- `neoaxios-resilience-kit` — rate limiting (fixed window, sliding window,
  token bucket), distributed circuit breaker, and async retry with
  deadlines.
- `neoaxios-stripe-kit` — structured error taxonomy and translator for the
  Stripe Python SDK.
- `neoaxios-test-foundation` — shared pytest infrastructure: fixtures,
  mocks (LLM server, SSH server, generic service endpoint), Redis test
  utilities, namespace management, latency statistics.
- `neoaxios-fastapi-kit` — FastAPI toolkit covering authentication,
  authorization, rate limiting, request correlation, idempotency, security
  headers, and structured errors.
- `neoaxios-sse-kit` — Server-Sent Events (W3C `text/event-stream`) parsing
  and serialization.
- Top-level `Makefile`, `build.yaml`, and license-parity check that drive
  `make build` (parallel wheel + Docker builds, content-hash cached).

[Unreleased]: https://github.com/neoaxios/neoaxios-starter-kit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/neoaxios/neoaxios-starter-kit/releases/tag/v0.2.1
