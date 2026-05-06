# neoaxios-fastapi-kit

Production toolkit for FastAPI services. Provides authentication and authorization,
HTTP middleware, rate limiting, structured error handling, health endpoints, and
graceful shutdown — designed to be added incrementally to an existing FastAPI app.

## Install

```bash
pip install neoaxios-fastapi-kit
```

Requires Python 3.8+. Runtime dependencies include `fastapi`, `pydantic`, `prometheus-client`,
`pyjwt`, `cryptography`, `httpx`, plus several `neoaxios-*` foundation packages
(`neoaxios-logging`, `neoaxios-resilience-kit`, `neoaxios-secure-config`,
`neoaxios-secure-cache`). The latter four are not bundled in this repository and must be
installed separately.

## Components

| Module | What it provides |
|---|---|
| `auth.authn` | Token decoders: bearer/API-key, JWT (HS256/RS256), OIDC discovery, dev-only JWT, anonymous, multi-provider. Provider modules for Auth0, Azure AD (with Microsoft Graph role enrichment), Keycloak, Okta. |
| `auth.authz` | Permission resolvers, ownership/tenant checks, ABAC policy evaluator, FastAPI dependencies for `require_permission` / `require_tenant_access` / `require_ownership`, exception handlers. |
| `auth.config` | Pydantic-validated config schemas, hierarchical YAML/env loaders, secret resolution via `neoaxios-secure-config`. |
| `auth.middleware` | ASGI auth middleware that validates tokens once and attaches the resolved identity to `scope["state"]`. |
| `auth.inter_service` | HMAC-SHA256 request signing/verification primitives for service-to-service calls without mTLS. |
| `middleware` | `RequestCorrelationMiddleware`, `RetryAfterMiddleware`, `IdempotencyMiddleware`, `SecurityHeadersMiddleware`, `HttpMetricsMiddleware`, plus `add_cors_config`. |
| `ratelimit` | Token-bucket rate limiter, per-tenant / per-user / per-IP key builders, fail-closed enforcement, IETF-compliant rate-limit headers, Prometheus metrics. |
| `errors` | `StructuredHTTPException` and `add_error_handlers` for uniform `{"error": {"code", "message", "correlation_id"}}` responses. |
| `endpoints` | `add_health_endpoint` (with shallow/deep depth), `add_metrics_endpoint`, `add_info_endpoint`. |
| `shutdown` | Lifespan-based graceful shutdown helper that drains in-flight work on SIGTERM. |

## Quickstart

```python
from fastapi import FastAPI

from neoaxios_fastapi_kit import (
    add_error_handlers,
    add_health_endpoint,
    auto_trace_routes,
    create_graceful_shutdown_lifespan,
    IdempotencyMiddleware,
    RequestCorrelationMiddleware,
    RetryAfterMiddleware,
)
from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)

lifespan = create_graceful_shutdown_lifespan()
app = FastAPI(title="my-service", lifespan=lifespan)

app.add_middleware(RequestCorrelationMiddleware)
app.add_middleware(RetryAfterMiddleware)
app.add_middleware(IdempotencyMiddleware)

add_error_handlers(app)
add_health_endpoint(app, version="1.0.0")
auto_trace_routes(app, logger)
```

See the `examples/` and `docs/` directories for fuller scenarios (multi-provider OIDC,
Azure AD with multi-tenant + Graph enrichment, Docker-ready services, JWT generation).

## License

Apache License 2.0. See [LICENSE](LICENSE).
