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

"""
neoaxios_fastapi_kit - Production toolkit for FastAPI services.

Provides:
- Authentication & authorization framework
- Standard health/metrics endpoints
- Auto-telemetry wrapping
- CORS configuration
- Standardized error handling
- Graceful shutdown (lifespan-based)

Usage:
    from fastapi import FastAPI
    from neoaxios_logging import get_telemetry
    from neoaxios_fastapi_kit import (
        add_health_endpoint,
        add_error_handlers,
        create_graceful_shutdown_lifespan,
        auto_trace_routes,
        RequestCorrelationMiddleware,
        RetryAfterMiddleware,
        IdempotencyMiddleware,
    )

    logger = get_telemetry(__name__)

    # Recommended: Use lifespan pattern for shutdown
    lifespan = create_graceful_shutdown_lifespan()
    app = FastAPI(title="My Service", lifespan=lifespan)

    # Correlation IDs
    app.add_middleware(RequestCorrelationMiddleware)

    # Retry-After headers
    app.add_middleware(RetryAfterMiddleware)

    # Structured errors with debug control
    add_error_handlers(app)

    # Health with depth parameter
    add_health_endpoint(app, version="1.0.0")

    auto_trace_routes(app, logger)
"""

from .converters import convert_openapi_to_function_calling
from .endpoints import (
    add_health_endpoint,
    add_info_endpoint,
    add_metrics_endpoint,
    add_tools_endpoint,
    start_metrics_server,
)
from .errors import StructuredHTTPException, add_error_handlers
from .server_helpers import generate_consumer_name, sanitize_postgres_url
from .middleware import (
    HttpMetricsMiddleware,
    IdempotencyMiddleware,
    RequestCorrelationMiddleware,
    RetryAfterMiddleware,
    SecurityHeadersMiddleware,
    add_cors_config,
    add_http_metrics,
    add_security_headers,
    auto_trace_routes,
    get_asgi_header,
)
from .shutdown import add_graceful_shutdown, create_graceful_shutdown_lifespan

__version__ = "0.2.2"

__all__ = [
    # Endpoints
    "add_health_endpoint",
    "add_metrics_endpoint",
    "start_metrics_server",
    "add_tools_endpoint",
    "add_info_endpoint",
    # Middleware - request lifecycle
    "RequestCorrelationMiddleware",
    "RetryAfterMiddleware",
    "IdempotencyMiddleware",
    # Middleware - Observability
    "HttpMetricsMiddleware",
    "add_http_metrics",
    # Middleware - Configuration
    "add_cors_config",
    "add_security_headers",
    "SecurityHeadersMiddleware",
    "auto_trace_routes",
    # Error handling
    "add_error_handlers",
    "StructuredHTTPException",
    # Shutdown
    "add_graceful_shutdown",
    "create_graceful_shutdown_lifespan",
    # Converters
    "convert_openapi_to_function_calling",
    # ASGI utilities
    "get_asgi_header",
    # Server startup helpers
    "sanitize_postgres_url",
    "generate_consumer_name",
]
