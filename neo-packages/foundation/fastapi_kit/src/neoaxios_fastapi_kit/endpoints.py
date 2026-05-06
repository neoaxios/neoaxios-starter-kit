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

"""Standard endpoint helpers for FastAPI services."""

from __future__ import annotations

import os
import time
from collections.abc import Awaitable, Callable
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query
from starlette.responses import JSONResponse, Response

from prometheus_client import (
    CollectorRegistry,
    CONTENT_TYPE_LATEST,
    generate_latest,
)
from neoaxios_logging import auto_trace, get_telemetry

from .converters import convert_openapi_to_function_calling

logger = get_telemetry(__name__)

# Multiprocess support: when PROMETHEUS_MULTIPROC_DIR is set, metrics are shared
# across processes (API server + Celery worker) via filesystem-backed mmap files.
# The /metrics endpoint aggregates from all processes using MultiProcessCollector.
_MULTIPROCESS_AVAILABLE = False

if os.environ.get("PROMETHEUS_MULTIPROC_DIR") or os.environ.get("prometheus_multiproc_dir"):
    from prometheus_client import multiprocess as _prometheus_multiprocess

    _MULTIPROCESS_AVAILABLE = True
    logger.info(
        "prometheus_multiprocess_enabled",
        dir=os.environ.get("PROMETHEUS_MULTIPROC_DIR")
        or os.environ.get("prometheus_multiproc_dir"),
    )


def _create_multiprocess_registry() -> CollectorRegistry:  # notrace: setup helper
    """Create a fresh CollectorRegistry with MultiProcessCollector attached.

    Used by both ``add_metrics_endpoint`` (per-request) and
    ``start_metrics_server`` (daemon thread) to aggregate metrics from
    all worker processes via filesystem-backed mmap files.

    Returns:
        A CollectorRegistry instance with multiprocess aggregation.
    """
    registry = CollectorRegistry()
    _prometheus_multiprocess.MultiProcessCollector(registry)
    return registry


@auto_trace(logger)
def add_health_endpoint(
    app: FastAPI,
    version: str = "1.0.0",
    start_time: Optional[float] = None,
    path: str = "/health",
    check_deep: Callable[[], Awaitable[dict[str, Any]]] | None = None,
) -> None:
    """Add a standard health check endpoint with an optional depth parameter.

    Args:
        app: FastAPI application instance
        version: Service version string
        start_time: Service start timestamp (defaults to current time)
        path: Health endpoint path (default: /health)
        check_deep: Optional async function returning dependency health for ?depth=deep

    Endpoint returns (shallow):
        {
            "status": "healthy",
            "version": "1.0.0",
            "uptime_seconds": 123.45
        }

    Endpoint returns (deep, when check_deep provided):
        {
            "status": "healthy",
            "version": "1.0.0",
            "uptime_seconds": 123.45,
            "dependencies": {
                "database": {"status": "healthy", "latency_ms": 5},
                "cache": {"status": "healthy", "latency_ms": 2}
            }
        }

    Usage:
        # Basic health endpoint
        app = FastAPI()
        add_health_endpoint(app, version="1.0.0")

        # With deep health check
        async def check_dependencies():
            return {
                "database": {"status": "healthy", "latency_ms": 5},
                "cache": {"status": "healthy", "latency_ms": 2},
            }

        add_health_endpoint(app, version="1.0.0", check_deep=check_dependencies)
    """
    if start_time is None:
        start_time = time.time()

    # NOTE: No @auto_trace - Route handler, excluded from auto_trace_routes() by
    # default (/health). Avoids log noise from frequent Kubernetes health checks.
    @app.get(path, tags=["health"])
    async def health_check(
        depth: str = Query(
            default="shallow",
            description="Health check depth: 'shallow' or 'deep'",
            pattern="^(shallow|deep)$",
        ),
    ) -> dict[str, Any]:
        """Service health check for Kubernetes liveness probes.

        Args:
            depth: Check depth - 'shallow' (default) or 'deep' for dependency checks.

        Returns:
            Health status with optional dependency information.
        """
        response: dict[str, Any] = {
            "status": "healthy",
            "version": version,
            "uptime_seconds": round(time.time() - start_time, 2),
        }

        # Deep health check includes dependency status
        if depth == "deep" and check_deep is not None:
            try:
                dependencies = await check_deep()
                response["dependencies"] = dependencies

                # Check if any dependency is unhealthy
                for dep_name, dep_status in dependencies.items():
                    if isinstance(dep_status, dict):
                        status = dep_status.get("status", "unknown")
                        if status not in ("healthy", "ok", "up"):
                            response["status"] = "degraded"
                            break
            except Exception as e:
                logger.warning(
                    "health_check_deep_failed",
                    error=str(e),
                )
                response["dependencies"] = {"error": str(e)}
                response["status"] = "degraded"

        return response


@auto_trace(logger)
def add_metrics_endpoint(
    app: FastAPI,
    path: str = "/metrics",
    registry: CollectorRegistry | None = None,
) -> None:
    """Add a metrics endpoint serving Prometheus exposition format.

    Serves the given *registry* (or the process-global default) via
    ``generate_latest()`` with Content-Type
    ``text/plain; version=0.0.4; charset=utf-8``.

    In multiprocess mode (``PROMETHEUS_MULTIPROC_DIR`` set), aggregates
    metrics from all processes (API server + Celery workers) via
    filesystem-backed mmap files using ``MultiProcessCollector``.
    The *registry* parameter is ignored in multiprocess mode.

    Args:
        app: FastAPI application instance.
        path: Metrics endpoint path (default: /metrics).
        registry: Optional CollectorRegistry to serve.  When ``None``
            (default), serves the process-global default registry.
            Primarily used by integration tests to isolate metrics.

    Usage:
        app = FastAPI()
        add_metrics_endpoint(app)
    """
    # Capture registry in closure so the handler always serves the
    # correct registry without module-level monkey-patching.
    _registry = registry

    # NOTE: No @auto_trace - Route handler, excluded from auto_trace_routes() by
    # default (/metrics). Avoids log noise from frequent Prometheus scraping.
    @app.get(path, tags=["metrics"])
    def get_metrics() -> Response:
        """Service metrics endpoint."""
        try:
            if _MULTIPROCESS_AVAILABLE:
                # Multiprocess mode: create a fresh registry and aggregate
                # metrics from all processes (API + Celery workers) via
                # shared filesystem-backed mmap files.
                mp_registry = _create_multiprocess_registry()
                metrics_output = generate_latest(mp_registry)
            elif _registry is not None:
                metrics_output = generate_latest(_registry)
            else:
                metrics_output = generate_latest()
            return Response(
                content=metrics_output,
                media_type=CONTENT_TYPE_LATEST,
            )
        except Exception as exc:
            logger.log_error(exc)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "metrics_generation_failed",
                    "detail": str(exc),
                },
            )


@auto_trace(logger)
def start_metrics_server(port: int) -> None:
    """Start a standalone Prometheus metrics HTTP server on a daemon thread.

    Wraps ``prometheus_client.start_http_server()`` which spawns a daemon
    thread running ``http.server.HTTPServer``.  In multiprocess mode
    (``PROMETHEUS_MULTIPROC_DIR`` set), creates a fresh ``CollectorRegistry``
    with ``MultiProcessCollector`` so the server aggregates metrics from all
    worker processes via filesystem-backed mmap files.

    Must be called **once** in the master process before worker fork
    (e.g., in ``serve_command()``).  Calling per-worker would cause
    ``OSError: Address already in use``.

    Args:
        port: TCP port number for the metrics HTTP server.
    """
    from prometheus_client import start_http_server

    if _MULTIPROCESS_AVAILABLE:
        registry = _create_multiprocess_registry()
        start_http_server(port, registry=registry)
        logger.info(
            "metrics_server_started",
            port=port,
            multiprocess=True,
        )
    else:
        start_http_server(port)
        logger.info(
            "metrics_server_started",
            port=port,
            multiprocess=False,
        )


@auto_trace(logger)
def add_tools_endpoint(
    app: FastAPI,
    path: str = "/tools",
    include_paths: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> None:
    """
    Add function calling discovery endpoint.

    Converts OpenAPI schema to OpenAI function calling format.
    Useful for clients that prefer this format over standard OpenAPI.

    Args:
        app: FastAPI application instance
        path: Tools endpoint path (default: /tools)
        include_paths: Only include these paths (regex patterns)
        exclude_paths: Exclude these paths (default: /health, /metrics, /info, /tools)

    Endpoint returns:
        {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "create_analysis",
                        "description": "Analyze text sentiment and extract topics.",
                        "parameters": {...}
                    }
                }
            ]
        }

    Usage:
        app = FastAPI()
        add_tools_endpoint(app)
        # Clients can discover functions via GET /tools
    """
    if exclude_paths is None:
        exclude_paths = ["/health", "/metrics", "/info", "/tools", "/docs", "/redoc", "/openapi.json"]

    # NOTE: No @auto_trace - Route handler, excluded from auto_trace_routes() by
    # default (/tools). Avoids log noise from frequent API discovery requests.
    @app.get(path, tags=["tools"])
    def get_tools():
        """
        Function discovery endpoint.

        Returns OpenAPI schema converted to OpenAI function calling format
        for clients that prefer this format.
        """
        openapi_schema = app.openapi()
        return convert_openapi_to_function_calling(
            openapi_schema,
            include_paths=include_paths,
            exclude_paths=exclude_paths,
        )


@auto_trace(logger)
def add_info_endpoint(
    app: FastAPI,
    path: str = "/info",
    git_commit: Optional[str] = None,
    build_time: Optional[str] = None,
    extra_info: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Add service information endpoint.

    Args:
        app: FastAPI application instance
        path: Info endpoint path (default: /info)
        git_commit: Git commit SHA
        build_time: Build timestamp
        extra_info: Additional metadata to include

    Endpoint returns:
        {
            "title": "My Service",
            "version": "1.0.0",
            "git_commit": "abc123...",
            "build_time": "2025-11-18T12:00:00Z",
            "openapi_url": "/openapi.json"
        }

    Usage:
        app = FastAPI(title="Analysis Service", version="1.0.0")
        add_info_endpoint(app, git_commit="abc123", build_time="2025-11-18")
    """
    # NOTE: No @auto_trace - Route handler, excluded from auto_trace_routes() by
    # default (/info). Avoids log noise from service discovery requests.
    @app.get(path, tags=["info"])
    def service_info():
        """Service metadata and build information."""
        info = {
            "title": app.title,
            "version": app.version,
            "openapi_url": app.openapi_url or "/openapi.json",
        }

        if git_commit:
            info["git_commit"] = git_commit

        if build_time:
            info["build_time"] = build_time

        if extra_info:
            info.update(extra_info)

        return info
