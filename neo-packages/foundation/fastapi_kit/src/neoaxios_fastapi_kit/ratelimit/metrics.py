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

"""Comprehensive Prometheus metrics for rate limiting.

Metrics exported:
- Counters: requests, denials, backend errors, cost
- Histograms: latency, remaining capacity
- Gauges: backend health

Implementation Notes:
- All methods decorated with @auto_trace for observability
- Thread-safe metric recording
- Telemetry logging always emitted alongside Prometheus metrics
"""


from prometheus_client import Counter, Gauge, Histogram
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class RateLimitMetrics:
    """Prometheus metrics collector for rate limiting.

    Provides comprehensive metrics for rate limiting monitoring and alerting.
    Records to both Prometheus and neoaxios-logging telemetry.

    Attributes:
        _enable_endpoint_labels: Whether to include endpoint labels in metrics
    """

    @auto_trace(logger)
    def __init__(self, enable_endpoint_labels: bool = False, registry=None) -> None:
        """Initialize Prometheus metrics.

        Args:
            enable_endpoint_labels: Whether to include endpoint-specific labels
            registry: Optional CollectorRegistry for metric registration.
                      Defaults to the global default registry.
        """
        self._enable_endpoint_labels = enable_endpoint_labels
        self._registry = registry

        self._init_prometheus_metrics()
        logger.info(
            "Initialized RateLimitMetrics",
            enable_endpoint_labels=enable_endpoint_labels,
        )

    @auto_trace(logger)
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metric objects.

        Creates Counter, Histogram, and Gauge objects for all metrics.
        Only called when prometheus-client is available.
        Uses self._registry if provided, otherwise the default global registry.

        Label sets for checks_total, denials_total, check_duration, and
        remaining_ratio are built conditionally based on self._enable_endpoint_labels
        before metric object creation (Prometheus label cardinality is
        immutable after registration).
        """
        reg = {"registry": self._registry} if self._registry is not None else {}

        # Build label sets conditionally (must happen before metric creation)
        checks_labels = (
            ["scope", "status", "endpoint"]
            if self._enable_endpoint_labels
            else ["scope", "status"]
        )
        scope_labels = (
            ["scope", "endpoint"]
            if self._enable_endpoint_labels
            else ["scope"]
        )

        # Counters
        self.checks_total = Counter(
            "ratelimit_checks_total",
            "Total rate limit checks",
            checks_labels,
            **reg,
        )

        self.denials_total = Counter(
            "ratelimit_denials_total",
            "Total rate limit denials",
            scope_labels,
            **reg,
        )

        self.backend_errors_total = Counter(
            "ratelimit_backend_errors_total",
            "Rate limit backend errors",
            ["backend", "error_type"],
            **reg,
        )

        self.cost_total = Counter(
            "ratelimit_cost_total",
            "Total rate limit cost consumed (allowed checks only)",
            ["scope"],
            **reg,
        )

        # Histograms
        self.check_duration = Histogram(
            "ratelimit_check_duration_seconds",
            "Rate limit check latency",
            scope_labels,
            buckets=[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            **reg,
        )

        self.remaining_ratio = Histogram(
            "ratelimit_remaining_ratio",
            "Remaining capacity ratio (0.0-1.0)",
            scope_labels,
            buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            **reg,
        )

        # Gauges
        self.backend_healthy = Gauge(
            "ratelimit_backend_healthy",
            "Backend health status (1=healthy, 0=unhealthy)",
            ["backend"],
            **reg,
        )

        logger.debug("Prometheus metrics initialized")

    @auto_trace(logger)
    def record_check(
        self,
        scope: str,
        allowed: bool,
        remaining: int,
        limit: int,
        duration_seconds: float,
        *,
        endpoint: str | None = None,
        cost: int = 1,
    ) -> None:
        """Record a rate limit check.

        Args:
            scope: Rate limit scope (user, tenant, ip, global)
            allowed: Whether the request was allowed
            remaining: Remaining capacity
            limit: Total limit
            duration_seconds: Check duration in seconds
            endpoint: Optional endpoint path for label inclusion
            cost: Request cost consumed; increments cost_total on allowed checks
        """
        status = "allowed" if allowed else "denied"

        # Build label dicts once for all metric calls (Finding #29/#43)
        if self._enable_endpoint_labels:
            ep = endpoint or ""
            checks_labels = {"scope": scope, "status": status, "endpoint": ep}
            scope_labels = {"scope": scope, "endpoint": ep}
        else:
            checks_labels = {"scope": scope, "status": status}
            scope_labels = {"scope": scope}

        self.checks_total.labels(**checks_labels).inc()

        if not allowed:
            self.denials_total.labels(**scope_labels).inc()

        if allowed:
            self.cost_total.labels(scope=scope).inc(cost)

        self.check_duration.labels(**scope_labels).observe(duration_seconds)

        if limit > 0:
            ratio = remaining / limit
            self.remaining_ratio.labels(**scope_labels).observe(ratio)

        # Log to telemetry
        logger.record_metric(
            "ratelimit.check",
            1,
            tags={"scope": scope, "status": status},
        )

        if not allowed:
            logger.record_metric(
                "ratelimit.denial",
                1,
                tags={"scope": scope},
            )

        logger.record_metric(
            "ratelimit.duration",
            duration_seconds,
            tags={"scope": scope},
        )

    @auto_trace(logger)
    def record_backend_error(
        self,
        backend: str = "redis",
        error_type: str = "unknown",
    ) -> None:
        """Record a backend error.

        Args:
            backend: Backend type (redis, memory)
            error_type: Error classification
        """
        self.backend_errors_total.labels(
            backend=backend,
            error_type=error_type,
        ).inc()

        # Log to telemetry
        logger.record_metric(
            "ratelimit.backend.error",
            1,
            tags={"backend": backend, "error_type": error_type},
        )
        logger.log_error(
            Exception(f"Rate limit backend error: {backend}/{error_type}")
        )

    @auto_trace(logger)
    def set_backend_health(self, backend: str, healthy: bool) -> None:
        """Set backend health status.

        Args:
            backend: Backend type (redis, memory)
            healthy: Health status
        """
        value = 1 if healthy else 0

        self.backend_healthy.labels(backend=backend).set(value)

        # Log to telemetry
        logger.record_metric(
            "ratelimit.backend.health",
            value,
            tags={"backend": backend},
        )

        if not healthy:
            logger.log_error(
                Exception(f"Rate limit backend unhealthy: {backend}")
            )


_default_metrics: RateLimitMetrics | None = None


@auto_trace(logger)
def create_metrics(enable_endpoint_labels: bool = False, registry=None) -> RateLimitMetrics:
    """Factory function for RateLimitMetrics (singleton per default registry)."""
    global _default_metrics
    if registry is None and _default_metrics is not None:
        return _default_metrics
    metrics = RateLimitMetrics(enable_endpoint_labels=enable_endpoint_labels, registry=registry)
    if registry is None:
        _default_metrics = metrics
    return metrics
