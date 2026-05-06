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

"""Prometheus metrics for secure_cache monitoring and alerting.

This module provides comprehensive Prometheus-compatible metrics for monitoring
cache security, performance, and integrity. Metrics can be exported to Prometheus
or recorded via neoaxios-logging telemetry.

Features:
- 7 core metrics for security and performance monitoring
- 4 Redis connection pool metrics for capacity planning and saturation detection
- Prometheus-compatible naming (underscores, _total suffix for counters)
- Tenant-scoped labels for multi-tenancy
- prometheus-client integration for Prometheus-compatible metrics export
- Dual emission to both Prometheus and neoaxios-logging telemetry
- Factory function for clean instantiation

Metrics:
- cache_signature_invalid_total: Counter of signature verification failures
- cache_decryption_failed_total: Counter of decryption failures
- cache_canary_mismatch: Gauge indicating canary tampering (0=ok, 1=tampered)
- cache_replay_detected_total: Counter of replay attack detections
- cache_v1_read_total: Counter of legacy v1 format reads (migration tracking)
- cache_integrity_violation_active: Gauge indicating active integrity violation (0=normal, 1=violation detected)
- cache_hit_rate: Gauge of cache hit rate (0.0-1.0)
- redis_pool_max_connections: Gauge of configured pool capacity per purpose
- redis_pool_in_use_connections: Gauge of connections currently checked out
- redis_pool_available_connections: Gauge of idle connections in pool
- redis_pool_created_connections: Gauge of total connections created

Usage:
    from neoaxios_secure_cache.metrics import create_metrics

    # Create metrics instance
    metrics = create_metrics()

    # Record security events
    metrics.record_signature_invalid(tenant_id="tenant-123")
    metrics.record_decryption_failed(tenant_id="tenant-123")
    metrics.record_replay_detected(tenant_id="tenant-123", user_id="user-456")

    # Update status gauges
    metrics.set_canary_mismatch(tenant_id="tenant-123", active=True)
    metrics.set_integrity_violation_active(tenant_id="tenant-123", active=True)

    # Track cache performance
    metrics.record_v1_read(tenant_id="tenant-123")
    metrics.set_hit_rate(tenant_id="tenant-123", rate=0.85)

    # Update pool metrics from gateway
    from neoaxios_secure_cache.gateway import get_gateway
    metrics.update_pool_stats(get_gateway().pool_stats())

Implementation Notes:
- Uses prometheus-client for Prometheus metrics and neoaxios-logging for telemetry
- All methods decorated with @auto_trace for observability
- Metrics are optional - wrappers work without metrics configured
- Thread-safe metric recording
- Factory function for clean instantiation

Alert Thresholds (for Grafana):
- signature_invalid > 0 - Critical
- decryption_failed > 0 - Critical
- canary_mismatch == 1 - Critical
- replay_detected > 0 - Warning
- cache_integrity_violation_active == 1 - Warning
- hit_rate < 0.5 - Warning
- redis_pool_in_use / redis_pool_max > 0.8 - Warning (pool saturation)
"""

from typing import Optional

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


class SecureCacheMetrics:
    """Prometheus metrics for secure_cache monitoring.

    Provides comprehensive metrics for cache security, performance, and integrity
    monitoring. Emits to both Prometheus and neoaxios-logging telemetry.

    Metrics are labeled by tenant_id to support multi-tenant deployments.

    Attributes:
        registry: Optional Prometheus CollectorRegistry (None for default registry)

    Example:
        metrics = SecureCacheMetrics()

        # Record security events
        metrics.record_signature_invalid(tenant_id="t1")
        metrics.record_decryption_failed(tenant_id="t1")

        # Update status
        metrics.set_canary_mismatch(tenant_id="t1", active=True)
        metrics.set_integrity_violation_active(tenant_id="t1", active=False)

        # Track performance
        metrics.set_hit_rate(tenant_id="t1", rate=0.92)
    """

    @auto_trace(logger)
    def __init__(self, registry: Optional[CollectorRegistry] = None) -> None:
        """Initialize metrics with optional custom registry.

        Args:
            registry: Optional Prometheus CollectorRegistry (None = default registry)

        Note:
            Use create_metrics() factory function instead of direct instantiation.
        """
        self.registry = registry
        self._init_prometheus_metrics()
        logger.info("Initialized SecureCacheMetrics with prometheus-client")

    @auto_trace(logger)
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metric objects.

        Creates Counter and Gauge objects for all metrics with tenant_id labels.
        Only called when prometheus-client is available.
        """
        # Counters (cumulative, always increasing)
        self._signature_invalid_counter = Counter(
            name="cache_signature_invalid_total",
            documentation="Total number of invalid signature detections",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        self._decryption_failed_counter = Counter(
            name="cache_decryption_failed_total",
            documentation="Total number of decryption failures",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        self._replay_detected_counter = Counter(
            name="cache_replay_detected_total",
            documentation="Total number of replay attack detections",
            labelnames=["tenant_id", "user_id"],
            registry=self.registry,
        )

        self._v1_read_counter = Counter(
            name="cache_v1_read_total",
            documentation="Total number of legacy v1 format reads",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        # Gauges (point-in-time values, can go up or down)
        self._canary_mismatch_gauge = Gauge(
            name="cache_canary_mismatch",
            documentation="Canary verification status (0=ok, 1=mismatch)",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        self._integrity_violation_active_gauge = Gauge(
            name="cache_integrity_violation_active",
            documentation="Integrity violation status (0=normal, 1=violation detected)",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        self._hit_rate_gauge = Gauge(
            name="cache_hit_rate",
            documentation="Cache hit rate ratio (0.0-1.0)",
            labelnames=["tenant_id"],
            registry=self.registry,
        )

        # Redis connection pool metrics (labeled by purpose: consumer, entity, cache, pubsub)
        self._pool_max_gauge = Gauge(
            name="redis_pool_max_connections",
            documentation="Configured max connections per pool",
            labelnames=["purpose"],
            registry=self.registry,
        )
        self._pool_in_use_gauge = Gauge(
            name="redis_pool_in_use_connections",
            documentation="Connections currently checked out from pool",
            labelnames=["purpose"],
            registry=self.registry,
        )
        self._pool_available_gauge = Gauge(
            name="redis_pool_available_connections",
            documentation="Idle connections available in pool",
            labelnames=["purpose"],
            registry=self.registry,
        )
        self._pool_created_gauge = Gauge(
            name="redis_pool_created_connections",
            documentation="Total connections created by pool (cumulative)",
            labelnames=["purpose"],
            registry=self.registry,
        )

        logger.debug("Prometheus metrics initialized")

    @auto_trace(logger)
    def record_signature_invalid(self, tenant_id: str) -> None:
        """Record invalid signature detection.

        Args:
            tenant_id: Tenant identifier for metric labeling

        Alert: Critical if > 0 (indicates tampering or key mismatch)
        """
        self._signature_invalid_counter.labels(tenant_id=tenant_id).inc()

        # Log to telemetry for debugging
        logger.record_metric(
            "cache.signature.invalid", 1, tags={"tenant_id": tenant_id}
        )
        logger.log_error(
            Exception(f"Signature invalid detected for tenant_id={tenant_id}")
        )

    @auto_trace(logger)
    def record_decryption_failed(self, tenant_id: str) -> None:
        """Record decryption failure.

        Args:
            tenant_id: Tenant identifier for metric labeling

        Alert: Critical if > 0 (indicates tampering or key mismatch)
        """
        self._decryption_failed_counter.labels(tenant_id=tenant_id).inc()

        # Log to telemetry for debugging
        logger.record_metric(
            "cache.decryption.failed", 1, tags={"tenant_id": tenant_id}
        )
        logger.log_error(
            Exception(f"Decryption failed for tenant_id={tenant_id}")
        )

    @auto_trace(logger)
    def set_canary_mismatch(self, tenant_id: str, active: bool) -> None:
        """Set canary mismatch status.

        Args:
            tenant_id: Tenant identifier for metric labeling
            active: True if canary mismatch detected, False if ok

        Alert: Critical if == 1 (indicates cache tampering)
        """
        value = 1 if active else 0
        self._canary_mismatch_gauge.labels(tenant_id=tenant_id).set(value)

        # Log to telemetry for debugging
        logger.record_metric(
            "cache.canary.mismatch", value, tags={"tenant_id": tenant_id}
        )

        if active:
            logger.log_error(
                Exception(f"Canary mismatch detected for tenant_id={tenant_id}")
            )

    @auto_trace(logger)
    def record_replay_detected(self, tenant_id: str, user_id: str) -> None:
        """Record replay attack detection.

        Args:
            tenant_id: Tenant identifier for metric labeling
            user_id: User identifier for metric labeling

        Alert: Warning if > 0 (indicates replay attack attempt)
        """
        self._replay_detected_counter.labels(
            tenant_id=tenant_id, user_id=user_id
        ).inc()

        # Log to telemetry for debugging
        logger.record_metric(
            "cache.replay.detected",
            1,
            tags={"tenant_id": tenant_id, "user_id": user_id},
        )
        logger.log_error(
            Exception(
                f"Replay attack detected for tenant_id={tenant_id}, user_id={user_id}"
            )
        )

    @auto_trace(logger)
    def record_v1_read(self, tenant_id: str) -> None:
        """Record legacy v1 format read.

        Args:
            tenant_id: Tenant identifier for metric labeling

        Note: Used for migration tracking. Not an error, but indicates
        legacy data still in cache.
        """
        self._v1_read_counter.labels(tenant_id=tenant_id).inc()

        # Log to telemetry for tracking
        logger.record_metric("cache.v1.read", 1, tags={"tenant_id": tenant_id})
        logger.debug(f"Legacy v1 format read for tenant_id={tenant_id}")

    @auto_trace(logger)
    def set_integrity_violation_active(self, tenant_id: str, active: bool) -> None:
        """Set integrity violation status.

        Args:
            tenant_id: Tenant identifier for metric labeling
            active: True if integrity violation detected, False if normal

        Alert: Warning if == 1 (indicates cache tampering detected)
        """
        value = 1 if active else 0
        self._integrity_violation_active_gauge.labels(tenant_id=tenant_id).set(value)

        # Log to telemetry for debugging
        logger.record_metric(
            "cache.integrity_violation.active", value, tags={"tenant_id": tenant_id}
        )

        if active:
            logger.log_error(
                Exception(f"Integrity violation detected for tenant_id={tenant_id}")
            )
        else:
            logger.info(f"Integrity violation cleared for tenant_id={tenant_id}")

    @auto_trace(logger)
    def set_hit_rate(self, tenant_id: str, rate: float) -> None:
        """Set cache hit rate.

        Args:
            tenant_id: Tenant identifier for metric labeling
            rate: Cache hit rate ratio (0.0-1.0)

        Raises:
            ValueError: If rate not in [0.0, 1.0]

        Alert: Warning if < 0.5 (indicates poor cache effectiveness)
        """
        if not (0.0 <= rate <= 1.0):
            raise ValueError(f"rate must be in [0.0, 1.0], got {rate}")

        self._hit_rate_gauge.labels(tenant_id=tenant_id).set(rate)

        # Log to telemetry for tracking
        logger.record_metric("cache.hit_rate", rate, tags={"tenant_id": tenant_id})
        logger.debug(f"Cache hit rate for tenant_id={tenant_id}: {rate:.2%}")

    @auto_trace(logger)
    def update_pool_stats(self, stats: dict[str, dict[str, int]]) -> None:
        """Update Redis connection pool metrics from gateway pool stats.

        Call periodically (e.g. from a Prometheus scrape callback or a
        background timer) with the output of ``RedisGateway.pool_stats()``.

        Args:
            stats: Dict keyed by purpose (e.g. "consumer", "entity") with
                pool stat dicts containing ``max_connections``, ``in_use``,
                ``available``, ``created``.
        """
        for purpose, pool in stats.items():
            self._pool_max_gauge.labels(purpose=purpose).set(pool.get("max_connections", 0))
            self._pool_in_use_gauge.labels(purpose=purpose).set(pool.get("in_use", 0))
            self._pool_available_gauge.labels(purpose=purpose).set(pool.get("available", 0))
            self._pool_created_gauge.labels(purpose=purpose).set(pool.get("created", 0))

            logger.record_metric(
                "redis.pool.utilization",
                pool.get("in_use", 0),
                tags={
                    "purpose": purpose,
                    "max_connections": pool.get("max_connections", 0),
                    "available": pool.get("available", 0),
                    "created": pool.get("created", 0),
                },
            )


@auto_trace(logger)
def _refresh_pool_stats(metrics: SecureCacheMetrics) -> None:
    """Fetch pool stats from the gateway and push to metrics gauges.

    Intended to be called as a pre-collect hook before Prometheus scrapes
    metric values.  No-op when the gateway singleton has not been initialized
    (e.g. during startup or in test environments without Redis).

    Args:
        metrics: ``SecureCacheMetrics`` instance whose pool gauges to refresh.
    """
    from neoaxios_secure_cache.gateway import get_gateway, is_gateway_initialized

    if not is_gateway_initialized():
        return

    try:
        stats = get_gateway().pool_stats()
        metrics.update_pool_stats(stats)
    except Exception as exc:
        logger.warning(
            "Failed to refresh pool stats during scrape",
            extra={"error": str(exc)},
        )


@auto_trace(logger)
def register_scrape_callback(
    metrics: SecureCacheMetrics,
    registry: Optional[CollectorRegistry] = None,
) -> None:
    """Register a scrape-time callback on a Prometheus registry.

    Wraps the registry's ``collect()`` method so that every call to
    ``generate_latest(registry)`` first refreshes the pool gauges via
    ``gateway.pool_stats()`` before yielding metric samples.

    This approach ensures pool gauge values are current when Prometheus
    scrapes ``/metrics``, without requiring a background thread or a
    full custom collector.

    Args:
        metrics: ``SecureCacheMetrics`` instance whose pool gauges to refresh.
        registry: Target ``CollectorRegistry``.  When ``None``, falls back to
            the registry stored on *metrics* (which may itself be ``None``,
            meaning the process-global default registry).
    """
    target_registry = registry if registry is not None else metrics.registry
    if target_registry is None:
        target_registry = REGISTRY

    # Idempotency guard: prevent double-wrapping if called multiple times
    if getattr(target_registry, "_pool_stats_callback_registered", False):
        logger.debug("Scrape callback already registered on this registry, skipping")
        return

    original_collect = target_registry.collect

    def _collecting_with_refresh():
        try:
            _refresh_pool_stats(metrics)
        except Exception as exc:
            logger.warning(
                "Error in scrape callback during pool stats refresh",
                extra={"error": str(exc)},
            )
        yield from original_collect()

    target_registry.collect = _collecting_with_refresh  # type: ignore[assignment]
    target_registry._pool_stats_callback_registered = True  # type: ignore[attr-defined]
    logger.info("pool_stats_scrape_callback_registered")


@auto_trace(logger)
def create_metrics(registry: Optional[CollectorRegistry] = None) -> SecureCacheMetrics:
    """Factory function for SecureCacheMetrics.

    Creates a SecureCacheMetrics instance with optional custom registry.

    Args:
        registry: Optional Prometheus CollectorRegistry (None = default registry)

    Returns:
        Configured SecureCacheMetrics instance

    Example:
        from neoaxios_secure_cache.metrics import create_metrics

        # Use default registry
        metrics = create_metrics()

        # Use custom registry
        from prometheus_client import CollectorRegistry
        custom_registry = CollectorRegistry()
        metrics = create_metrics(registry=custom_registry)

        # Record metrics
        metrics.record_signature_invalid(tenant_id="tenant-123")
    """
    return SecureCacheMetrics(registry=registry)
