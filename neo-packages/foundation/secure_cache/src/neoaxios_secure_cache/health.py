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

"""Cache health status for readiness probe integration.

Provides ``get_cache_health()`` which returns a dict compatible with
neoaxios_fastapi_kit's ``add_health_endpoint(check_deep=...)`` callback format.

When the cache's CanaryMonitor detects tampering and activates TamperDetectionState,
the returned status becomes ``"degraded"``.  Infrastructure (k8s readiness
probes, load balancers) can then drain traffic from the affected pod.

Usage:
    from neoaxios_secure_cache.health import get_cache_health

    async def check_dependencies():
        return {
            "cache": get_cache_health(cache),
            "database": {"status": "healthy"},
        }

    add_health_endpoint(app, version="1.0.0", check_deep=check_dependencies)
"""

from typing import Any

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@auto_trace(logger)
def get_cache_health(cache: Any) -> dict[str, str]:
    """Return health status dict for the cache dependency.

    Checks whether the cache has a CanaryMonitor attached and whether
    its TamperDetectionState is active.  The returned dict uses the ``status``
    key convention expected by ``add_health_endpoint``'s ``check_deep``
    response format: values not in ``("healthy", "ok", "up")`` cause
    the overall health endpoint to return ``"degraded"``.

    Args:
        cache: Cache object returned by ``create_secure_cache()``.
            Expected to have an optional ``.canary`` attribute with a
            ``.tamper_detection.is_active()`` method.

    Returns:
        Dict with ``status`` key (``"healthy"`` or ``"degraded"``)
        and additional context fields.
    """
    canary = getattr(cache, "canary", None)
    if canary is None:
        return {"status": "healthy", "canary": "disabled"}

    fallback = getattr(canary, "tamper_detection", None)
    if fallback is None:
        return {"status": "healthy", "canary": "tamper_detection_not_configured"}

    try:
        is_active = fallback.is_active()
    except Exception:
        logger.log_error(
            Exception("Failed to check tamper_detection.is_active() — reporting degraded")
        )
        return {"status": "degraded", "reason": "tamper_detection_check_error"}

    if is_active:
        logger.warning(
            "cache_health_degraded",
            reason="canary_tampering_detected",
            tenant_id=getattr(canary, "tenant_id", "unknown"),
        )
        return {"status": "degraded", "reason": "canary_tampering_detected"}

    return {"status": "healthy", "canary": "ok"}
