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

"""Rate limiter configuration.

This module provides configuration dataclasses for the rate limiting framework.
It supports endpoint-specific rate limits, scope-based limiting (user/tenant/IP/global),
and cost-based limits. All rate limiting operations are fail-closed for security
and configuration parameters are input-validated.

Usage:
    from neoaxios_resilience_kit.ratelimit.config import RateLimitConfig, EndpointConfig

    # Create configuration
    config = RateLimitConfig(
        key_prefix="ratelimit:",
        default_rate="1000/60s",
        endpoints={
            "/v1/items": EndpointConfig(
                rate="100/60s",
                scope="user",
                cost=1,
            ),
            "/v1/expensive": EndpointConfig(
                rate="10/60s",
                scope="user",
                cost=5,
            ),
        },
    )

    # Get endpoint-specific config
    endpoint_cfg = config.get_endpoint_config("/v1/items")
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from neoaxios_logging import get_telemetry, auto_trace

from .utils import parse_rate, _MAX_COST_PER_REQUEST

# =============================================================================
# Telemetry
# =============================================================================
logger = get_telemetry(__name__)


# =============================================================================
# Configuration Dataclasses
# =============================================================================


@dataclass
class EndpointConfig:
    """Configuration for a specific endpoint's rate limit.

    Attributes:
        rate: Rate limit string (e.g., "100/60s")
        scope: Key scope - "user", "tenant", "ip", "global"
        cost: Number of capacity slots this request consumes from the window's limit budget.
            A request with cost=N occupies N of the window's configured limit slots, so
            higher-cost endpoints allow fewer calls per window.
    """

    rate: str
    scope: str = "user"
    cost: int = 1

    def __post_init__(self):
        """Validate configuration on initialization."""
        # Validate rate format (direct parse avoids double-parse via is_valid_rate)
        try:
            parse_rate(self.rate)
        except ValueError:
            raise ValueError(f"Invalid rate format: {self.rate}")

        # Validate scope
        valid_scopes = ("user", "tenant", "ip", "global")
        if self.scope not in valid_scopes:
            raise ValueError(
                f"Invalid scope: {self.scope}. Must be one of {valid_scopes}"
            )

        # Bound cost to protect against memory exhaustion (CWE-770)
        if not (1 <= self.cost <= _MAX_COST_PER_REQUEST):
            raise ValueError(
                f"Invalid cost: {self.cost}. "
                f"Must be between 1 and {_MAX_COST_PER_REQUEST} (CWE-770 protection)"
            )


@dataclass
class RateLimitConfig:
    """Global rate limiter configuration.

    Rate limiting is fail-closed: when the backend is unavailable,
    requests are rejected (503) rather than admitted.

    Attributes:
        key_prefix: Logical prefix for key builder output (default: "ratelimit:").
            This is NOT a raw Redis key prefix — actual Redis keys are constructed
            by the backend via CacheNamespace.make_key(). Do not
            use this field for direct Redis key construction.
        default_rate: Default rate limit for undecorated endpoints
        endpoints: Per-endpoint configuration overrides
        include_epoch_timestamp: Include X-RateLimit-Reset-At epoch header
            for monitoring dashboards. Default False to minimize overhead.
    """

    key_prefix: str = "ratelimit:"
    default_rate: str = "1000/60s"
    endpoints: Dict[str, EndpointConfig] = field(default_factory=dict)
    include_epoch_timestamp: bool = False

    def __post_init__(self):
        """Validate configuration on initialization."""
        # Validate default_rate format (direct parse avoids double-parse via is_valid_rate)
        try:
            parse_rate(self.default_rate)
        except ValueError:
            raise ValueError(f"Invalid default_rate format: {self.default_rate}")

        # Validate key_prefix
        if not self.key_prefix:
            raise ValueError("key_prefix cannot be empty")

    @auto_trace(logger)
    def get_endpoint_config(self, path: str) -> Optional[EndpointConfig]:
        """Get configuration for a specific endpoint path.

        Args:
            path: Request path (e.g., "/v1/items")

        Returns:
            EndpointConfig if configured, None otherwise
        """
        return self.endpoints.get(path)
