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

"""Centralized service tier system.

Maps JWT roles to parameter overrides for rate limits, pagination,
and other operational dimensions. Consumers instantiate ServiceTiers
from parsed config and call resolve methods at request time.

Design: most-restrictive-wins when multiple roles match tiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from pydantic import BaseModel, Field
from neoaxios_logging import auto_trace, get_telemetry

if TYPE_CHECKING:
    from starlette.requests import Request

logger = get_telemetry(__name__)


# ---------------------------------------------------------------------------
# Config models (parsed from YAML)
# ---------------------------------------------------------------------------


class RateLimitOverride(BaseModel):
    """Per-tier rate limit override."""

    requests: int = Field(..., ge=1)
    window_seconds: int | None = Field(default=None, ge=1)


class TierOverrides(BaseModel):
    """What a tier can override. Extensible for future dimensions."""

    rate_limits: dict[str, RateLimitOverride] = Field(default_factory=dict)


class ServiceTierConfig(BaseModel):
    """Top-level tier configuration."""

    definitions: dict[str, TierOverrides] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Resolution results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedRateLimit:
    """Resolved rate limit after tier application."""

    requests: int
    window_seconds: int


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class ServiceTiers:
    """Resolves effective configuration from caller roles.

    Instantiated once at startup. Thread-safe (immutable after init).
    Pre-indexes tier data by operation for O(1) lookup.
    """

    __slots__ = ("_rate_limit_tiers",)

    def __init__(self, config: ServiceTierConfig) -> None:
        rl_tiers: dict[str, list[tuple[str, int, int | None]]] = {}
        for role_name, overrides in config.definitions.items():
            for operation, rl_override in overrides.rate_limits.items():
                rl_tiers.setdefault(operation, []).append(
                    (role_name, rl_override.requests, rl_override.window_seconds)
                )
        self._rate_limit_tiers = rl_tiers

    @auto_trace(logger)
    def resolve_rate_limit(
        self,
        roles: frozenset[str] | set[str] | None,
        operation: str,
        base_requests: int,
        base_window: int,
    ) -> ResolvedRateLimit:
        """Most-restrictive-wins: lowest requests among matching tiers."""
        tiers = self._rate_limit_tiers.get(operation)
        if not tiers or not roles:
            return ResolvedRateLimit(base_requests, base_window)

        best_requests: int | None = None
        best_window: int | None = None
        for role_name, tier_requests, tier_window in tiers:
            if role_name in roles:
                if best_requests is None or tier_requests < best_requests:
                    best_requests = tier_requests
                    best_window = tier_window

        if best_requests is None:
            return ResolvedRateLimit(base_requests, base_window)
        return ResolvedRateLimit(
            best_requests,
            best_window if best_window is not None else base_window,
        )

    @auto_trace(logger)
    def has_rate_limit_tiers(self, operation: str) -> bool:
        """Check if any tiers exist for an operation."""
        return bool(self._rate_limit_tiers.get(operation))

    @auto_trace(logger)
    def make_limit_resolver(
        self,
        operation: str,
        base_requests: int,
        base_window: int,
    ) -> Callable[[Request], tuple[int, int] | None] | None:
        """Create a limit_resolver callback for require_rate_limit().

        Returns None if no tiers are defined for this operation.
        """
        if not self.has_rate_limit_tiers(operation):
            return None

        def _resolver(request: Request) -> tuple[int, int] | None:
            identity = getattr(getattr(request, "state", None), "identity", None)
            if identity is None:
                return None
            roles = getattr(identity, "roles", None)
            if not roles:
                return None
            resolved = self.resolve_rate_limit(
                roles, operation, base_requests, base_window
            )
            if (
                resolved.requests == base_requests
                and resolved.window_seconds == base_window
            ):
                return None
            return (resolved.requests, resolved.window_seconds)

        return _resolver
