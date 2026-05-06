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

"""Shared utilities for rate limiting module.

Centralizes rate-limit helpers (parsing, sliding-window member
generation, cost validation) so each backend and algorithm consumes
the same parsing and key-generation logic.
"""

import secrets

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)

# Maximum cost per request — input sanitization to bound list
# allocation; protects against memory exhaustion attacks (CWE-770).
_MAX_COST_PER_REQUEST = 1000


@auto_trace(logger)
def parse_rate(rate: str) -> tuple[int, int]:
    """Parse rate limit string into (limit, window_seconds).

    Args:
        rate: Rate limit string in format "N/period".
              Supported period values:
              - Explicit seconds: "<window>s" (e.g., "60s", "300s")
              Examples: "100/60s", "10/1s", "5/300s"

    Returns:
        Tuple of (limit, window_seconds)

    Raises:
        ValueError: If rate format is invalid or period is unknown
    """
    try:
        limit_str, period = rate.split("/")
        limit = int(limit_str)
    except ValueError as e:
        raise ValueError(f"Invalid rate format: {rate}") from e

    if period.endswith("s") and period[:-1].isdigit():
        window_seconds = int(period[:-1])
        if window_seconds <= 0:
            raise ValueError(f"Invalid period: {period}")
        return limit, window_seconds

    raise ValueError(f"Invalid period: {period}")


@auto_trace(logger)
def is_valid_rate(rate: str) -> bool:
    """Check if rate limit string is valid format.

    Args:
        rate: Rate limit string to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        parse_rate(rate)
        return True
    except ValueError:
        return False


@auto_trace(logger)
def _generate_window_members(now: float, cost: int) -> list[tuple[str, float]]:
    """Generate unique member entries for sliding window storage.

    Optimized to minimize cryptographic operations by generating a single
    random token shared across all entries in the batch, reducing overhead
    from O(cost) to O(1).

    Member Format: "{timestamp}:{token}:{index}"
    - timestamp: Request timestamp (ensures time-based uniqueness)
    - token: 8-byte random hex (ensures uniqueness within same timestamp)
    - index: Entry index (ensures uniqueness within same batch)

    Args:
        now: Current timestamp
        cost: Number of entries to generate (1 to _MAX_COST_PER_REQUEST)

    Returns:
        List of (member_id, timestamp) tuples ready for storage

    Raises:
        ValueError: If cost is outside valid range [1, _MAX_COST_PER_REQUEST]

    Example:
        >>> members = _generate_window_members(1234567890.0, 3)
        >>> # Returns: [
        >>> #   ("1234567890.0:a1b2c3d4e5f6a7b8:0", 1234567890.0),
        >>> #   ("1234567890.0:a1b2c3d4e5f6a7b8:1", 1234567890.0),
        >>> #   ("1234567890.0:a1b2c3d4e5f6a7b8:2", 1234567890.0),
        >>> # ]

    Security:
        Validates the ``cost`` parameter to prevent memory exhaustion
        attacks (CWE-770). The ``_MAX_COST_PER_REQUEST`` cap of 1000
        prevents DoS via unbounded list allocation.
    """
    if cost < 1:
        raise ValueError(f"Cost must be >= 1, got: {cost}")
    if cost > _MAX_COST_PER_REQUEST:
        raise ValueError(
            f"Cost {cost} exceeds maximum {_MAX_COST_PER_REQUEST}. "
            f"This protects against memory exhaustion attacks (CWE-770)."
        )

    base_token = secrets.token_hex(8)
    return [(f"{now}:{base_token}:{i}", now) for i in range(cost)]
