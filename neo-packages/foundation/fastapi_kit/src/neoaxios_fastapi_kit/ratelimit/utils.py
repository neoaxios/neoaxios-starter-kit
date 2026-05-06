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

"""HTTP-specific rate limiting utilities.

Provides IETF-compliant rate limit header construction and TTL conversion
helpers. These are HTTP concerns that belong in neoaxios-fastapi-kit, not in the
framework-agnostic resilience-kit layer.

References:
    - IETF draft-ietf-httpapi-ratelimit-headers
"""

import time

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

logger = get_telemetry(__name__)


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def epoch_to_ttl(reset_at: int) -> int:
    """Convert a Unix epoch reset timestamp to TTL seconds.

    Args:
        reset_at: Unix timestamp when the rate limit window resets.

    Returns:
        Non-negative seconds until the window resets.
    """
    return max(0, reset_at - int(time.time()))


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def build_ratelimit_headers(
    limit: int,
    remaining: int,
    reset_seconds: int,
    window_seconds: int,
    include_retry_after: bool = False,
    include_epoch: bool = False,
) -> dict[str, str]:
    """Build IETF-compliant rate limit headers.

    Constructs both IETF standard RateLimit-* headers and legacy X-RateLimit-*
    headers for backward compatibility.

    IETF Headers (draft-ietf-httpapi-ratelimit-headers):
        - RateLimit-Limit: Maximum requests per window
        - RateLimit-Remaining: Requests remaining in current window
        - RateLimit-Reset: Seconds until window reset (TTL, not epoch)
        - RateLimit-Policy: Rate limit policy in "{limit};w={window}" format

    Legacy Headers (backward compatibility):
        - X-RateLimit-Limit: Same as RateLimit-Limit
        - X-RateLimit-Remaining: Same as RateLimit-Remaining
        - X-RateLimit-Reset: Same as RateLimit-Reset (TTL seconds)
        - X-RateLimit-Reset-At: Unix epoch timestamp (optional, for monitoring)

    Args:
        limit: Maximum requests allowed per window.
        remaining: Requests remaining in current window.
        reset_seconds: Seconds until window reset (TTL).
        window_seconds: Window duration in seconds.
        include_retry_after: Include Retry-After header (for 429 responses).
        include_epoch: Include X-RateLimit-Reset-At epoch header.

    Returns:
        Dictionary of header name to string value.

    References:
        - IETF draft-ietf-httpapi-ratelimit-headers
        - RFC 7231 Section 7.1.3 (Retry-After)
    """
    headers = {
        # IETF standard headers
        "RateLimit-Limit": str(limit),
        "RateLimit-Remaining": str(remaining),
        "RateLimit-Reset": str(reset_seconds),
        "RateLimit-Policy": f"{limit};w={window_seconds}",
        # Legacy headers (backward compatibility)
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_seconds),
    }

    if include_retry_after:
        headers["Retry-After"] = str(reset_seconds)

    if include_epoch:
        epoch_reset = int(time.time()) + reset_seconds
        headers["X-RateLimit-Reset-At"] = str(epoch_reset)

    return headers
